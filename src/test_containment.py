"""Containment tests — the safety-critical claims must be verified, not asserted.

These run without Docker, on the rlimits fallback, in CI.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import blast_radius  # noqa: E402
import sandbox  # noqa: E402
import vultr_inference  # noqa: E402

FAST_TIMEOUT = 2.0  # keep the unit suite inside the 60s submit gate


@pytest.fixture(scope="module")
def suite():
    """One probe suite run, reused by the read-only assertions.

    Each full run spawns real subprocesses, so 7 identical suites cost ~45s and
    pushed the suite against the 60s cap in submit.py. Only tests that assert on
    a *fresh* run get their own.
    """
    return blast_radius.run_probes(runtimes=("rlimits",), timeout=FAST_TIMEOUT)


@pytest.fixture(scope="module")
def shared_att(suite):
    import attestation
    return attestation.build_attestation(runtimes=("rlimits",), timeout=FAST_TIMEOUT)


def test_destructive_probe_refused_without_container(suite):
    """rm -rf must never run where containment is not a real boundary."""
    report = blast_radius.run_probes(runtimes=("rlimits",), timeout=FAST_TIMEOUT)
    rmrf = [p for p in report["probes"] if p["key"] == "rm_rf"]
    assert len(rmrf) == 1
    assert rmrf[0]["outcome"] == "SKIPPED", "rm_rf ran under rlimits = host exposed"
    assert rmrf[0]["measured"] is False


def test_report_never_claims_zero_on_unverified_axis(suite):
    """An unmeasured axis must not be scored CONTAINED."""
    report = suite
    for axis in blast_radius.AXES:
        if report["axes"][axis]["measured"] == 0:
            assert report["axes"][axis]["verdict"] == "UNVERIFIED"
    if report["verdict"] == "BLAST RADIUS ZERO":
        assert all(report["axes"][a]["measured"] > 0 for a in blast_radius.AXES)


def test_canary_tampering_is_detected():
    """If the host canary file changes, the suite must report a breach."""
    token, env_name, path = blast_radius.plant_canary()
    try:
        assert blast_radius.canary_intact(token, path) is True
        with open(path, "w", encoding="utf-8") as fh:  # simulate an escape
            fh.write("tampered")
        assert blast_radius.canary_intact(token, path) is False
    finally:
        blast_radius.unplant_canary(env_name, path)


def test_container_argv_keeps_every_containment_flag():
    """A dropped flag turns the containment claim into a lie. Pin them all.

    This is verifiable without a Docker daemon, which is why it matters:
    the daemon only exists on the Vultr VM, the bug would ship silently.
    """
    argv = sandbox.docker_argv(container_id="br-test", workdir="/tmp/x")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "-i" in argv, "stdin must be wired into the container"

    required = {
        ("--network", "none"): "egress must be blocked",
        ("--read-only",): "rootfs must be read-only",
        ("--cap-drop", "ALL"): "must drop capabilities",
        ("--user", "65534:65534"): "must run non-root",
        ("--pids-limit",): "must limit process count",
        ("--memory",): "must limit memory",
        ("--security-opt", "no-new-privileges"): "must prevent escalation",
    }
    for flag, why in required.items():
        assert any(a == flag[0] for a in argv), f"missing {flag[0]} — {why}"
        if len(flag) == 2:
            i = argv.index(flag[0])
            assert argv[i + 1] == flag[1], f"{flag[0]} must be {flag[1]} — {why}"

    # the task dir is mounted read-only, and the payload runs from it
    i = argv.index("-v")
    assert argv[i + 1].endswith(":/task:ro")
    assert argv[-3:] == [sandbox.DEFAULT_IMAGE, "python", "/task/payload.py"]


def test_rlimits_scrubs_host_env():
    """A probe must not see the host canary secret (secret hygiene axis)."""
    token, env_name, path = blast_radius.plant_canary()
    try:
        res = sandbox.execute(
            "import os\nprint('SEEN' if any('CANARY' in k.upper() for k in os.environ) else 'CLEAN')\n",
            allow_container=False, allow_rlimits=True, timeout=15,
        )
        assert res.runtime == "rlimits"
        assert "SEEN" not in res.stdout, "host secret env var leaked"
        assert res.degraded is True, "fallback must mark itself DEGRADED"
    finally:
        blast_radius.unplant_canary(env_name, path)


def test_stdin_reaches_the_payload():
    """The agent's code reads stdin; the sandbox must actually pass it."""
    res = sandbox.execute(
        "import sys\nprint(sum(int(x) for x in sys.stdin.read().split()))",
        allow_container=False, allow_rlimits=True, timeout=15, stdin_data="1 2 3",
    )
    assert res.runtime == "rlimits"
    assert res.stdout.strip() == "6", f"stdin did not reach the payload: {res.stdout!r}"


def test_container_only_payload_never_falls_back(monkeypatch, tmp_path):
    """rm -rf / fork bomb must never run on the host just because rlimits is on."""
    marker = tmp_path / "ran"
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    res = sandbox.execute(
        f"open({str(marker)!r}, 'w').write('ran')",
        allow_container=True, allow_rlimits=True, require_container=True, timeout=5,
    )
    assert res.runtime == "none"
    assert res.runtime_error is True
    assert not marker.exists(), "container-only payload ran on the host"


def test_crashed_probe_is_unverified(monkeypatch):
    """A probe that exits non-zero did not measure; it must not score CONTAINED."""
    def fake_execute(code, **kwargs):
        return sandbox.ExecResult(exit_code=1, stdout="", stderr="SyntaxError: bad",
                                  runtime="container")

    monkeypatch.setattr(blast_radius.sandbox, "execute", fake_execute)
    report = blast_radius.run_probes(runtimes=("container",), timeout=1)
    non_bombs = [p for p in report["probes"] if p["key"] not in ("mem_bomb", "fork_bomb")]
    assert non_bombs
    assert all(p["outcome"] == "UNVERIFIED" for p in non_bombs), non_bombs
    assert all(p["measured"] is False for p in non_bombs)
    assert report["verdict"] != "BLAST RADIUS ZERO"


def test_no_runtime_cannot_claim_containment(monkeypatch):
    """No sandbox = no measurement. This must never print BLAST RADIUS ZERO."""
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    report = blast_radius.run_probes(runtimes=("container",), timeout=FAST_TIMEOUT)
    assert report["blast_radius"] == 0
    assert report["verdict"] != "BLAST RADIUS ZERO"
    assert report["runtimes"] == [], "a runtime that never ran must not be reported"
    assert all(not p["measured"] for p in report["probes"])


def test_generated_code_never_runs_without_container(monkeypatch, tmp_path):
    """Model-written code is untrusted; it must never run via the rlimits path."""
    import main
    marker = tmp_path / "ran"
    payload = f"open({str(marker)!r}, 'w').write('ran')"
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    monkeypatch.setattr(main.vultr_inference, "have_key", lambda: True)
    monkeypatch.setattr(main.vultr_inference, "generate_code", lambda task: payload)
    report = main.run_task("write a file", probe=False)
    assert report["code_generated"] is True
    assert report["exec"]["runtime"] == "none"
    assert report["exec"]["runtime_error"] is True
    assert not marker.exists(), "generated code ran on the host"


def test_self_heal_repairs_after_a_real_failure(monkeypatch):
    """The agent must read real stderr and repair, not just retry blindly."""
    import main
    calls = {"generate": 0, "repair": 0, "execute": 0}

    monkeypatch.setattr(main.sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(main.vultr_inference, "have_key", lambda: True)

    def generate(task):
        calls["generate"] += 1
        return "print(int('not a number'))"

    def repair(task, code, stdout, stderr, attempt):
        calls["repair"] += 1
        assert "ValueError" in stderr, "repair must receive the real error output"
        assert attempt == 2
        return "print(42)"

    def execute(code, **kwargs):
        calls["execute"] += 1
        if "not a number" in code:
            return sandbox.ExecResult(exit_code=1, stderr="ValueError: bad input",
                                      runtime="container", duration_s=0.1)
        return sandbox.ExecResult(exit_code=0, stdout="42\n", runtime="container",
                                  duration_s=0.1)

    monkeypatch.setattr(main.vultr_inference, "generate_code", generate)
    monkeypatch.setattr(main.vultr_inference, "repair_code", repair)
    monkeypatch.setattr(main.sandbox, "execute", execute)

    report = main.run_task("compute something", probe=False)
    assert calls == {"generate": 1, "repair": 1, "execute": 2}
    assert len(report["attempts"]) == 2
    assert report["fixed"] is True
    assert report["code"] == "print(42)"
    assert report["exec"]["stdout"] == "42\n"


def test_self_heal_gives_up_after_max_attempts(monkeypatch):
    """A repair budget is a limit, not an infinite loop."""
    import main
    calls = {"repair": 0}

    monkeypatch.setattr(main.sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(main.vultr_inference, "have_key", lambda: True)
    monkeypatch.setattr(main.vultr_inference, "generate_code", lambda task: "broken")
    monkeypatch.setattr(main.vultr_inference, "repair_code",
                        lambda *a, **k: (calls.__setitem__("repair", calls["repair"] + 1)
                                         or "still broken"))
    monkeypatch.setattr(main.sandbox, "execute",
                        lambda code, **kw: sandbox.ExecResult(exit_code=1,
                                                              stderr="still broken",
                                                              runtime="container"))

    report = main.run_task("task", probe=False, max_attempts=3)
    assert len(report["attempts"]) == 3
    assert calls["repair"] == 2
    assert report["fixed"] is False


def test_self_heal_does_not_repair_runtime_errors(monkeypatch):
    """No Docker is an infrastructure failure; retrying cannot fix it."""
    import main
    called = {"repair": False}

    monkeypatch.setattr(main.sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(main.vultr_inference, "have_key", lambda: True)
    monkeypatch.setattr(main.vultr_inference, "generate_code", lambda task: "print(1)")
    monkeypatch.setattr(main.vultr_inference, "repair_code",
                        lambda *a, **k: called.__setitem__("repair", True))
    monkeypatch.setattr(main.sandbox, "execute",
                        lambda code, **kw: sandbox.ExecResult(
                            exit_code=125, runtime="none", runtime_error=True,
                            note="container required; no Docker daemon"))

    report = main.run_task("task", probe=False, max_attempts=3)
    assert len(report["attempts"]) == 1
    assert called["repair"] is False
    assert report["fixed"] is False


def test_output_is_capped(monkeypatch):
    """A payload that prints forever must not exhaust host memory."""
    res = sandbox.execute("print('x' * 2000000)", allow_container=False,
                          allow_rlimits=True, timeout=15)
    assert res.runtime == "rlimits"
    assert len(res.stdout) <= sandbox.MAX_OUTPUT_BYTES + 200
    assert "truncated" in res.stdout


def test_residue_is_checked_from_the_host(suite):
    """Lifecycle discipline means nothing survives, verified host-side."""
    residue = [p for p in suite["probes"] if p["key"] == "residue"][0]
    assert residue["outcome"] == "CONTAINED"
    assert residue["detail"].startswith("no container")


def test_container_gone_for_removed_container():
    assert blast_radius.container_gone("") is True
    assert blast_radius.container_gone("br-does-not-exist") is True


def test_container_gone_fails_closed_on_error(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("docker unavailable")
    monkeypatch.setattr(blast_radius.subprocess, "run", boom)
    assert blast_radius.container_gone("br-unknown") is False


def test_container_gone_fails_closed_on_daemon_error(monkeypatch):
    """A daemon error is not "the container is gone". Unknown must not pass."""
    class Proc:
        returncode = 1
        stderr = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"

    monkeypatch.setattr(blast_radius.subprocess, "run", lambda *a, **k: Proc())
    assert blast_radius.container_gone("br-unknown") is False


def test_container_gone_accepts_dockers_not_found(monkeypatch):
    """Docker's own "not found" is the one signal that means lifecycle is clean."""
    class Proc:
        returncode = 1
        stderr = "Error: No such object: br-gone"

    monkeypatch.setattr(blast_radius.subprocess, "run", lambda *a, **k: Proc())
    assert blast_radius.container_gone("br-gone") is True


def test_segfault_is_not_a_resource_limit(monkeypatch):
    """SIGSEGV is a crash, not evidence that a cap was enforced."""
    monkeypatch.setattr(sandbox, "ensure_image", lambda *a, **k: (True, ""))
    monkeypatch.setattr(sandbox, "_run_bounded", lambda *a, **k: ("", "", 139, False))
    res = sandbox.run_container("print('boom')")
    assert res.exit_code == 139
    assert res.killed_by_limit is False


def test_sigkill_is_a_resource_limit(monkeypatch):
    monkeypatch.setattr(sandbox, "ensure_image", lambda *a, **k: (True, ""))
    monkeypatch.setattr(sandbox, "_run_bounded", lambda *a, **k: ("", "", 137, False))
    res = sandbox.run_container("print('oom')")
    assert res.killed_by_limit is True


def test_sigabrt_is_not_a_resource_limit(monkeypatch):
    """SIGABRT is a crash, not evidence that a cap was enforced."""
    monkeypatch.setattr(sandbox, "ensure_image", lambda *a, **k: (True, ""))
    monkeypatch.setattr(sandbox, "_run_bounded", lambda *a, **k: ("", "", -6, False))
    res = sandbox.run_rlimits("raise RuntimeError('boom')")
    assert res.exit_code == -6
    assert res.killed_by_limit is False


def test_probe_failure_still_cleans_up_the_canary(monkeypatch):
    """An unexpected probe error must not leave the host secret in os.environ."""
    def boom(*args, **kwargs):
        raise RuntimeError("probe crashed")

    monkeypatch.setattr(blast_radius.sandbox, "execute", boom)
    try:
        blast_radius.run_probes(runtimes=("rlimits",), timeout=FAST_TIMEOUT)
    except RuntimeError:
        pass
    else:
        raise AssertionError("the probe error should propagate after cleanup")
    assert blast_radius.CANARY_ENV_NAME not in os.environ


def test_limits_report_is_honest():
    """Report must say which limits applied, never over-claim."""
    res = sandbox.execute("print('hi')", allow_container=False, allow_rlimits=True,
                          timeout=10)
    assert res.degraded is True
    assert "applied" in res.limits and "unsupported" in res.limits


def test_missing_key_fails_loudly_never_mock():
    """No key -> raise with setup instructions. Never return fake code."""
    old = os.environ.pop(vultr_inference.KEY_ENV, None)
    try:
        assert vultr_inference.have_key() is False
        try:
            vultr_inference.generate_code("print anything")
        except vultr_inference.MissingInferenceKey as exc:
            assert vultr_inference.KEY_ENV in str(exc)
            assert ".env.example" in str(exc)
        else:
            raise AssertionError("generate_code must raise when the key is missing")
    finally:
        if old is not None:
            os.environ[vultr_inference.KEY_ENV] = old


def test_inference_base_url_is_vultr_pillar():
    """Pillar: every LLM call must go through Vultr Serverless Inference."""
    assert vultr_inference.BASE_URL == "https://api.vultrinference.com/v1"


def test_no_model_id_is_bundled(monkeypatch):
    """Model choice belongs to the team via .env, not to the source."""
    monkeypatch.delenv("INFERENCE_MODEL", raising=False)
    assert vultr_inference.model_name() == ""
    assert not hasattr(vultr_inference, "DEFAULT_MODEL")
    assert not hasattr(vultr_inference, "PROVIDER_MODELS")
    assert not hasattr(vultr_inference, "FALLBACK_MODELS")


def test_missing_model_fails_loudly(monkeypatch):
    """A key without a model must error, never silently use a stale id."""
    monkeypatch.setenv(vultr_inference.KEY_ENV, "test-key")
    monkeypatch.delenv("INFERENCE_MODEL", raising=False)
    with pytest.raises(vultr_inference.InferenceError) as exc:
        vultr_inference.generate_code("print anything")
    assert "INFERENCE_MODEL" in str(exc.value)


def test_provider_defaults_to_vultr(monkeypatch):
    """Config can change, but the Vultr pillar is the default."""
    for name in ("INFERENCE_PROVIDER", "ANTHROPIC_API_KEY", "INFERENCE_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    assert vultr_inference.provider() == "vultr"
    assert vultr_inference.base_url() == "https://api.vultrinference.com/v1"


def test_key_never_crosses_providers(monkeypatch):
    """A Vultr key must not be sent to Anthropic just because it is present."""
    monkeypatch.setenv("INFERENCE_PROVIDER", "anthropic")
    monkeypatch.setenv(vultr_inference.KEY_ENV, "vultr-key")
    monkeypatch.delenv(vultr_inference.ANTHROPIC_KEY_ENV, raising=False)
    assert vultr_inference.have_key() is False


def test_self_test_fails_when_model_is_missing(monkeypatch):
    """No model configured must exit non-zero even when no key is present."""
    monkeypatch.setenv("INFERENCE_PROVIDER", "openai")
    monkeypatch.delenv(vultr_inference.KEY_ENV, raising=False)
    monkeypatch.delenv(vultr_inference.ANTHROPIC_KEY_ENV, raising=False)
    monkeypatch.delenv("INFERENCE_MODEL", raising=False)
    assert vultr_inference._self_test() == 1


def test_canary_token_is_redacted_from_reports():
    """A leak proves the point; the raw token does not belong in the report."""
    import re
    report = blast_radius.run_probes(runtimes=("rlimits",), timeout=FAST_TIMEOUT)
    for probe in report["probes"]:
        assert not re.search(r"br-[0-9a-f]{32}", probe["detail"]), \
            "the raw canary token leaked into the report"


def test_canary_survives_the_run(suite):
    """The canary must be judged before cleanup deletes it. Getting this wrong
    reported every run as a breach, which is exactly the kind of lie this
    project exists to prevent."""
    report = suite
    assert report["canary_intact"] is True, "host canary reported as leaked without being touched"
    assert report["canary_leaked"] is False


def test_attestation_never_grades_an_unmeasured_axis(shared_att):
    """An attestation that claims a grade it did not measure is worse than no
    attestation — it is the exact lie this project exists to stop."""
    att = shared_att
    assert att["schema"].startswith("blast-radius/attestation")
    graded = all(att["axes"][a]["verdict"] == "CONTAINED" for a in att["axes"])
    if not graded:
        assert att["verdict"] != "BLAST RADIUS ZERO"
    for axis, v in att["axes"].items():
        if v["verdict"] == "UNVERIFIED":
            assert v["probes_measured"].startswith("0/")


def test_attestation_reports_degraded_runtime(shared_att):
    att = shared_att
    assert att["degraded_runtime"] is True
    assert att["measured_under"]["sandbox_boundary"] is False


def test_attestation_writes_a_file(shared_att):
    import tempfile
    import attestation
    with tempfile.TemporaryDirectory() as d:
        p = attestation.write_attestation(shared_att, outdir=d)
        assert os.path.exists(p)
        assert p.endswith(".json")
        import json
        assert json.load(open(p))["schema"].startswith("blast-radius/attestation")


def test_strip_fences():
    assert "print(1)" in vultr_inference.strip_fences("```python\nprint(1)\n```")
    assert "print(1)" in vultr_inference.strip_fences("blah\n```python\nprint(1)\n```")
    assert vultr_inference.strip_fences("print(1)") == "print(1)"


def test_build_returns_nonempty_report():
    import main
    out = main.build("smoke input", probe_timeout=FAST_TIMEOUT)
    assert isinstance(out, str) and out.strip()
    assert "BLAST RADIUS" in out
