"""Blast radius measurement — the product.

The claim every agent demo makes is "it executes safely". Nobody shows evidence.
This module turns that claim into a number: for each of the four axes the event
names (process isolation, secret hygiene, resource limits, lifecycle discipline)
we run a probe that tries to break containment, then record what it reached.

blast radius = number of axes where the probe got OUT. 0 means Blast Radius Zero.

Containment is verified from the HOST side, not from the probe's own report: the
host plants a canary the probe cannot know about, then checks afterwards whether
the probe ever reached it. A probe that lies, crashes, or is skipped never
produces a PASS.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass

import sandbox

AXES = ("process_isolation", "secret_hygiene", "resource_limits", "lifecycle_discipline")
CANARY_ENV_NAME = "BR_CANARY_SECRET"
CANARY_FILE_PREFIX = "br_host_canary_"


@dataclass
class Probe:
    key: str
    axis: str
    title: str
    code: str
    destructive: bool = False
    kind: str = "generic"  # generic | fs | env | net | bomb | rmrf | residue


# --------------------------------------------------------------------- canary


def plant_canary() -> tuple[str, str, str]:
    """Hide a secret where a contained process must not reach it.

    Returns (token, env_name, file_path). The env var is set on the host only;
    the sandbox child gets a scrubbed environment, so seeing it means a leak.

    Concurrency note: the env var name is fixed, so two probe suites must not run
    at the same time in one process. The Gradio app queues runs; if multi-user
    execution is ever added, give each run its own env name.
    """
    token = f"br-{uuid.uuid4().hex}"
    env_name = CANARY_ENV_NAME
    os.environ[env_name] = token  # host process only; sandbox scrubs it for the child
    # Plant it shallow (/tmp, or /private/tmp on macOS) so the filesystem probe
    # can actually reach it. mkstemp's default dir is several levels deep on
    # macOS, and the probe's depth cap would prune it before that — producing a
    # false CONTAINED on the one axis this demo exists to measure.
    fd, path = tempfile.mkstemp(prefix=CANARY_FILE_PREFIX, suffix=".txt", dir="/tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    return token, env_name, path


def unplant_canary(env_name: str, path: str) -> None:
    os.environ.pop(env_name, None)
    try:
        os.remove(path)
    except OSError:
        pass


def canary_intact(token: str, path: str) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read() == token
    except OSError:
        return False


def redact_token(text: str, token: str) -> str:
    """Never put the raw canary in a report an auditor can read.

    The token is the proof that the probe reached the host; it does not need to
    travel in the attestation. Replacing it keeps the evidence and removes the
    secret from logs, the UI and the JSON file.
    """
    return text.replace(token, "<canary>") if token else text


def container_gone(container_id: str) -> bool:
    """Lifecycle discipline, checked from the host: the container must be gone.

    An empty id means the rlimits fallback ran; its workdir is removed separately.
    """
    if not container_id:
        return True
    try:
        proc = subprocess.run(["docker", "inspect", container_id],
                              capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return False  # the container still exists
        # Only "not found" means gone. A daemon/socket error is unknown, and
        # unknown must never be reported as lifecycle discipline.
        err = (proc.stderr or "").lower()
        return "no such object" in err or "no such container" in err
    except (subprocess.SubprocessError, OSError):
        # Fail closed: if we cannot inspect the container, we cannot claim it is
        # gone. "Unknown" must never be reported as lifecycle discipline.
        return False


# --------------------------------------------------------------------- probes

PROBES: list[Probe] = [
    Probe(
        key="fs_escape",
        axis="process_isolation",
        title="Filesystem escape — find the host canary",
        kind="fs",
        code="""
import os
SKIP = ("/proc", "/sys", "/dev", "/System", "/Volumes", "/Library", "/private/var/vm")
hits = []
for root, dirs, files in os.walk("/", topdown=True):
    if root.count("/") > 3 or any(root.startswith(p) for p in SKIP):
        dirs[:] = []
        continue
    for fn in files:
        if fn.startswith("br_host_canary_"):
            p = os.path.join(root, fn)
            try:
                data = open(p, encoding="utf-8").read()[:120]
            except Exception:
                data = "READ_FAILED"
            hits.append(p + " TOKEN=" + data)
if hits:
    print("ESCAPED_FILES=" + " | ".join(hits[:5]))
else:
    print("CONTAINED")
""",
    ),
    Probe(
        key="env_leak",
        axis="secret_hygiene",
        title="Secret hygiene — can host secrets leak into the sandbox",
        kind="env",
        code="""
import os
suspicious = [k for k in os.environ if "CANARY" in k.upper() or "SECRET" in k.upper()]
print("LEAKED_ENV=" + ",".join(sorted(suspicious)[:5]) if suspicious else "CONTAINED")
""",
    ),
    Probe(
        key="net_egress",
        axis="secret_hygiene",
        title="Egress — send data out of the sandbox",
        kind="net",
        code="""
import socket
try:
    socket.setdefaulttimeout(4)
    socket.create_connection(("1.1.1.1", 80), timeout=4).close()
    print("ESCAPED_EGRESS=connected")
except Exception as e:
    print("CONTAINED egress blocked: %s" % type(e).__name__)
""",
    ),
    Probe(
        key="mem_bomb",
        axis="resource_limits",
        title="Resource limit — memory bomb (must be killed by the cap)",
        kind="bomb",
        code="""
blocks = []
try:
    while True:
        blocks.append(bytearray(24 * 1024 * 1024))
except MemoryError:
    print("LIMIT_MEMORY")
""",
    ),
    Probe(
        key="fork_bomb",
        axis="resource_limits",
        title="Resource limit — fork bomb (must be killed by pids-limit)",
        kind="bomb",
        # A fork bomb is never run on the host: RLIMIT_NPROC is not a security
        # boundary, and a platform that ignores it would harm the operator.
        destructive=True,
        code="""
import os
while True:
    try:
        if os.fork() == 0:
            os._exit(0)
    except OSError:
        print("LIMIT_PIDS")
        break
""",
    ),
    Probe(
        key="rm_rf",
        axis="lifecycle_discipline",
        title="Lifecycle — rm -rf / inside the sandbox (must be harmless)",
        destructive=True,
        kind="rmrf",
        code="""
import os
removed = 0
for root, dirs, files in os.walk("/", topdown=False):
    if any(p in root for p in ("/proc", "/sys", "/dev")):
        continue
    for fn in files:
        try:
            os.remove(os.path.join(root, fn))
            removed += 1
        except Exception:
            pass
print("rm_rf done inside sandbox, removed=%d" % removed)
""",
    ),
    Probe(
        key="residue",
        axis="lifecycle_discipline",
        title="Lifecycle — no process or file survives the run",
        kind="residue",
        code="""
import os
open("leaked_pid", "w").write(str(os.getpid()))
print("child pid=%d" % os.getpid())
""",
    ),
]


def run_probes(*, runtimes: tuple[str, ...] = ("container",), verbose: bool = False,
               timeout: float = 15.0) -> dict:
    """Run the probe suite and score the four axes. Returns a report dict.

    `timeout` is per-probe. Unit tests pass a small value; the resource bombs are
    stopped by the cap in production and by the clock in fast tests.
    """
    allow_container = "container" in runtimes
    allow_rlimits = "rlimits" in runtimes
    token, env_name, canary_path = plant_canary()
    results: list[dict] = []
    runtime_used: set[str] = set()

    def finish() -> None:
        unplant_canary(env_name, canary_path)

    canary_final = False
    try:
        for probe in PROBES:
            # Destructive payloads are refused outside a container: rlimits is not
            # a security boundary, so running rm -rf there would endanger the host.
            if probe.destructive and not allow_container:
                results.append({"key": probe.key, "axis": probe.axis, "title": probe.title,
                                "outcome": "SKIPPED", "contained": True, "measured": False,
                                "detail": "destructive payload only runs in a container"})
                continue

            res = sandbox.execute(probe.code, allow_container=allow_container,
                                  allow_rlimits=allow_rlimits, timeout=timeout, memory_mb=256,
                                  pids_limit=64, require_container=probe.destructive)
            # A runtime that never ran the payload is not evidence of containment.
            if res.runtime_error:
                results.append({"key": probe.key, "axis": probe.axis, "title": probe.title,
                                "outcome": "UNVERIFIED", "contained": True, "measured": False,
                                "detail": res.note or "runtime error — payload not measured",
                                "runtime": res.runtime, "degraded": True})
                if verbose:
                    print(f"  [UNVERIFIED] {probe.key:14} {res.note}")
                continue

            # A non-bomb probe killed by the clock produced no verdict. Counting a
            # timeout as contained would turn a slow image pull into a false PASS.
            if res.timed_out and probe.kind != "bomb":
                runtime_used.add(res.runtime)
                results.append({"key": probe.key, "axis": probe.axis, "title": probe.title,
                                "outcome": "UNVERIFIED", "contained": True, "measured": False,
                                "detail": f"timed out after {res.duration_s:.1f}s — no verdict",
                                "runtime": res.runtime, "degraded": res.degraded})
                if verbose:
                    print(f"  [UNVERIFIED] {probe.key:14} timed out")
                continue

            # A probe that crashed never produced a verdict. An intact host canary
            # is not evidence that the probe searched for it.
            if probe.kind != "bomb" and res.exit_code != 0:
                runtime_used.add(res.runtime)
                results.append({"key": probe.key, "axis": probe.axis, "title": probe.title,
                                "outcome": "UNVERIFIED", "contained": True, "measured": False,
                                "detail": f"probe exited {res.exit_code} — no verdict",
                                "runtime": res.runtime, "degraded": res.degraded})
                if verbose:
                    print(f"  [UNVERIFIED] {probe.key:14} exited {res.exit_code}")
                continue

            runtime_used.add(res.runtime)
            out, err = res.stdout, res.stderr
            combined = f"{out}\n{err}"

            # Host-side authority: the canary file must be untouched, its token
            # must never appear in probe output, and the env var name must not be
            # echoed back without a CONTAINED verdict. Any of those is a breach.
            canary_leaked = (token in combined) or (env_name in out and "CONTAINED" not in out)
            file_intact = canary_intact(token, canary_path)

            # Never print a blank verdict: fall back to why the probe produced nothing.
            def _why() -> str:
                if out.strip():
                    return out.strip().splitlines()[-1][:110]
                if res.timed_out:
                    return f"timeout {res.duration_s:.1f}s, no output"
                if res.stderr.strip():
                    return f"exit={res.exit_code} stderr={res.stderr.strip().splitlines()[-1][:80]}"
                return f"exit={res.exit_code}, no output"

            if probe.kind == "bomb":
                # Only a real limit signal counts: killed by the cap, killed by the
                # clock, or the payload caught the limit error and said so. A generic
                # non-zero exit (syntax error, missing import) is not containment.
                limit_marker = "LIMIT_MEMORY" in out or "LIMIT_PIDS" in out
                contained = res.killed_by_limit or res.timed_out or limit_marker
                detail = (f"stopped by limit exit={res.exit_code} {res.duration_s:.1f}s"
                          if contained else f"ran {res.duration_s:.1f}s without hitting a limit")
            elif probe.kind == "net":
                contained = "ESCAPED_EGRESS" not in out
                detail = _why()
            elif probe.kind == "rmrf":
                contained = file_intact and not canary_leaked
                detail = ("rm_rf contained, host canary intact" if contained
                          else "rm_rf ESCAPED to host")
            elif probe.kind == "residue":
                gone = container_gone(res.container_id)
                contained = gone and not canary_leaked and file_intact
                detail = ("no container or pid file survived" if contained
                          else "residue survived the run")
            else:  # fs / env / generic
                contained = (not canary_leaked) and file_intact
                detail = _why()

            detail = redact_token(detail, token)
            results.append({"key": probe.key, "axis": probe.axis, "title": probe.title,
                            "outcome": "CONTAINED" if contained else "LEAK",
                            "contained": bool(contained), "measured": True,
                            "detail": detail, "runtime": res.runtime,
                            "degraded": res.degraded, "duration_s": round(res.duration_s, 2)})
            if verbose:
                print(f"  [{results[-1]['outcome']:9}] {probe.key:14} {detail}")

        # Check the host canary BEFORE cleanup removes it — otherwise every run
        # reports the canary as reached and the host looks breached.
        canary_final = canary_intact(token, canary_path)
    finally:
        finish()

    axes = {}
    for axis in AXES:
        rows = [r for r in results if r["axis"] == axis]
        measured = [r for r in rows if r["measured"]]
        if not measured:
            verdict = "UNVERIFIED"
        elif not all(r["contained"] for r in measured):
            verdict = "LEAK"
        elif len(measured) < len(rows):
            # Some probes on this axis never ran. Never upgrade that to CONTAINED.
            verdict = "PARTIAL"
        else:
            verdict = "CONTAINED"
        axes[axis] = {"verdict": verdict, "probes": len(rows), "measured": len(measured)}

    breaches = sum(1 for r in results if r["outcome"] == "LEAK")
    if breaches:
        verdict = "BLAST RADIUS > 0"
    elif all(v["verdict"] == "CONTAINED" for v in axes.values()):
        verdict = "BLAST RADIUS ZERO"
    else:
        verdict = "PARTIALLY UNVERIFIED"
    return {
        "blast_radius": breaches,
        "verdict": verdict,
        "axes": axes,
        "probes": results,
        "runtimes": sorted(runtime_used),
        "degraded": any(r.get("degraded") for r in results),
        "canary_intact": canary_final,
        "canary_leaked": not canary_final,
    }


def format_report(report: dict) -> str:
    head = (f"blast radius = {report['blast_radius']}  ->  {report['verdict']}"
            f"   [runtime: {', '.join(report['runtimes']) or 'none'}]")
    if report.get("degraded"):
        head += "\n!! DEGRADED: fallback or failed runtime — containment not fully proven."
    lines = [head, ""]
    for axis in AXES:
        v = report["axes"][axis]
        lines.append(f"  {axis:24} {v['verdict']:10} (measured {v['measured']}/{v['probes']})")
    lines.append("")
    for r in report["probes"]:
        lines.append(f"  [{r['outcome']:9}] {r['key']:14} {r['detail']}")
    return "\n".join(lines)
