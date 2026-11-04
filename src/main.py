#!/usr/bin/env python3
"""BLAST RADIUS — core loop.

  task -> Vultr Serverless Inference generates code -> run in the sandbox
       -> real output -> blast radius report with evidence

Run:  python3 src/main.py "compute the mean price column of this CSV"
      python3 src/main.py --input data.csv "compute the mean price"
Check containment: python3 src/main.py --probe

Without an inference key the code-generation step explicitly reports SKIPPED;
the containment measurement still runs for real. It never mocks success.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import blast_radius  # noqa: E402
import sandbox  # noqa: E402
import vultr_inference  # noqa: E402
from attestation import build_attestation, format_summary, write_attestation  # noqa: E402

DEFAULT_TASK = (
    "Read CSV text from stdin. Print the mean of the 'price' column, rounded to 2 decimals."
)

SAMPLE_CSV = "name,price\nwidget,10.50\ngadget,20.25\nbolt,4.25\n"


def _runtimes() -> tuple[str, ...]:
    return ("container",) if sandbox.docker_available() else ("rlimits",)


MAX_ATTEMPTS_DEFAULT = 3


def _exec_report(exec_res: sandbox.ExecResult) -> dict:
    return {
        "runtime": exec_res.runtime, "exit_code": exec_res.exit_code,
        "timed_out": exec_res.timed_out, "duration_s": round(exec_res.duration_s, 2),
        "degraded": exec_res.degraded, "runtime_error": exec_res.runtime_error,
        "stdout": exec_res.stdout[-4000:], "stderr": exec_res.stderr[-2000:],
        "limits": exec_res.limits, "note": exec_res.note,
    }


def run_task(task: str, *, stdin_data: str | None = None, probe: bool = True,
             verbose: bool = False, probe_timeout: float = 15.0,
             max_attempts: int = MAX_ATTEMPTS_DEFAULT) -> dict:
    """Run the self-healing loop: generate → execute → repair → re-execute.

    A missing key or a failed model call is reported, never mocked. Runtime
    failures (no Docker, image pull error) stop the loop immediately: retrying
    cannot fix infrastructure, and running untrusted code without a container is
    not allowed.
    """
    report: dict = {"task": task, "stdin_bytes": len(stdin_data or "")}
    runtimes = _runtimes()
    report["runtimes"] = list(runtimes)
    attempts: list[dict] = []
    repair_errors: list[str] = []

    # --- 1. plan + generate code via Vultr Serverless Inference
    code = None
    report["llm"] = "ERROR: no inference attempt was made"
    if vultr_inference.have_key():
        try:
            code = vultr_inference.generate_code(task)
            report["llm"] = (f"OK via {vultr_inference.base_url()} "
                             f"(provider {vultr_inference.provider()}, "
                             f"model {vultr_inference.model_name()})")
        except (vultr_inference.InferenceError, vultr_inference.MissingInferenceKey) as exc:
            report["llm"] = f"ERROR: {exc}"
    else:
        report["llm"] = (
            "SKIPPED — no key configured. Copy .env.example to .env and fill in "
            "INFERENCE_API_KEY (Vultr) or ANTHROPIC_API_KEY (Claude)."
        )

    # --- 2. execute, then repair from real output until it works or budget ends
    limit = max(1, int(max_attempts))
    while code and len(attempts) < limit:
        # Generated code is untrusted: it must run inside a real container. Never
        # fall back to rlimits for it — that mode is not a security boundary and
        # would run model-written code directly on the operator's machine.
        exec_res = sandbox.execute(code, allow_container=("container" in runtimes),
                                   allow_rlimits=("rlimits" in runtimes),
                                   require_container=True, stdin_data=stdin_data,
                                   timeout=20, memory_mb=256)
        attempts.append({"n": len(attempts) + 1, "code": code,
                         "exec": _exec_report(exec_res)})
        if exec_res.runtime_error or exec_res.ok or len(attempts) >= limit:
            break
        try:
            code = vultr_inference.repair_code(
                task, code, exec_res.stdout, exec_res.stderr, len(attempts) + 1)
        except (vultr_inference.InferenceError,
                vultr_inference.MissingInferenceKey) as exc:
            repair_errors.append(str(exc))
            break

    report["attempts"] = attempts
    report["code_generated"] = bool(attempts)
    if attempts:
        final = attempts[-1]
        report["code"] = final["code"]
        report["exec"] = final["exec"]
        report["fixed"] = len(attempts) > 1 and final["exec"]["exit_code"] == 0 \
            and not final["exec"]["timed_out"]
        report["llm"] += f" | attempts={len(attempts)}"
        if report["fixed"]:
            report["llm"] += " | self-healed"
        if repair_errors:
            report["llm"] += f" | repair error: {repair_errors[-1]}"
    else:
        report["code"] = None
        report["exec"] = None
        report["fixed"] = False

    # --- 3. measure blast radius (always real)
    if probe:
        br = blast_radius.run_probes(runtimes=runtimes, verbose=verbose, timeout=probe_timeout)
        report["blast_radius"] = br
    return report


def build(task: str, stdin_data: str | None = None, probe_timeout: float = 15.0,
          max_attempts: int = MAX_ATTEMPTS_DEFAULT) -> str:
    """Return the human-readable report. Used by app.py and by CI smoke test."""
    r = run_task(task, stdin_data=stdin_data, verbose=True,
                 probe_timeout=probe_timeout, max_attempts=max_attempts)
    lines = [
        "=" * 72,
        f"BLAST RADIUS — task: {r['task']}",
        "=" * 72,
        f"[0/3] stdin         : {r['stdin_bytes']} bytes",
        f"[1/3] generate code : {r['llm']}",
    ]
    if r["code_generated"]:
        attempts = r["attempts"]
        if len(attempts) > 1:
            lines.append(f"[1b]  self-heal     : {len(attempts)} attempts "
                         f"({'fixed the failure' if r['fixed'] else 'gave up'})")
            for a in attempts[:-1]:
                last_err = (a["exec"]["stderr"].strip().splitlines() or ["(no output)"])[-1]
                lines.append(f"       attempt {a['n']}: exit={a['exec']['exit_code']} "
                             f"| {last_err[:90]}")
        lines += ["--- code ---", r["code"][:1200], "--------------"]
        e = r["exec"]
        lines += [f"[2/3] real run      : runtime={e['runtime']} exit={e['exit_code']} "
                  f"{e['duration_s']}s limits={e['limits']}"]
        if e.get("note"):
            lines.append(f"        {e['note']}")
        lines.append("--- stdout ---")
        lines.append((e["stdout"] or "(empty)").rstrip()[:2000])
        if e["stderr"].strip():
            lines.append("--- stderr ---")
            lines.append(e["stderr"].rstrip()[:800])
    else:
        lines.append("[2/3] real run      : SKIPPED (no code to run)")

    if r.get("blast_radius"):
        lines += ["", "[3/3] blast radius report", blast_radius.format_report(r["blast_radius"])]
    return "\n".join(lines)


def attest(task: str | None = None, outdir: str | None = None) -> dict:
    """Run a fresh containment measurement and write the attestation record.

    Returns the record with `_path` set to the JSON file. `task` is context only;
    the probes run regardless, because an attestation must describe the machine
    as it is now.
    """
    att = build_attestation(task=task, runtimes=_runtimes())
    att["_path"] = write_attestation(att, outdir)
    return att


def _parse_input_args(args: list[str]) -> tuple[str, str | None]:
    """Split `--input` / `--input-text` from the task text.

    The built-in sample CSV is the default so the quickstart task returns a real
    result instead of reading EOF.
    """
    stdin_data: str | None = SAMPLE_CSV
    task_parts: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--input", "--input-text") and i + 1 < len(args):
            value = args[i + 1]
            if arg == "--input" and value == "-":
                stdin_data = sys.stdin.read()
            elif arg == "--input":
                stdin_data = Path(value).read_text(encoding="utf-8")
            else:
                stdin_data = value
            i += 2
        else:
            task_parts.append(arg)
            i += 1
    return (" ".join(task_parts) or DEFAULT_TASK), stdin_data


def _pop_int_option(args: list[str], name: str, default: int) -> int:
    """Remove `--name N` from args and return N. Raises ValueError if malformed."""
    if name not in args:
        return default
    i = args.index(name)
    if i + 1 >= len(args):
        raise ValueError(f"{name} needs an integer value")
    try:
        value = int(args[i + 1])
    except ValueError as exc:
        raise ValueError(f"{name} needs an integer value") from exc
    del args[i:i + 2]
    return max(1, value)


def main() -> int:
    args = sys.argv[1:]
    # `--json` is a modifier, not a task word: accept it anywhere on the line.
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    try:
        max_attempts = _pop_int_option(args, "--max-attempts", MAX_ATTEMPTS_DEFAULT)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args and args[0] == "--probe":
        print(blast_radius.format_report(
            blast_radius.run_probes(runtimes=_runtimes(), verbose=True)))
        return 0
    if args and args[0] == "--attest":
        att = attest()
        print(format_summary(att))
        print(f"\n-> {att['_path']}")
        return 0
    try:
        task, stdin_data = _parse_input_args(args)
    except OSError as exc:
        print(f"Could not read the input file: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(run_task(task, stdin_data=stdin_data, max_attempts=max_attempts),
                         indent=2, default=str))
        return 0
    print(build(task, stdin_data=stdin_data, max_attempts=max_attempts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
