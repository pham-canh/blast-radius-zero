#!/usr/bin/env python3
"""app.py — BLAST RADIUS demo (Gradio + FastAPI healthcheck).

Runs on a Vultr VM (the backend must be a Vultr VM). Three screens, each showing
evidence rather than a claim:
  1) Task input + the agent's real execution result (with self-healing attempts)
  2) Blast radius report across the four axes
  3) Blast radius score history (persisted to disk)
  4) Attestation download for an auditor

Deploy: run directly on the Vultr VM (the app must call `docker run`, so do not
wrap it in a container). Demo URL = the VM's IP:7860 (or HTTPS via Caddy).
Local: pip install -r requirements.txt && python3 app.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

try:
    import gradio as gr
except Exception:  # gradio is a runtime dep for the UI, not for the core loop
    gr = None

# Import errors must surface, never silently degrade into a fake result.
try:
    import blast_radius
    import history
    import main
    import sandbox
    import vultr_inference
except Exception as _exc:  # pragma: no cover
    raise SystemExit(
        f"Could not import src/: {_exc}\n"
        "Run `python3 src/main.py --probe` to confirm the core loop works."
    )

HISTORY = history.RunHistory()


def _runtime_label() -> str:
    if sandbox.docker_available():
        return "container (Docker — real security boundary)"
    return ("rlimits (DEGRADED — NOT a security boundary; "
            "model-written code will not be executed)")


def run_task(task: str, stdin_data: str) -> tuple[str, str, str]:
    """Screen 1 + 2: run the agent loop, return its output and the radius report."""
    report = main.run_task(task or main.DEFAULT_TASK, stdin_data=stdin_data or None,
                           probe=True)
    HISTORY.append({
        "task": report["task"],
        "blast_radius": report["blast_radius"]["blast_radius"],
        "verdict": report["blast_radius"]["verdict"],
        "attempts": len(report.get("attempts", [])),
        "fixed": report.get("fixed", False),
    })

    llm = report["llm"]
    exec_block = ""
    if report["code_generated"]:
        e = report["exec"]
        attempts = report.get("attempts", [])
        if len(attempts) > 1:
            exec_block += (f"self-heal = {len(attempts)} attempts "
                           f"({'fixed the failure' if report.get('fixed') else 'gave up'})\n")
        exec_block += (f"runtime = {e['runtime']}  (limit: {e['limits']})\n"
                       f"exit = {e['exit_code']}  duration = {e['duration_s']}s\n")
        if e.get("runtime_error"):
            exec_block += f"NOT EXECUTED: {e.get('note', 'runtime error')}\n"
        exec_block += (f"\n--- code ---\n{report['code']}\n\n--- stdout ---\n"
                       f"{(e['stdout'] or '(empty)').rstrip()}\n")
        if e["stderr"].strip():
            exec_block += f"\n--- stderr ---\n{e['stderr'].rstrip()}"
    else:
        exec_block = "Code generation did not run:\n" + llm

    header = (f"Task: {report['task']}\n"
              f"LLM: {llm}\n"
              f"Sandbox runtime: {_runtime_label()}\n")
    return header + "\n" + exec_block, blast_radius.format_report(report["blast_radius"]), \
        _history_table()


def _history_table() -> str:
    records = HISTORY.recent(10)
    if not records:
        return "No runs yet."
    rows = ["| # | blast radius | verdict | attempts | task | when |",
            "|---|---|---|---|---|---|"]
    for i, h in enumerate(records, 1):
        age = h.get("at", "")[:19].replace("T", " ")
        rows.append(f"| {i} | **{h.get('blast_radius', '?')}** | {h.get('verdict', '?')} "
                    f"| {h.get('attempts', '?')} | {str(h.get('task', ''))[:60]} "
                    f"| {age} |")
    return "\n".join(rows)


def recheck() -> str:
    """Screen 2 stand-alone: re-measure containment without running a task."""
    return blast_radius.format_report(
        blast_radius.run_probes(runtimes=("container",) if sandbox.docker_available()
                                else ("rlimits",), verbose=False))


def write_attestation() -> tuple[str, str]:
    """Screen 4: measure fresh and return a downloadable attestation file."""
    att = main.attest(task="demo UI attestation")
    return att["_path"], format_attestation_summary(att)


def format_attestation_summary(att: dict) -> str:
    from attestation import format_summary
    return format_summary(att)


def _health() -> dict:
    return {
        "status": "ok",
        "runtime": _runtime_label(),
        "docker": sandbox.docker_available(),
        "llm_key": vultr_inference.have_key(),
        "provider": vultr_inference.provider(),
        "model": vultr_inference.model_name() or None,
    }


if gr is None:
    print("gradio is not installed. Run `pip install -r requirements.txt` and try again.",
          file=sys.stderr)
    raise SystemExit(1)

with gr.Blocks(title="BLAST RADIUS — Safe Agent Execution on Vultr") as demo:
    gr.Markdown("# BLAST RADIUS\n**An agent that runs untrusted code, measured by what it cannot escape.**")
    gr.Markdown(f"Current sandbox runtime: **{_runtime_label()}**")

    with gr.Tab("1. Run task"):
        task_in = gr.Textbox(label="Task", value=main.DEFAULT_TASK, lines=3)
        input_in = gr.Textbox(label="Input (stdin)", value=main.SAMPLE_CSV, lines=6)
        go = gr.Button("Run agent", variant="primary")
        task_out = gr.Textbox(label="Real execution result", lines=22)
        radius_out = gr.Textbox(label="Blast radius report", lines=20)
    with gr.Tab("2. Measure blast radius"):
        remeasure = gr.Button("Re-measure containment")
        radius_only = gr.Textbox(label="Four containment axes", lines=24)
        remeasure.click(recheck, outputs=radius_only)
    with gr.Tab("3. History"):
        hist = gr.Textbox(label="Blast radius score history (persisted)", lines=14)
    with gr.Tab("4. Attestation"):
        attest_btn = gr.Button("Measure now and write attestation")
        attest_file = gr.File(label="Attestation JSON", interactive=False)
        attest_summary = gr.Textbox(label="Attestation summary", lines=18)
        attest_btn.click(write_attestation, outputs=[attest_file, attest_summary])

    go.click(run_task, inputs=[task_in, input_in], outputs=[task_out, radius_out, hist])
    demo.load(_history_table, outputs=hist)

demo.queue()

try:
    from fastapi import FastAPI
except Exception:  # pragma: no cover - gradio normally brings fastapi
    FastAPI = None

if FastAPI is not None:
    app = FastAPI(title="Blast Radius")

    @app.get("/healthz")
    def healthz() -> dict:
        return _health()

    gr.mount_gradio_app(app, demo, path="/")
else:  # pragma: no cover
    app = None


if __name__ == "__main__":
    if app is not None:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=7860)
    else:
        demo.launch(server_name="0.0.0.0", server_port=7860, show_error=True)
