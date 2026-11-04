# BLAST RADIUS

**An agent that runs untrusted code, measured by what it cannot escape.**

Most agent demos *claim* they execute safely. Nobody shows evidence. BLAST RADIUS
runs hostile payloads against its own sandbox and publishes the measured result:
how far the blast radius actually reaches.

Event: [Vultr: Agent Rush Hackathon](https://lablab.ai/ai-hackathons/vultr-hackathon)
Challenge: **Blast Radius Zero — Safe Agent Execution on Vultr**

## The problem

A June 2026 study ([arXiv 2606.24496](https://arxiv.org/abs/2606.24496)) found
agentic tools can still exfiltrate API keys and compromise the operator's machine
*even when the agent runs inside a sandboxed container*. Containers get the
containment claim; almost nobody produces the containment evidence. Teams
shipping agents to production cannot answer "is this sandbox actually containing?"

## What this does

1. Give the agent a task.
2. Vultr Serverless Inference writes the code.
3. The code executes in a throwaway container on a Vultr VM.
4. If it fails, the agent reads the real stderr and repairs the program, then
   reruns it (up to 3 attempts).
5. A probe suite attacks that container and measures what got out.
6. You get a **blast radius score** with evidence — and an attestation file.

`blast radius = 0` means Blast Radius Zero.

### Why AI is load-bearing

The sandbox is not fed a fixed script. The payload is generated from the user's
task, and when it fails the LLM receives the sandbox's real stderr and returns a
fix. Remove the model and the demo has nothing to run: this is an agent with a
measured safety boundary, not a static benchmark.

## Quickstart

```bash
# does this machine have a real sandbox boundary?
python3 src/main.py --probe

# run one task end to end (ships a sample CSV on stdin)
python3 src/main.py "read CSV from stdin, print the mean of the 'price' column"

# cap the repair budget (default 3; 1 disables self-healing)
python3 src/main.py --max-attempts 1 "read CSV from stdin, print the mean price"

# use your own input (file, literal text, or stdin with "-")
python3 src/main.py --input data.csv "read CSV from stdin, print the mean price"
python3 src/main.py --input-text "a,b\n1,2\n" "sum column b"

# machine-readable report
python3 src/main.py --json "read CSV from stdin, print the mean price"

# run a fresh containment measurement and write the attestation file
python3 src/main.py --attest

# tests
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest src/ -q
```

`--probe` prints the four containment axes, one line per probe. If Docker is not
available it says `DEGRADED` and refuses to claim containment — see *Honest
reporting* below. A task that reads stdin gets the built-in sample CSV unless
`--input` overrides it, so the quickstart returns a real result.

## The four axes

The challenge names these; each one is measured by a probe that tries to break it.

| Axis | Probe | Contained means |
|---|---|---|
| Process isolation | walk the filesystem for the host canary | canary never reached |
| Secret hygiene | enumerate env for host secrets; try raw egress | nothing leaked, no connection |
| Resource limits | memory bomb, fork bomb | killed by cap, not by luck |
| Lifecycle discipline | `rm -rf /`; leftover pid file | host intact, nothing survives the run |

### Honest reporting

The rules the code enforces, because a containment demo that lies is worthless:

- **Verified from the host side.** The host plants a canary the probe cannot know
  about, then checks afterwards whether it was reached. A probe that crashes,
  hangs, or lies never scores a PASS.
- **`rm -rf` only runs inside a container.** The rlimits fallback applies real
  limits but is *not* a security boundary, so destructive payloads are refused
  there rather than risked on your machine.
- **Model-written code only runs inside a container.** The same rule covers any
  task the agent generates: without Docker the code is not executed at all, and
  the run is reported as not measured.
- **No Docker daemon means DEGRADED, not "contained".** The rlimits path exists so
  the code runs in CI; reports from it are labelled and do not claim containment.
- **A probe that never ran is UNVERIFIED, not CONTAINED.** A failed `docker run`
  or a missing runtime cannot score a pass; an axis with unmeasured probes is
  reported `PARTIAL`, and the overall verdict can never be `BLAST RADIUS ZERO`.
- **Only a real limit signal counts.** A resource bomb passes only if the cap or
  the clock killed it, or the payload caught the limit error itself; an unrelated
  crash is not containment. Captured output is capped so a printing loop cannot
  exhaust host memory.

On a machine without Docker, the suite correctly reports a non-zero blast radius
— the rlimits fallback really does let a payload read host files and reach the
network. On the Vultr VM, the container boundary blocks both: `blast radius = 0`.

## Vultr integration

All three mandatory pillars are load-bearing, not logos:

- **Vultr VM** — hosts the app and spawns every sandbox container. Remove it and
  there is nowhere to execute.
- **Vultr Serverless Inference** — every LLM call goes through
  `https://api.vultrinference.com/v1` (OpenAI-compatible): the first generation
  and every repair round. Remove it and both agent loops stop.
- **Sandbox boundary** — `docker run` with `--network none`, `--read-only`,
  `--cap-drop ALL`, non-root user, no-new-privileges, memory/pids/cpu caps.
  Every one of those flags is pinned by a test.

## Configuration

Configuration lives in `.env` (gitignored); `.env.example` is the template. Each
teammate uses their own `.env` with their own key and exactly one
`INFERENCE_MODEL`. Copy the template and fill it in:

```bash
cp .env.example .env
# edit .env
python3 src/vultr_inference.py --list-models   # verify provider + model
```

| Variable | Purpose |
|---|---|
| `INFERENCE_PROVIDER` | `vultr` (default), `anthropic`, or `openai` |
| `INFERENCE_API_KEY` | Vultr key, or any OpenAI-compatible provider |
| `ANTHROPIC_API_KEY` | Claude key when `INFERENCE_PROVIDER=anthropic` |
| `INFERENCE_BASE_URL` | Default `https://api.vultrinference.com/v1` |
| `INFERENCE_MODEL` | **Required**; no default. Copy an id from `--list-models` |
| `INFERENCE_FALLBACK_MODELS` | Optional comma-separated list; empty by default |
| `BLAST_RADIUS_BACKEND` | Set to `vultr` on the VM so attestations record the host |
| `BLAST_RADIUS_HISTORY` | UI history file; default `out/history.jsonl` |
| `BLAST_RADIUS_OUTDIR` | Attestation output directory; default the system temp dir |

No model id is bundled: `INFERENCE_MODEL` is required and must be an id the
provider actually serves. Do not add a default id back to the source; hosted model
ids rotate and a withdrawn route 404s on demo day. If the team has a Claude
key, set `INFERENCE_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`, and an
`INFERENCE_MODEL`; the client uses the Anthropic Messages API. This is supported
for local development, but the submitted demo **must** keep `INFERENCE_PROVIDER=vultr` —
the challenge requires every LLM call to go through Vultr Serverless Inference.

Without a key the code-generation step reports `SKIPPED` with instructions; the
containment measurement still runs. It never fakes a model response.

## Run the demo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then add your key and INFERENCE_MODEL
python3 app.py
```

The app starts on `0.0.0.0:7860` and has four screens:

1. **Run a task** — task input, stdin input, generated code, repair attempts, real
   stdout, live blast radius report.
2. **Measure blast radius** — re-run the probe suite without running a task.
3. **History** — blast radius score for recent runs, persisted to disk
   (`BLAST_RADIUS_HISTORY`, default `out/history.jsonl`).
4. **Attestation** — measure fresh and download the JSON record.

`GET /healthz` returns the runtime, Docker availability, provider and configured
model, so a deploy check does not have to scrape the UI.

## Deployment (Vultr VM)

The app runs directly on a Vultr Cloud Compute VM, not inside a container: it
needs to call `docker run` itself. Wrapping it in Docker would require privileged
mode or docker-in-docker, which we deliberately avoid.

**1. Create the VM.** Compute → Cloud Compute → Ubuntu 24.04, at least 2 vCPU /
4 GB RAM. Open ports **22**, **80** and **443** in the firewall.

**2. Bootstrap the VM.**

```bash
git clone https://github.com/pham-canh/blast-radius-zero.git /tmp/blast-radius-setup
cd /tmp/blast-radius-setup
sudo BLAST_RADIUS_DOMAIN=demo.example.com \
     bash deploy/vultr-bootstrap.sh https://github.com/pham-canh/blast-radius-zero.git main
```

The script installs Docker, Python, Caddy, a `blastradius` systemd service and
HTTPS (Caddy falls back to `<vm-ip>.sslip.io` when no domain is given), then
waits for `/healthz`.

**3. Add the key and one model, then restart.**

```bash
sudo editor /etc/blast-radius/blast-radius.env
sudo systemctl restart blast-radius
sudo systemctl status blast-radius --no-pager
```

The demo URL is printed by the script (HTTPS), and `/healthz` shows Docker,
provider and model status.

**4. Confirm real containment on the VM.**

```bash
cd /opt/blast-radius
python3 src/main.py --probe
```

This must report `runtime: container` and `blast radius = 0`. A `runtime: rlimits`
or `DEGRADED` line means Docker is not being used, so containment is not proven.

Manual install is still possible: install Docker, create a venv, install
`requirements.txt`, then run `app.py`. Keep the app outside a container so it can
call `docker run`.

Note: Vultr bills hourly, including idle instances. Create the VM when you are
ready to deploy, and destroy it when you are done demoing.

## Architecture

```
task -> src/main.py:run_task()
          1. vultr_inference.generate_code()   -> code           (Vultr Serverless Inference)
          2. sandbox.execute(code)             -> stdout/stderr  (docker run, disposable)
          3. if exit != 0: repair_code()       -> new code, re-execute (max 3 attempts)
          4. blast_radius.run_probes()         -> blast radius   (host-side canary check)
```

| File | Responsibility |
|---|---|
| `src/vultr_inference.py` | Vultr Serverless Inference client (generate + repair) |
| `src/sandbox.py` | Container runtime + rlimits fallback |
| `src/blast_radius.py` | The probe suite and the scoring |
| `src/attestation.py` | Attestation file for auditor hand-off |
| `src/history.py` | Persisted run history (JSONL, bounded) |
| `src/main.py` | The self-healing core loop |
| `app.py` | Gradio UI + FastAPI `/healthz` (4 screens) |
| `deploy/` | Vultr bootstrap, systemd unit, Caddy HTTPS config |
| `src/test_smoke.py`, `src/test_containment.py`, `src/test_history.py` | Test suite |

## Status

Verified: 43 tests pass; the fallback probe suite runs end to end; a real
container run returns the correct mean from stdin; the self-healing loop is
unit-tested with a mocked model (failure → repair → success, budget exhaustion,
and no repair on infrastructure errors).
Verified on a local Docker daemon: container mode returns **blast radius = 0**
across all four axes, with the host canary intact (attestation emitted).
Not yet verified: a real LLM call (needs `INFERENCE_API_KEY` plus
`INFERENCE_MODEL`; no model id is bundled), deployment to a Vultr VM, and the
event submission assets (video, deck).

## License

MIT
