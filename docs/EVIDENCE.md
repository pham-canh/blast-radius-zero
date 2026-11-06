# Evidence — 6 November 2026

All numbers below were produced by the deployed build, not by a mock. The
commands are reproducible from the repo; the live demo is the source of truth.

## Environment

| | |
|---|---|
| Host | Vultr Cloud Compute, Shared CPU, 2 vCPU / 4 GB RAM, Singapore |
| OS | Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic |
| Sandbox | Docker 29.1.3 (`runtime: container`) |
| Python | 3.12.3 (deployed venv) |
| LLM | Vultr Serverless Inference, `deepseek-v4.1-flash-1017` |
| Demo | <https://139.180.147.61.sslip.io/> |
| Bootstrapped by | `deploy/vultr-bootstrap.sh` |

## Health check

```json
{"status":"ok","runtime":"container (Docker — real security boundary)","docker":true,"llm_key":true,"provider":"vultr","model":"deepseek-v4.1-flash-1017"}
```

## Test suite

```text
$ PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest src/ -q
...........................................                              [100%]
44 passed in 11.13s
```

## Real agent run (model-written code)

Golden path from the UI: default CSV task, sample input, one generation, one
execution. The code below was written by Vultr Serverless Inference; the stdout
came from the container.

```text
LLM: OK via https://api.vultrinference.com/v1 (provider vultr, model deepseek-v4.1-flash-1017) | attempts=1
Sandbox runtime: container (Docker — real security boundary)

runtime = container  (limit: {'memory_mb': 256, 'cpus': 0.5, 'pids_limit': 64, 'timeout_s': 20})
exit = 0  duration = 0.93s

--- code ---
import sys
import csv

reader = csv.DictReader(sys.stdin)
prices = [float(row["price"]) for row in reader if row.get("price") not in (None, "")]
print(f"{sum(prices) / len(prices):.2f}")

--- stdout ---
11.67
```

Screenshots: [`docs/run.png`](run.png) (task + stdout + report),
[`docs/ui.png`](ui.png) (containment screen).

## Containment probe

```text
$ python3 src/main.py --probe
blast radius = 0  ->  BLAST RADIUS ZERO   [runtime: container]

  process_isolation        CONTAINED  (measured 1/1)
  secret_hygiene           CONTAINED  (measured 2/2)
  resource_limits          CONTAINED  (measured 2/2)
  lifecycle_discipline     CONTAINED  (measured 2/2)

  [CONTAINED] fs_escape      CONTAINED
  [CONTAINED] env_leak       CONTAINED
  [CONTAINED] net_egress     CONTAINED egress blocked: OSError
  [CONTAINED] mem_bomb       stopped by limit exit=137 1.0s
  [CONTAINED] fork_bomb      stopped by limit exit=0 0.5s
  [CONTAINED] rm_rf          rm_rf contained, host canary intact
  [CONTAINED] residue        no container or pid file survived
```

## Attestation

[`docs/attestation.example.json`](attestation.example.json) is the actual JSON
written by `src/main.py --attest` on the VM at `2026-11-06T03:45:20Z`. It records:

- `blast_radius: 0`, `verdict: "BLAST RADIUS ZERO"`
- `host_canary_intact: true`
- `measured_under.vultr_vm_backend: true`
- `measured_under.llm_provider: "vultr"`
- all four axes `CONTAINED`

The attestation contains no key material or private host data.

## Fresh-install verification

The pins in `requirements.txt` were installed into a clean Python 3.12 venv (not
the deployed one) on 6 Nov 2026:

```text
gradio==4.44.1
gradio_client==1.3.0
huggingface_hub==0.36.2
fastapi==0.115.6
starlette==0.41.3
pydantic==2.9.2
```

Then the Gradio API built and the UI served HTTP 200:

```text
$ python -c "import app; print(len(app.demo.get_api_info()['named_endpoints']))"
4
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7860/
200
```

Why these pins are load-bearing:

- `huggingface_hub>=1.0` removes `HfFolder`, which Gradio 4.44 imports.
- FastAPI 0.162 / Starlette 1.10 changed the `bool` schema path used by
  `gradio_client`; `0.115.6` / `0.41.3` is the tested pair.
- `pydantic==2.9.2` avoids the bool JSON-schema edge that required a
  `gradio_client` patch on the first deploy.

## Deployment fixes confirmed

- The stock VM had UFW active with only `22/tcp`; the bootstrap now opens
  `80/443/7860` when UFW is active.
- `ProtectHome=true` blocked Docker's default config path. The service now uses
  `DOCKER_CONFIG=/var/lib/blast-radius/.docker`, so container stderr is clean.
- The bootstrap pre-pulls `python:3.11-slim`, pins the requirement set, and runs
  `--probe` as the `blastradius` user before printing the URL.

## Reproduce

```bash
git clone https://github.com/pham-canh/blast-radius-zero.git
cd blast-radius-zero
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # add INFERENCE_API_KEY + INFERENCE_MODEL
python3 src/main.py --probe
python3 app.py
```

On a fresh Vultr VM, use `deploy/vultr-bootstrap.sh` (see the README). The event
requires the Vultr VM and Vultr Serverless Inference; the demo keeps
`INFERENCE_PROVIDER=vultr`.
