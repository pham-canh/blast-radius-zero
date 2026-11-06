# Submission — Vultr: Agent Rush Hackathon

**Challenge:** Blast Radius Zero — Safe Agent Execution on Vultr  
**Team:** arabeacon  
**Live demo:** <https://139.180.147.61.sslip.io/>  
**Repository:** <https://github.com/pham-canh/blast-radius-zero>

## Title

**BLAST RADIUS — Measured Containment for Agent Execution**

## Short description (175 / 255 characters)

> An agent that executes model-written code in a disposable Vultr-hosted
> container and publishes a measured blast radius score. 43 tests, real LLM
> calls, live demo, attestation.

## Long description (139 words)

> Most agent demos claim safe execution; almost none produce evidence. BLAST
> RADIUS is an agent that runs untrusted, model-written code inside a disposable
> Docker container on a Vultr VM, attacks that container with seven probes across
> four containment axes, and publishes the measured blast radius. The host plants
> a canary the payload cannot know about and verifies the result afterwards, so a
> crashed, hung or lying probe never scores a pass. On a successful run the
> verdict is BLAST RADIUS ZERO and a JSON attestation records the runtime, the
> four axes, the host canary state and the Vultr backend. The loop is
> self-healing: a failed program's real stderr goes back to Vultr Serverless
> Inference for repair. The public demo is live, and the repo includes 43 tests,
> the one-command Vultr bootstrap and the evidence from the 6 Nov run.

## Tags

AI Agents, Cybersecurity, Sandboxing, Vultr, Serverless Inference,
Developer Tools, Python, Gradio

## Team

**Team arabeacon** — Canh Pham (agent loop, inference, Vultr deployment),
Abdul Ahad (backend, sandboxing), Amna Yaqoob (product, coordination).

## Assets

| Asset | Location |
|---|---|
| Live demo | <https://139.180.147.61.sslip.io/> |
| Health check | <https://139.180.147.61.sslip.io/healthz> |
| 10-slide deck | [`docs/DECK.pdf`](DECK.pdf) |
| Deck outline and sources | [`docs/DECK.md`](DECK.md) |
| 16:9 cover | [`docs/cover.png`](cover.png) |
| Demo screenshots | [`docs/run.png`](run.png), [`docs/ui.png`](ui.png) |
| Verification evidence | [`docs/EVIDENCE.md`](EVIDENCE.md) |
| Attestation JSON | [`docs/attestation.example.json`](attestation.example.json) |

## Judge quick path

1. Open the live URL; `/healthz` should report `docker: true`, provider `vultr`
   and model `deepseek-v4.1-flash-1017`.
2. Tab **1. Run task** → **Run agent**; read the model-written code and the real
   stdout.
3. Tab **2. Measure blast radius** → **Re-measure containment**; watch
   `rm_rf` contained, the host canary intact and `blast radius = 0`.
4. Tab **4. Attestation** → **Measure now and write attestation**; download the
   JSON record.
