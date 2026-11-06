# BLAST RADIUS — 10-slide deck

Live: <https://139.180.147.61.sslip.io/>  
PDF: [`docs/DECK.pdf`](DECK.pdf)  
Cover: [`docs/cover.png`](cover.png)

1. **Title** — BLAST RADIUS; an agent that runs untrusted code, measured by what
   it cannot escape. Team arabeacon, 6 Nov 2026.
2. **Problem** — agents run code; nobody measures the box. June 2026 study
   (arXiv 2606.24496) found key exfiltration even inside sandboxed containers.
   Teams get a claim, not a score or an audit trail.
3. **Solution** — a blast radius score with receipts: 7 probes, 4 axes, a
   host-side canary, and a JSON attestation. No Docker means DEGRADED, never
   "contained".
4. **Live demo** — public URL and the three-step golden path; screenshot of the
   live containment screen.
5. **How it works** — task → Vultr Serverless Inference → disposable container →
   probes → score; self-healing from real stderr.
6. **Evidence** — 44/44 tests, real model call, stdout `11.67`, all four axes
   CONTAINED, canary intact, blast radius 0.
7. **Why Vultr** — the VM is the execution host, Serverless Inference writes and
   repairs the code, the container is the boundary. All three are load-bearing.
8. **Market** — AI systems security ~$8B by 2030 (Dell'Oro Group, 2026). Buyers:
   platform teams, AppSec, compliance. Bottom-up SAM: 10k teams × $10k/yr =
   $100M (assumption to validate).
9. **Business model** — open-source wedge; $99/workspace/month SaaS; $0.01/run
   metered attestation API; GitHub Action → Vultr Marketplace → platform
   partnerships.
10. **Team, roadmap, ask** — Team arabeacon; hosted attestation API, GitHub
    Action, policy packs for LangGraph/CrewAI; ask for Vultr credits, design
    partners and a security review.

## Sources

- arXiv 2606.24496, agentic tool sandbox escape / key exfiltration study (June
  2026).
- Dell'Oro Group, *AI Systems Security* market forecast, 2026 (~$8B by 2030).
- Vultr Serverless Inference: <https://api.vultrinference.com/v1>.
- Repo evidence: [`docs/EVIDENCE.md`](EVIDENCE.md) and
  [`docs/attestation.example.json`](attestation.example.json).
