"""Attestation — the sellable artifact.

The measurement is the demo. The attestation is the product: a signed-by-
evidence record per run that a security team can attach to a release ticket
and hand to an auditor, instead of "our agent is sandboxed, trust us".

What it deliberately does not do: claim a grade it did not measure. If an
axis came back UNVERIFIED, the attestation says so, and the verdict stays
PARTIALLY UNVERIFIED no matter how nice the rest looks.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

import vultr_inference
from blast_radius import AXES, run_probes
from sandbox import docker_available

SCHEMA = "blast-radius/attestation@1"


def _on_vultr() -> bool:
    """Never claim Vultr just because the app is running. An attestation that
    asserts a host it did not verify is the same lie the project exists to stop.

    Vultr VMs expose their vendor via DMI; an explicit BLAST_RADIUS_BACKEND=vultr
    is accepted for environments where DMI is unavailable.
    """
    if os.environ.get("BLAST_RADIUS_BACKEND", "").strip().lower() == "vultr":
        return True
    try:
        with open("/sys/class/dmi/id/sys_vendor", encoding="utf-8") as fh:
            return "vultr" in fh.read().lower()
    except OSError:
        return False


def build_attestation(*, task: str | None = None,
                      runtimes: tuple[str, ...] | None = None,
                      timeout: float = 15.0) -> dict:
    """Run a fresh probe suite and build the attestation record.

    This always measures now; it never reuses a previous run's numbers. That is
    deliberate: an attestation must describe the machine state at issue time.
    `task` is recorded as context only (it is not executed here).
    """
    runtimes = runtimes or (("container",) if docker_available() else ("rlimits",))
    br = run_probes(runtimes=runtimes, timeout=timeout)

    axes = {}
    for axis in AXES:
        v = br["axes"][axis]
        axes[axis] = {
            "verdict": v["verdict"],
            "probes_measured": f"{v['measured']}/{v['probes']}",
            # only list the evidence for axes that were actually measured
            "evidence": [p["detail"] for p in br["probes"]
                         if p["axis"] == axis and p.get("measured")],
        }

    graded = all(br["axes"][a]["verdict"] == "CONTAINED" for a in AXES)
    return {
        "schema": SCHEMA,
        "issued_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "task": task,
        "sandbox_runtime": br["runtimes"],
        "degraded_runtime": br["degraded"],
        "blast_radius": br["blast_radius"],
        "verdict": br["verdict"],
        "axes": axes,
        "host_canary_intact": br["canary_intact"],
        "measured_under": {
            "vultr_vm_backend": _on_vultr(),
            "llm_provider": vultr_inference.provider(),
            "llm_endpoint": vultr_inference.base_url(),
            "sandbox_boundary": br["runtimes"] == ["container"],
        },
        "executive_summary": (
            "Blast Radius Zero: no probe reached the host across all four axes."
            if graded and br["blast_radius"] == 0 else
            f"{br['verdict']} — {br['blast_radius']} probe(s) breached containment."
        ),
    }


def to_json(att: dict) -> str:
    return json.dumps(att, indent=2, ensure_ascii=False)


def write_attestation(att: dict, outdir: str | None = None) -> str:
    """Write the attestation to disk and return the path."""
    outdir = outdir or os.environ.get("BLAST_RADIUS_OUTDIR") or tempfile.gettempdir()
    os.makedirs(outdir, exist_ok=True)
    stamp = att["issued_at"].replace(":", "").replace("-", "")
    name = f"attestation-{stamp}-br{att['blast_radius']}.json"
    path = os.path.join(outdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_json(att))
    return path


def format_summary(att: dict) -> str:
    lines = ["=" * 72, "ATTESTATION — BLAST RADIUS", "=" * 72,
             f"issued : {att['issued_at']}",
             f"runtime: {', '.join(att['sandbox_runtime'])}"
             + ("   [DEGRADED]" if att["degraded_runtime"] else ""),
             f"canary : {'intact' if att['host_canary_intact'] else 'REACHED'}",
             f"verdict: {att['verdict']}  (blast radius = {att['blast_radius']})", ""]
    for axis, v in att["axes"].items():
        lines.append(f"  {axis:24} {v['verdict']:10} {v['probes_measured']}")
        for ev in v["evidence"]:
            lines.append(f"      - {ev}")
    lines += ["", att["executive_summary"]]
    return "\n".join(lines)
