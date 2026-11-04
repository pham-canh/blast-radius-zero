"""Smoke test — keeps CI honest. Always green in a working tree."""
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
SRC_MAIN = SRC_DIR / "main.py"


def test_no_stub_template():
    txt = SRC_MAIN.read_text(encoding="utf-8") if SRC_MAIN.exists() else ""
    assert "TODO: wire sponsor API" not in txt, "src/main.py still contains the starter stub"
    assert "[MVP] returns:" not in txt, "src/main.py still returns a stub — replace it with real logic"


def test_entrypoint_runs():
    """The core loop must produce a non-empty report from a clean import."""
    sys.path.insert(0, str(SRC_DIR))
    from main import build as _build

    out = _build("smoke input")
    assert isinstance(out, str) and out.strip()
