"""Run history must survive a restart without becoming a failure mode."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import history  # noqa: E402


def test_history_survives_restart(tmp_path):
    path = tmp_path / "out" / "history.jsonl"
    first = history.RunHistory(path)
    first.append({"task": "a", "blast_radius": 0, "verdict": "BLAST RADIUS ZERO"})
    first.append({"task": "b", "blast_radius": 2, "verdict": "BLAST RADIUS > 0"})

    reloaded = history.RunHistory(path)
    assert [r["task"] for r in reloaded.recent()] == ["a", "b"]
    assert all("at" in r for r in reloaded.recent())


def test_history_is_capped(tmp_path):
    path = tmp_path / "history.jsonl"
    run_history = history.RunHistory(path, limit=3)
    for i in range(6):
        run_history.append({"task": str(i)})
    assert len(run_history) == 3
    assert [r["task"] for r in run_history.recent()] == ["3", "4", "5"]
    assert len(history.RunHistory(path).recent()) == 3


def test_history_ignores_bad_lines(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text('{"task": "ok"}\nnot-json\n{"task": "also ok"}\n', encoding="utf-8")
    assert [r["task"] for r in history.RunHistory(path).recent()] == ["ok", "also ok"]


def test_history_write_failure_never_raises(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    run_history = history.RunHistory(blocker / "history.jsonl")
    run_history.append({"task": "still works"})
    assert run_history.recent()[-1]["task"] == "still works"
