"""The Python reference agrees with the committed conformance vectors (the Rust and Go sides check the same files)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "conformance"
sys.path.insert(0, str(ROOT))

from runner import resolve, run  # noqa: E402

FIXTURES = json.loads((ROOT / "vectors" / "fixtures.json").read_text(encoding="utf-8"))
SUITES = sorted(p for p in (ROOT / "vectors").glob("*.json") if p.name != "fixtures.json")


def test_every_suite_is_present_and_nonempty():
    names = {p.stem for p in SUITES}
    assert {"canonical", "evaluate", "evaluate_action", "tally", "capability_problems", "receipts_verify"} <= names
    assert sum(len(json.loads(p.read_text(encoding="utf-8"))["cases"]) for p in SUITES) > 5000


@pytest.mark.parametrize("path", SUITES, ids=lambda p: p.stem)
def test_python_matches_every_vector(path):
    suite = json.loads(path.read_text(encoding="utf-8"))
    failures = [c["name"] for c in suite["cases"] if run(suite["op"], resolve(c["input"], FIXTURES)) != c["expected"]]
    assert not failures, f"{len(failures)} of {len(suite['cases'])} differ, first: {failures[:5]}"
