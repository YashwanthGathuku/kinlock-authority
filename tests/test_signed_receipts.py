"""Signed receipt chains: a fully recomputed chain no longer verifies."""

from __future__ import annotations

import json

import pytest

from kinlock_authority import ReceiptChain
from kinlock_authority.canonical import digest
from kinlock_authority.receipts import GENESIS

KEY = b"r" * 32


def _fill(chain: ReceiptChain, n: int = 4) -> None:
    for i in range(n):
        chain.append("executed", {"request_id": f"r{i}", "amount_cents": 1000 + i}, ts=f"2026-10-22T14:00:0{i}.000Z")


def _recompute(path, edit) -> None:
    """What an attacker with write access does: edit a receipt, then redo every hash after it."""
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    edit(rows)
    prev = GENESIS
    for r in rows:
        r["prev"] = prev
        body = {k: r[k] for k in ("seq", "ts", "kind", "data", "prev")}
        r["hash"] = digest(body)
        prev = r["hash"]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_signed_chain_verifies_and_carries_signatures(tmp_path):
    chain = ReceiptChain(tmp_path / "r.jsonl", key=KEY)
    _fill(chain)
    rep = chain.verify()
    assert rep.ok and rep.receipts == 4
    assert all(len(r.sig) == 64 for r in chain.receipts())


def test_fully_recomputed_chain_passes_unsigned_check_but_fails_signed(tmp_path):
    path = tmp_path / "r.jsonl"
    _fill(ReceiptChain(path, key=KEY))

    def edit(rows):
        rows[1]["data"]["amount_cents"] = 999999

    _recompute(path, edit)
    assert ReceiptChain(path).verify().ok  # hashes alone can't tell
    rep = ReceiptChain(path, key=KEY).verify()
    assert not rep.ok and rep.broken_at == 1 and "signature" in rep.reason


def test_recomputed_chain_with_signatures_stripped_is_rejected(tmp_path):
    path = tmp_path / "r.jsonl"
    _fill(ReceiptChain(path, key=KEY))

    def strip(rows):
        rows[2]["data"]["amount_cents"] = 1
        for r in rows:
            r.pop("sig", None)

    _recompute(path, strip)
    rep = ReceiptChain(path, key=KEY).verify()
    assert not rep.ok and rep.reason == "receipt is not signed"


def test_signature_from_a_different_key_is_rejected(tmp_path):
    path = tmp_path / "r.jsonl"
    _fill(ReceiptChain(path, key=b"x" * 32))
    assert not ReceiptChain(path, key=KEY).verify().ok


def test_unsigned_chain_still_works_without_a_key(tmp_path):
    chain = ReceiptChain(tmp_path / "r.jsonl")
    _fill(chain)
    assert chain.verify().ok
    assert "sig" not in json.loads((tmp_path / "r.jsonl").read_text().splitlines()[0])


def test_old_unsigned_lines_are_readable_but_fail_signed_verification(tmp_path):
    path = tmp_path / "r.jsonl"
    _fill(ReceiptChain(path))
    assert [r.sig for r in ReceiptChain(path, key=KEY).receipts()] == [""] * 4
    assert not ReceiptChain(path, key=KEY).verify().ok


def test_short_key_is_refused(tmp_path):
    with pytest.raises(ValueError):
        ReceiptChain(tmp_path / "r.jsonl", key=b"short")
