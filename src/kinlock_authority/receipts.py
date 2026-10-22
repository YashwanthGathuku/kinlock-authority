"""Append-only, hash-chained receipts.

Each line is one JSON receipt whose hash covers the previous receipt's hash.
Editing, dropping or reordering any past receipt breaks the chain, and
`verify()` says where.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .canonical import digest

GENESIS = "0" * 64


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Receipt:
    seq: int
    ts: str
    kind: str
    data: dict[str, Any]
    prev: str
    hash: str

    def body(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "kind": self.kind, "data": self.data, "prev": self.prev}


@dataclass
class ChainReport:
    ok: bool
    receipts: int
    head: str
    broken_at: int | None = None
    reason: str | None = None


@dataclass
class ReceiptChain:
    path: Path
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def receipts(self) -> Iterator[Receipt]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield Receipt(**json.loads(line))

    def verify(self) -> ChainReport:
        prev, n = GENESIS, 0
        try:
            for n, r in enumerate(self.receipts(), start=1):
                if r.seq != n - 1:
                    return ChainReport(False, n, prev, r.seq, f"sequence gap: expected {n - 1}, found {r.seq}")
                if r.prev != prev:
                    return ChainReport(False, n, prev, r.seq, "prev hash does not match the receipt before it")
                if digest(r.body()) != r.hash:
                    return ChainReport(False, n, prev, r.seq, "receipt content does not match its hash")
                prev = r.hash
        except (json.JSONDecodeError, TypeError) as e:
            return ChainReport(False, n, prev, n, f"unreadable receipt: {e}")
        return ChainReport(True, n, prev)

    def append(self, kind: str, data: dict[str, Any], ts: str | None = None) -> Receipt:
        with self._lock:
            last: Receipt | None = None
            for last in self.receipts():
                pass
            seq = 0 if last is None else last.seq + 1
            prev = GENESIS if last is None else last.hash
            body = {"seq": seq, "ts": ts or utc_now_iso(), "kind": kind, "data": data, "prev": prev}
            r = Receipt(**body, hash=digest(body))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps({**body, "hash": r.hash}, ensure_ascii=False) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return r
