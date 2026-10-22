"""Exact-action approval capabilities.

When a trusted person approves a held action, the server issues a capability:
an HMAC-SHA256 signature over the action's digest, the request id, who
approved, their ceiling, a random nonce and an expiry. Executing the action
needs a capability that passes every check below. So an approval for $200 at
one shop cannot be replayed, stretched to $2,000, moved to another shop or
another request, or used after it expires.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

from .canonical import canonical


@dataclass(frozen=True)
class Capability:
    cap_id: str
    request_id: str
    action_digest: str
    approver: str  # e.g. "contact:anna" or "owner"
    role: str  # "contact" | "owner"
    ceiling_cents: int
    nonce: str
    issued_at: float
    expires_at: float
    sig: str = ""

    def payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("sig")
        return d

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Capability":
        return cls(**d)


class Signer:
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        self._key = key

    def sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._key, canonical(payload), sha256).hexdigest()

    def valid(self, cap: Capability) -> bool:
        return hmac.compare_digest(self.sign(cap.payload()), cap.sig)


def issue_capability(signer: Signer, *, request_id: str, action_digest: str, approver: str, role: str, ceiling_cents: int, now: float, ttl: float = 120.0) -> Capability:
    cap = Capability(
        cap_id="cap_" + secrets.token_hex(8),
        request_id=request_id,
        action_digest=action_digest,
        approver=approver,
        role=role,
        ceiling_cents=int(ceiling_cents),
        nonce=secrets.token_hex(16),
        issued_at=now,
        expires_at=now + ttl,
    )
    return Capability(**{**cap.payload(), "sig": signer.sign(cap.payload())})


def capability_problems(signer: Signer, cap: Capability, *, request_id: str, current_digest: str | None, amount_cents: int, used: set[str], now: float) -> list[str]:
    """Every reason this capability can't release this action. Empty = usable."""
    problems: list[str] = []
    if not signer.valid(cap):
        problems.append("The approval's signature is not valid")
    if cap.cap_id in used:
        problems.append("This approval was already used")
    if now > cap.expires_at:
        problems.append("This approval has expired")
    if cap.request_id != request_id:
        problems.append("This approval belongs to a different request")
    if current_digest is None:
        problems.append("That request is no longer waiting")
    elif not hmac.compare_digest(cap.action_digest, current_digest):
        problems.append("The request changed after it was approved")
    if amount_cents > cap.ceiling_cents:
        problems.append("The amount is over what the approver may allow")
    return problems
