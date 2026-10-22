"""kinlock-authority: deterministic authority for actions an AI assistant asks to take.

The assistant turns speech into a structured action. This library decides
whether that action may run. It never asks a model.

Three ideas carry it:

* Authority direction. Every action either lowers authority (freeze, cancel,
  lower a limit), raises it (unfreeze, raise a limit, add a contact) or spends.
  A low-assurance channel such as voice may lower authority freely and may
  never raise it.
* Exact-action approvals. A trusted person approves one action. The approval
  is an HMAC-signed capability bound to that action's digest, single-use,
  expiring, and capped at the approver's ceiling. The rules run again before
  the action does.
* Receipts. Every decision is appended to a hash-chained log that anyone can
  re-verify.
"""

from .approvals import Capability, Signer, capability_problems, issue_capability
from .policy import (
    Action,
    Check,
    Contact,
    Decision,
    History,
    Limits,
    Outcome,
    Policy,
    authority_direction,
    evaluate,
    may_approve,
)
from .receipts import ChainReport, Receipt, ReceiptChain

__all__ = [
    "Action",
    "Capability",
    "ChainReport",
    "Check",
    "Contact",
    "Decision",
    "History",
    "Limits",
    "Outcome",
    "Policy",
    "Receipt",
    "ReceiptChain",
    "Signer",
    "authority_direction",
    "capability_problems",
    "evaluate",
    "issue_capability",
    "may_approve",
]
__version__ = "0.1.0"
