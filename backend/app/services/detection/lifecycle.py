"""Alert states and the user transitions between them (PHASE4_ARCHITECTURE.md section 8).

The one automatic path (a `resolved` alert whose key fires again becomes `open`) lives in the store, not here:
this table is only what a person may ask for.
"""

from typing import Final

STATUSES: Final = (
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "false_positive",
    "suppressed",
)
ACTIVE: Final = ("open", "acknowledged", "investigating")
CLOSED: Final = ("resolved", "false_positive", "suppressed")

_FROM_ACTIVE = {"open", "acknowledged", "investigating", "resolved", "false_positive", "suppressed"}
_USER: Final[dict[str, frozenset[str]]] = {
    **{state: frozenset(_FROM_ACTIVE - {state}) for state in ACTIVE},
    **{
        state: frozenset({"open"}) for state in CLOSED
    },  # reopen; "suppressed" -> "open" is unsuppress
}

# Retention removes closed alerts first, then acknowledged ones, and open or investigating ones last.
_PRUNE_PRIORITY: Final = {
    "resolved": 0, "false_positive": 0, "suppressed": 0, "acknowledged": 1, "open": 2, "investigating": 2,
}  # fmt: skip


class TransitionRefused(ValueError):
    """The requested status change is not in the table."""


def check_transition(old: str, new: str) -> None:
    if old not in _USER or new not in _USER:
        raise TransitionRefused(f"Unknown alert status: {old!r} to {new!r}.")
    if new not in _USER[old]:
        if old == new:
            raise TransitionRefused(f"The alert is already {old}.")
        raise TransitionRefused(f"An alert that is {old} cannot be changed to {new}.")


def prune_priority(status: str) -> int:
    return _PRUNE_PRIORITY.get(status, 2)
