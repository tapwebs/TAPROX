"""Domain-name analysis for the DNS rules (Phase 4 / M4). Pure: no clock, no network, no database.

Names come from the network and are untrusted. Nothing here raises on any string: a name is lowercased, stripped of
trailing dots and bounded, and the result says whether it is a well-formed DNS name. The *original* text is kept by the
caller (the telemetry event) as inert text; this module only builds the separate form used for analysis.

The parent ("registrable") domain comes from the bundled Public Suffix List (`app/data/public_suffix_list.dat`, MPL-2.0;
source, date and hash in `app/data/README.md`). The list is read from disk once. If the file is missing or unreadable the
last two labels are used instead and `parent_domain` says so, so a finding can state that the list was not available.
There is no network access, ever.
"""

import math
from collections import Counter
from dataclasses import dataclass
from functools import cache
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "public_suffix_list.dat"

MAX_NAME_TEXT = (
    512  # characters kept of any name; DNS allows 253, so a longer one is already invalid
)
MAX_LABELS = 128
MAX_LABEL = 63
MAX_NAME = 253

_SERVICE_LABELS = frozenset({"_tcp", "_udp"})
_NON_ANALYSIS_TLDS = frozenset({"local", "arpa"})


@dataclass(frozen=True, slots=True)
class DnsName:
    text: str  # lowercase, no trailing dot, at most MAX_NAME_TEXT characters
    labels: tuple[str, ...]  # at most MAX_LABELS
    valid: bool  # a well-formed DNS name: no empty label, no label over 63, no more than 253 characters


def normalize(raw: str) -> DnsName:
    """The analysis form of a name. Never raises; hostile input gives `valid=False` and bounded text."""
    text = raw.lower().rstrip(".")
    oversize = len(text) > MAX_NAME_TEXT
    if oversize:
        text = text[:MAX_NAME_TEXT]
    if not text:
        return DnsName("", (), False)
    parts = text.split(".")
    labels = tuple(parts[:MAX_LABELS])
    valid = (
        not oversize
        and len(parts) <= MAX_LABELS
        and len(text) <= MAX_NAME
        and all(0 < len(label) <= MAX_LABEL for label in parts)
    )
    return DnsName(text, labels, valid)


def shannon_entropy(text: str) -> float:
    """Bits per character of the characters in `text` (0.0 for an empty or single-symbol string)."""
    if not text:
        return 0.0
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in Counter(text).values()) + 0.0


def is_service_discovery(name: DnsName) -> bool:
    """`.local`, reverse (`.arpa`) and `_tcp` / `_udp` service names: not ordinary host names to analyse."""
    labels = name.labels
    return bool(labels) and (
        labels[-1] in _NON_ANALYSIS_TLDS or any(label in _SERVICE_LABELS for label in labels)
    )


class SuffixList:
    """Public Suffix List rules: exact, wildcard (`*.x`) and exception (`!x`)."""

    def __init__(
        self,
        exact: frozenset[str],
        wildcard: frozenset[str],
        exception: frozenset[str],
        available: bool,
    ) -> None:
        self._exact, self._wild, self._exc = exact, wildcard, exception
        self.available = available
        self.rule_count = len(exact) + len(wildcard) + len(exception)

    @classmethod
    def empty(cls) -> "SuffixList":
        return cls(frozenset(), frozenset(), frozenset(), False)

    @classmethod
    def from_text(cls, text: str) -> "SuffixList":
        exact: set[str] = set()
        wild: set[str] = set()
        exc: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()  # a rule ends at the first whitespace
            kind = exc if rule.startswith("!") else wild if rule.startswith("*.") else exact
            rule = rule[1:] if rule.startswith("!") else rule[2:] if rule.startswith("*.") else rule
            try:
                rule = rule.encode("idna").decode(
                    "ascii"
                )  # the list holds Unicode; DNS carries punycode
            except UnicodeError:
                continue  # one bad line never stops the loader
            if rule:
                kind.add(rule)
        return cls(frozenset(exact), frozenset(wild), frozenset(exc), True)

    @classmethod
    def load(cls, path: Path) -> "SuffixList":
        try:
            return cls.from_text(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            return cls.empty()

    def parent(self, name: DnsName) -> tuple[str, bool]:
        """(registrable domain, True) from the list; (last two labels, False) when the list is not available."""
        labels = name.labels
        n = len(labels)
        if n <= 1:
            return name.text, self.available
        if not self.available:
            return ".".join(labels[-2:]), False
        suffix_len = 1  # the default rule: an unknown TLD is itself a suffix
        best = 0
        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self._exc:
                suffix_len, best = n - i - 1, -1  # an exception rule wins over every other rule
                break
            if not best and (candidate in self._exact or ".".join(labels[i + 1 :]) in self._wild):
                best = n - i
        if best > 0:
            suffix_len = best
        if n <= suffix_len:
            return name.text, True  # the name is itself a public suffix
        return ".".join(labels[-(suffix_len + 1) :]), True


@cache
def default_suffixes() -> SuffixList:
    return SuffixList.load(DATA_FILE)


def parent_domain(name: DnsName) -> tuple[str, bool]:
    return default_suffixes().parent(name)
