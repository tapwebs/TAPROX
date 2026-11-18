"""Grouping findings that concern the same entity close together in time. Pure and bounded."""

from collections import OrderedDict
from dataclasses import dataclass, field

WINDOW_SECONDS = 600.0  # ten minutes of packet time
MAX_ENTITIES = 5_000


@dataclass(slots=True)
class _Group:
    group_id: str
    last_t: float
    rules: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class Correlation:
    group_id: str
    other_rules: int  # distinct rules in the group besides this finding's own


class CorrelationIndex:
    def __init__(
        self, prefix: str, *, window: float = WINDOW_SECONDS, max_entities: int = MAX_ENTITIES
    ) -> None:
        self._prefix = prefix
        self._window = window
        self._max = max_entities
        self._groups: OrderedDict[str, _Group] = OrderedDict()
        self._next = 1

    def observe(self, entity_key: str, rule_id: str, t: float) -> Correlation:
        """Corroboration counts distinct *rules* (M3 decision): a sweep and a scan are both reconnaissance."""
        group = self._groups.get(entity_key)
        if group is None or t - group.last_t > self._window:
            group = _Group(f"{self._prefix}-g{self._next}", t)
            self._next += 1
        group.rules.add(rule_id)
        group.last_t = max(group.last_t, t)
        self._groups[entity_key] = group
        self._groups.move_to_end(entity_key)
        while len(self._groups) > self._max:
            self._groups.popitem(last=False)
        return Correlation(group.group_id, len(group.rules - {rule_id}))
