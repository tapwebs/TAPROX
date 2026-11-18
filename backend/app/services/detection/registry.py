"""The catalogue of rules, their defaults, and validation of any change to a setting."""

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from app.services.detection.rules import baselined as bsl
from app.services.detection.rules import device as dev
from app.services.detection.rules.app import CLEARTEXT_META as APP_004
from app.services.detection.rules.app import ICMP_META as APP_003
from app.services.detection.rules.app import UNUSUAL_META as APP_002
from app.services.detection.rules.app import CleartextProtocol, IcmpExchange, UnusualPort
from app.services.detection.rules.base import Rule, RuleMeta
from app.services.detection.rules.dns import (
    LONG_NAMES_META as DNS_004,
)
from app.services.detection.rules.dns import (
    NXDOMAIN_META as DNS_002,
)
from app.services.detection.rules.dns import (
    QUERY_RATE_META as DNS_001,
)
from app.services.detection.rules.dns import (
    RESOLVER_META as DNS_006,
)
from app.services.detection.rules.dns import (
    UNIQUE_NAMES_META as DNS_003,
)
from app.services.detection.rules.dns import (
    UNUSUAL_TYPES_META as DNS_005,
)
from app.services.detection.rules.dns import (
    DnsQueryRate,
    LongNames,
    NxdomainRate,
    UnconfiguredResolver,
    UniqueNames,
    UnusualTypes,
)
from app.services.detection.rules.recon import ARP_META as REC_003
from app.services.detection.rules.recon import META as REC_001
from app.services.detection.rules.recon import REPEAT_META as REC_004
from app.services.detection.rules.recon import SEQUENCE_META as REC_005
from app.services.detection.rules.recon import SWEEP_META as REC_002
from app.services.detection.rules.recon import (
    ArpSweepPattern,
    HostSweepPattern,
    PortScanPattern,
    RepeatedAttempts,
    SequentialPorts,
)
from app.services.detection.rules.traffic import FAILURE_META as TRF_003
from app.services.detection.rules.traffic import REGULAR_META as TRF_006
from app.services.detection.rules.traffic import ConnectionFailureRate, RegularIntervals


class RuleConfigError(ValueError):
    """A rule setting that is unknown, of the wrong type, or outside its bounds."""


@dataclass(frozen=True, slots=True)
class RuleSpec:
    meta: RuleMeta
    factory: Callable[[Mapping[str, int | float]], Rule]


class Registry:
    def __init__(self, specs: Iterable[RuleSpec]) -> None:
        self._specs: dict[str, RuleSpec] = {}
        for spec in specs:
            if spec.meta.id in self._specs:
                raise ValueError(f"Rule {spec.meta.id} is registered twice.")
            self._specs[spec.meta.id] = spec

    def specs(self) -> list[RuleSpec]:
        return list(self._specs.values())

    def get(self, rule_id: str) -> RuleSpec:
        try:
            return self._specs[rule_id]
        except KeyError:
            raise RuleConfigError(f"There is no rule {rule_id!r}.") from None

    def defaults(self, rule_id: str) -> dict[str, int | float]:
        return {p.name: p.default for p in self.get(rule_id).meta.params}

    def validate(self, rule_id: str, overrides: Mapping[str, object]) -> dict[str, int | float]:
        """The full parameter set with `overrides` applied, or RuleConfigError. Nothing is coerced silently."""
        meta = self.get(rule_id).meta
        known = {p.name: p for p in meta.params}
        values = self.defaults(rule_id)
        for name, raw in overrides.items():
            spec = known.get(name)
            if spec is None:
                raise RuleConfigError(f"{rule_id} has no setting {name!r}.")
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise RuleConfigError(f"{name} must be a number.")
            if isinstance(raw, float) and not math.isfinite(raw):
                raise RuleConfigError(f"{name} must be a finite number.")
            if spec.kind == "int":
                if isinstance(raw, float) and not raw.is_integer():
                    raise RuleConfigError(f"{name} must be a whole number.")
                value: int | float = int(raw)
            else:
                value = float(raw)
            if not spec.minimum <= value <= spec.maximum:
                raise RuleConfigError(
                    f"{name} must be between {spec.minimum} and {spec.maximum} {spec.unit}; got {value}."
                )
            values[name] = value
        return values


@dataclass(frozen=True, slots=True)
class RuleSettings:
    """Which rules run and with what values. Built once per run; a change applies to the next run."""

    enabled: Mapping[str, bool] = field(default_factory=dict)  # absent = the rule's default
    overrides: Mapping[str, Mapping[str, object]] = field(default_factory=dict)

    def is_enabled(self, meta: RuleMeta) -> bool:
        return self.enabled.get(meta.id, meta.default_enabled)


def default_registry() -> Registry:
    return Registry(
        [
            RuleSpec(REC_001, PortScanPattern),
            RuleSpec(REC_002, HostSweepPattern),
            RuleSpec(REC_003, ArpSweepPattern),
            RuleSpec(REC_004, RepeatedAttempts),
            RuleSpec(REC_005, SequentialPorts),
            RuleSpec(TRF_003, ConnectionFailureRate),
            RuleSpec(TRF_006, RegularIntervals),
            RuleSpec(APP_002, UnusualPort),
            RuleSpec(APP_003, IcmpExchange),
            RuleSpec(APP_004, CleartextProtocol),
            RuleSpec(DNS_001, DnsQueryRate),
            RuleSpec(DNS_002, NxdomainRate),
            RuleSpec(DNS_003, UniqueNames),
            RuleSpec(DNS_004, LongNames),
            RuleSpec(DNS_005, UnusualTypes),
            RuleSpec(DNS_006, UnconfiguredResolver),
            RuleSpec(dev.NEW_DEVICE_META, dev.NewDeviceInInventory),
            RuleSpec(dev.UNKNOWN_MAC_META, dev.UnknownMac),
            RuleSpec(dev.SHARED_IP_META, dev.SharedIp),
            RuleSpec(dev.GATEWAY_MAC_META, dev.GatewayMacChanged),
            RuleSpec(bsl.VOLUME_META, bsl.OutboundVolume),
            RuleSpec(bsl.LARGE_TRANSFER_META, bsl.LargeTransfer),
            RuleSpec(bsl.FREQUENCY_META, bsl.ConnectionFrequency),
            RuleSpec(bsl.NEW_PROTOCOL_META, bsl.NewProtocol),
            RuleSpec(bsl.NEW_PEER_META, bsl.NewPeer),
            RuleSpec(bsl.NEW_LISTENER_META, bsl.NewListener),
            RuleSpec(bsl.NEW_APP_META, bsl.NewApplication),
        ]
    )
