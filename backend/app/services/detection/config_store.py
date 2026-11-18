"""Everything the user configures or the engine remembers between runs, in SQLite (Phase 4 / M5, M6, M9).

Rule settings, suppressions, device annotations, network profiles (gateway MAC memory, baseline readiness) and device
baselines. Each operation opens its own short session; a failure here never reaches the capture threads (the detection
service catches it and runs with defaults, saying so in the run's warnings).
"""

import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, delete, func, select
from sqlalchemy.orm import Session

from app.models.alert import AlertRow
from app.models.app_meta import AppMeta
from app.models.detection import (
    DetectionRuleChange,
    DetectionRuleSetting,
    DeviceAnnotation,
    DeviceBaseline,
    NetworkProfile,
    Suppression,
)
from app.models.device import Device, DeviceAddress
from app.services.detection import baseline as bl
from app.services.detection.registry import Registry, RuleConfigError, RuleSettings

ROLES = ("gateway", "dns_server", "server", "printer", "iot", "workstation", "unspecified")
TRUSTS = ("unreviewed", "known", "ignored")
CHANGES_KEPT = 1_000
SUPPRESSIONS_MAX = 5_000
NOTE_MAX = 300

# Settings kept in app_meta, with their bounds. Everything here is validated on write and on read.
SETTINGS: dict[str, tuple[float, float, float]] = {  # key -> (default, minimum, maximum)
    "retention.alert_days": (180, 7, 3650),
    "retention.alert_max": (5000, 100, 100000),
    "baseline.hours_min": (bl.DEFAULT_HOURS_MIN, 0.0, 720.0),
    "baseline.sessions_min": (bl.DEFAULT_SESSIONS_MIN, 1, 100),
    "risk.half_life_days": (7, 1, 90),
}

_UNSET: Any = object()


def utcnow() -> datetime:
    return datetime.now(UTC)


class NotFound(LookupError):
    """The rule, device, suppression or network asked for does not exist."""


class Invalid(ValueError):
    """A value outside what the setting accepts."""


@dataclass(frozen=True, slots=True)
class RuleRow:
    enabled: bool | None
    overrides: dict[str, int | float]
    updated_at: datetime


def network_key(networks: Iterable[str], gateways: Iterable[str]) -> str | None:
    """`<cidr>|<gateway>` for the first network and gateway of a vantage, or None when there is no network."""
    nets, gws = list(networks), list(gateways)
    if not nets:
        return None
    return f"{nets[0]}|{gws[0] if gws else ''}"[:64]


class ConfigStore:
    def __init__(self, engine: Engine, *, clock: Any = utcnow) -> None:
        self._engine = engine
        self.engine = engine
        self._clock = clock

    # --- rules ---------------------------------------------------------------------------------------------------
    def rule_rows(self) -> dict[str, RuleRow]:
        with Session(self._engine) as db:
            out: dict[str, RuleRow] = {}
            for row in db.scalars(select(DetectionRuleSetting)):
                try:
                    raw = json.loads(row.params_json or "{}")
                except ValueError:
                    raw = {}
                overrides = (
                    {
                        k: v
                        for k, v in raw.items()
                        if isinstance(v, (int, float)) and not isinstance(v, bool)
                    }
                    if isinstance(raw, dict)
                    else {}
                )
                out[row.rule_id] = RuleRow(row.enabled, overrides, row.updated_at)
            return out

    def load_settings(self, registry: Registry) -> RuleSettings:
        """The saved settings as the engine wants them. A stored value that no longer validates is ignored."""
        enabled: dict[str, bool] = {}
        overrides: dict[str, dict[str, object]] = {}
        for rule_id, row in self.rule_rows().items():
            try:
                registry.get(rule_id)
            except RuleConfigError:
                continue
            if row.enabled is not None:
                enabled[rule_id] = row.enabled
            try:
                registry.validate(rule_id, row.overrides)
                overrides[rule_id] = dict(row.overrides)
            except RuleConfigError:
                continue
        return RuleSettings(enabled=enabled, overrides=overrides)

    def put_rule(
        self,
        registry: Registry,
        rule_id: str,
        *,
        enabled: Any = _UNSET,
        params: Mapping[str, object] | None = None,
    ) -> RuleRow:
        """Change a rule's switch and/or parameters (validated against their bounds). The next run uses them."""
        try:
            registry.get(rule_id)
        except RuleConfigError:
            raise NotFound(f"There is no rule {rule_id!r}.") from None
        if params is not None:
            registry.validate(rule_id, params)  # RuleConfigError (a ValueError) when out of bounds
        now = self._clock()
        with Session(self._engine) as db:
            row = db.get(DetectionRuleSetting, rule_id)
            old = {
                "enabled": row.enabled if row else None,
                "params": json.loads(row.params_json) if row else {},
            }
            if row is None:
                row = DetectionRuleSetting(
                    rule_id=rule_id, enabled=None, params_json="{}", updated_at=now
                )
                db.add(row)
            if enabled is not _UNSET:
                row.enabled = enabled
            if params is not None:
                row.params_json = json.dumps({k: params[k] for k in sorted(params)})
            row.updated_at = now
            new = {"enabled": row.enabled, "params": json.loads(row.params_json)}
            kind = "params" if params is not None else ("enable" if row.enabled else "disable")
            db.add(
                DetectionRuleChange(
                    rule_id=rule_id,
                    at=now,
                    kind=kind,
                    old_json=json.dumps(old),
                    new_json=json.dumps(new),
                )
            )
            self._trim_changes(db, rule_id)
            db.commit()
            return RuleRow(row.enabled, dict(new["params"]), now)

    def reset_rule(self, registry: Registry, rule_id: str) -> None:
        try:
            registry.get(rule_id)
        except RuleConfigError:
            raise NotFound(f"There is no rule {rule_id!r}.") from None
        now = self._clock()
        with Session(self._engine) as db:
            row = db.get(DetectionRuleSetting, rule_id)
            old = {"enabled": row.enabled, "params": json.loads(row.params_json)} if row else {}
            if row is not None:
                db.delete(row)
            db.add(
                DetectionRuleChange(
                    rule_id=rule_id, at=now, kind="reset", old_json=json.dumps(old), new_json="{}"
                )
            )
            self._trim_changes(db, rule_id)
            db.commit()

    @staticmethod
    def _trim_changes(db: Session, rule_id: str) -> None:
        ids = list(
            db.scalars(
                select(DetectionRuleChange.id)
                .where(DetectionRuleChange.rule_id == rule_id)
                .order_by(DetectionRuleChange.id.desc())
                .offset(CHANGES_KEPT)
            )
        )
        if ids:
            db.execute(delete(DetectionRuleChange).where(DetectionRuleChange.id.in_(ids)))

    def rule_changes(self, rule_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with Session(self._engine) as db:
            rows = db.scalars(
                select(DetectionRuleChange)
                .where(DetectionRuleChange.rule_id == rule_id)
                .order_by(DetectionRuleChange.id.desc())
                .limit(limit)
            )
            return [
                {
                    "at": r.at,
                    "kind": r.kind,
                    "old": json.loads(r.old_json or "{}"),
                    "new": json.loads(r.new_json or "{}"),
                }
                for r in rows
            ]

    # --- suppressions --------------------------------------------------------------------------------------------
    def list_suppressions(self) -> list[Suppression]:
        now = self._clock()
        with Session(self._engine) as db:
            rows = db.scalars(select(Suppression).order_by(Suppression.id.desc()))
            return [r for r in rows if r.expires_at is None or r.expires_at > now]

    def put_suppression(
        self,
        registry: Registry,
        rule_id: str,
        kind: str,
        key: str,
        reason: str,
        expires_at: datetime | None,
    ) -> Suppression:
        try:
            registry.get(rule_id)
        except RuleConfigError:
            raise NotFound(f"There is no rule {rule_id!r}.") from None
        if (
            not key.strip()
            or len(key) > 80
            or not reason.strip()
            or len(reason) > 300
            or kind not in ("ip", "mac", "device", "domain", "network")
        ):
            raise Invalid(
                "A suppression needs a kind, a key of at most 80 characters and a reason of at most 300."
            )
        now = self._clock()
        if expires_at is not None and expires_at <= now:
            raise Invalid("The expiry must be in the future.")
        with Session(self._engine) as db:
            row = db.scalars(
                select(Suppression).where(
                    Suppression.rule_id == rule_id,
                    Suppression.entity_kind == kind,
                    Suppression.entity_key == key,
                )
            ).first()
            if row is None:
                if (
                    db.scalar(select(func.count()).select_from(Suppression)) or 0
                ) >= SUPPRESSIONS_MAX:
                    raise Invalid("Too many suppressions; remove some first.")
                row = Suppression(
                    rule_id=rule_id,
                    entity_kind=kind,
                    entity_key=key,
                    reason=reason,
                    created_at=now,
                    expires_at=expires_at,
                )
                db.add(row)
            else:
                row.reason, row.expires_at = reason, expires_at
            db.commit()
            db.refresh(row)
            return row

    def delete_suppression(self, suppression_id: int) -> None:
        with Session(self._engine) as db:
            row = db.get(Suppression, suppression_id)
            if row is None:
                raise NotFound("There is no such suppression.")
            db.delete(row)
            db.commit()

    def active_suppressions(self) -> frozenset[tuple[str, str, str]]:
        return frozenset((s.rule_id, s.entity_kind, s.entity_key) for s in self.list_suppressions())

    # --- annotations and the inventory ---------------------------------------------------------------------------
    def annotation(self, device_id: int) -> DeviceAnnotation | None:
        with Session(self._engine) as db:
            return db.get(DeviceAnnotation, device_id)

    def put_annotation(
        self, device_id: int, role: str, trust: str, note: str | None
    ) -> DeviceAnnotation:
        if role not in ROLES or trust not in TRUSTS or (note is not None and len(note) > NOTE_MAX):
            raise Invalid("Unknown role or trust, or a note longer than 300 characters.")
        with Session(self._engine) as db:
            if db.get(Device, device_id) is None:
                raise NotFound("There is no such device.")
            row = db.get(DeviceAnnotation, device_id)
            if row is None:
                row = DeviceAnnotation(
                    device_id=device_id, role=role, trust=trust, note=note, updated_at=self._clock()
                )
                db.add(row)
            else:
                row.role, row.trust, row.note, row.updated_at = role, trust, note, self._clock()
            db.commit()
            db.refresh(row)
            return row

    def known_entities(self) -> frozenset[str]:
        """Addresses of devices the user marked known (the context factor lowers their alerts' score)."""
        with Session(self._engine) as db:
            ids = [
                r
                for r in db.scalars(
                    select(DeviceAnnotation.device_id).where(DeviceAnnotation.trust == "known")
                )
            ]
            if not ids:
                return frozenset()
            ips = db.scalars(select(DeviceAddress.ip).where(DeviceAddress.device_id.in_(ids)))
            return frozenset(ips)

    def inventory_macs(self) -> frozenset[str]:
        with Session(self._engine) as db:
            return frozenset(m.lower() for m in db.scalars(select(Device.mac)))

    def inventory_ip_macs(self) -> dict[str, str]:
        """The current address of each inventory device with its hardware address (lower case). An address a device used earlier is not listed, so a reused DHCP lease is not a contradiction."""
        with Session(self._engine) as db:
            rows = db.execute(select(Device.last_ip, Device.mac).where(Device.last_ip.is_not(None)))
            return {ip: mac.lower() for ip, mac in rows if ip is not None}

    def ip_keys(self) -> dict[str, str]:
        """Inventory address -> device key (the device id as text), for baselines."""
        with Session(self._engine) as db:
            return {
                ip: str(did)
                for ip, did in db.execute(select(DeviceAddress.ip, DeviceAddress.device_id))
            }

    # --- settings in app_meta ------------------------------------------------------------------------------------
    def settings(self) -> dict[str, float]:
        with Session(self._engine) as db:
            stored = dict(
                db.execute(
                    select(AppMeta.key, AppMeta.value).where(AppMeta.key.in_(list(SETTINGS)))
                ).all()
            )
        out: dict[str, float] = {}
        for key, (default, lo, hi) in SETTINGS.items():
            try:
                value = float(stored[key])
                out[key] = value if math.isfinite(value) and lo <= value <= hi else default
            except (KeyError, ValueError):
                out[key] = default
        return out

    def put_settings(self, values: Mapping[str, float]) -> dict[str, float]:
        for key, value in values.items():
            if key not in SETTINGS:
                raise Invalid(f"Unknown setting {key!r}.")
            _, lo, hi = SETTINGS[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not lo <= value <= hi
            ):
                raise Invalid(f"{key} must be a number between {lo:g} and {hi:g}.")
        with Session(self._engine) as db:
            for key, value in values.items():
                row = db.get(AppMeta, key)
                text = f"{value:g}"
                if row is None:
                    db.add(AppMeta(key=key, value=text))
                else:
                    row.value = text
            db.commit()
        return self.settings()

    # --- networks and baselines ----------------------------------------------------------------------------------
    def networks(self) -> list[dict[str, Any]]:
        cfg = self.settings()
        with Session(self._engine) as db:
            out = []
            for n in db.scalars(
                select(NetworkProfile).order_by(NetworkProfile.last_seen_at.desc())
            ):
                devices = (
                    db.scalar(
                        select(func.count())
                        .select_from(DeviceBaseline)
                        .where(DeviceBaseline.network_id == n.id)
                    )
                    or 0
                )
                out.append(
                    {
                        "id": n.id, "network_key": n.network_key, "cidr": n.cidr, "gateway_ip": n.gateway_ip,
                        "gateway_mac": n.gateway_mac, "live_seconds": n.live_seconds, "sessions": n.sessions,
                        "first_seen_at": n.first_seen_at, "last_seen_at": n.last_seen_at,
                        "baseline_ready": bl.is_ready(n.live_seconds, n.sessions, cfg["baseline.hours_min"], int(cfg["baseline.sessions_min"])),
                        "baseline_ready_at": n.baseline_ready_at, "baseline_devices": devices,
                        "hours_needed": cfg["baseline.hours_min"], "sessions_needed": int(cfg["baseline.sessions_min"]),
                    }
                )  # fmt: skip
            return out

    def run_inputs(self, key: str | None) -> tuple[bl.BaselineView, str | None]:
        """The stored baseline view and the stored gateway MAC for a network, for a run about to start."""
        if key is None:
            return bl.BaselineView(), None
        cfg = self.settings()
        with Session(self._engine) as db:
            net = db.scalars(
                select(NetworkProfile).where(NetworkProfile.network_key == key)
            ).first()
            if net is None:
                return bl.BaselineView(), None
            devices: dict[str, bl.DeviceBaselineData] = {}
            for row in db.scalars(
                select(DeviceBaseline).where(DeviceBaseline.network_id == net.id)
            ):
                data = bl.DeviceBaselineData(
                    bl.loads_set(row.protocols_json, bl.SET_CAPS["protocols"]),
                    bl.loads_set(row.apps_json, bl.SET_CAPS["apps"]),
                    bl.loads_set(row.lan_peers_json, bl.SET_CAPS["lan_peers"]),
                    bl.loads_set(row.listen_ports_json, bl.SET_CAPS["listen_ports"]),
                    bl.loads_set(row.ext_peers_json, bl.SET_CAPS["ext_peers"]),
                    bl.loads_windows(row.windows_json),
                    row.median_out, row.mad_out, row.median_flows, row.mad_flows,
                )  # fmt: skip
                devices[row.device_key] = data
            ready = bl.is_ready(
                net.live_seconds,
                net.sessions,
                cfg["baseline.hours_min"],
                int(cfg["baseline.sessions_min"]),
            )
            age = (self._clock() - net.first_seen_at).total_seconds() / 86400.0
            ip_keys = {
                ip: str(did)
                for ip, did in db.execute(select(DeviceAddress.ip, DeviceAddress.device_id))
            }
            return bl.BaselineView(ready, max(0.0, age), devices, ip_keys), net.gateway_mac

    def record_run(
        self,
        key: str | None,
        cidr: str,
        gateway_ip: str | None,
        gateway_mac: str | None,
        live: bool,
        seconds: int,
        learned: Mapping[str, bl.DeviceBaselineData],
    ) -> dict[str, Any]:
        """At the end of a run. A live run adds its time and sessions and rewrites each learned device row once; a file
        run never touches a baseline. The gateway MAC is remembered either way only when it was seen in a live run."""
        if key is None or not live:
            return {"baseline_updated": False}
        now = self._clock()
        cfg = self.settings()
        with Session(self._engine) as db:
            net = db.scalars(
                select(NetworkProfile).where(NetworkProfile.network_key == key)
            ).first()
            if net is None:
                net = NetworkProfile(
                    network_key=key,
                    cidr=cidr[:43],
                    gateway_ip=gateway_ip,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(net)
                db.flush()
            net.live_seconds += max(0, seconds)
            net.sessions += 1
            net.last_seen_at = now
            if gateway_mac:
                net.gateway_mac, net.gateway_mac_at = gateway_mac, now
            if net.baseline_ready_at is None and bl.is_ready(
                net.live_seconds,
                net.sessions,
                cfg["baseline.hours_min"],
                int(cfg["baseline.sessions_min"]),
            ):
                net.baseline_ready_at = now
            written = 0
            existing = {
                r.device_key: r
                for r in db.scalars(
                    select(DeviceBaseline).where(DeviceBaseline.network_id == net.id)
                )
            }
            for device_key, run_data in learned.items():
                row = existing.get(device_key)
                stored = None
                if row is not None:
                    stored = bl.DeviceBaselineData(
                        bl.loads_set(row.protocols_json, 64), bl.loads_set(row.apps_json, 128), bl.loads_set(row.lan_peers_json, 512),
                        bl.loads_set(row.listen_ports_json, 128), bl.loads_set(row.ext_peers_json, 1024), bl.loads_windows(row.windows_json),
                    )  # fmt: skip
                merged = bl.merge(stored, run_data)
                if row is None:
                    row = DeviceBaseline(network_id=net.id, device_key=device_key, updated_at=now)
                    if device_key.isdigit():
                        row.device_id = int(device_key) if db.get(Device, int(device_key)) else None
                    db.add(row)
                row.protocols_json, row.apps_json = (
                    json.dumps(merged.protocols),
                    json.dumps(merged.apps),
                )
                row.lan_peers_json, row.listen_ports_json = (
                    json.dumps(merged.lan_peers),
                    json.dumps(merged.listen_ports),
                )
                row.ext_peers_json, row.windows_json = (
                    json.dumps(merged.ext_peers),
                    json.dumps([list(w) for w in merged.windows]),
                )
                row.windows_count = merged.windows_count
                row.median_out, row.mad_out, row.median_flows, row.mad_flows = (
                    merged.median_out,
                    merged.mad_out,
                    merged.median_flows,
                    merged.mad_flows,
                )
                row.updated_at = now
                written += 1
            cutoff = now - timedelta(days=90)
            db.execute(
                delete(DeviceBaseline).where(
                    DeviceBaseline.network_id == net.id, DeviceBaseline.updated_at < cutoff
                )
            )
            db.commit()
            return {
                "baseline_updated": True,
                "baseline_rows_written": written,
                "network_id": net.id,
            }

    def delete_baselines(self, network_id: int) -> int:
        """Reset one network: its learned devices and readiness (the gateway MAC memory is kept)."""
        with Session(self._engine) as db:
            net = db.get(NetworkProfile, network_id)
            if net is None:
                raise NotFound("There is no such network.")
            count = (
                db.scalar(
                    select(func.count())
                    .select_from(DeviceBaseline)
                    .where(DeviceBaseline.network_id == network_id)
                )
                or 0
            )
            db.execute(delete(DeviceBaseline).where(DeviceBaseline.network_id == network_id))
            net.live_seconds, net.sessions, net.baseline_ready_at = 0, 0, None
            db.commit()
            return count

    def delete_all(self) -> None:
        """Part of "delete all security history": baselines and readiness (profiles and gateway memory stay)."""
        with Session(self._engine) as db:
            db.execute(delete(DeviceBaseline))
            for net in db.scalars(select(NetworkProfile)):
                net.live_seconds, net.sessions, net.baseline_ready_at = 0, 0, None
            db.commit()

    # --- device risk ---------------------------------------------------------------------------------------------
    def device_risk(
        self, device_id: int | None = None, now: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Device risk profiles: 100 x (1 - product over alerts of (1 - s/100 x d)), d = 0.5 ^ (age_days / half_life)."""
        now = now or self._clock()
        half_life = self.settings()["risk.half_life_days"]
        with Session(self._engine) as db:
            q = select(AlertRow).where(AlertRow.entity_device_id.is_not(None))
            if device_id is not None:
                q = q.where(AlertRow.entity_device_id == device_id)
            alerts: dict[int, list[AlertRow]] = {}
            for a in db.scalars(q):
                alerts.setdefault(int(a.entity_device_id or 0), []).append(a)
            devices = (
                {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(list(alerts))))}
                if alerts
                else {}
            )
            notes = {a.device_id: a for a in db.scalars(select(DeviceAnnotation))}
        out = []
        for did, rows in sorted(alerts.items()):
            device = devices.get(did)
            if device is None:
                continue
            profile = device_risk_profile(rows, now, half_life)
            ann = notes.get(did)
            out.append(
                {
                    "device_id": did, "ip": device.last_ip, "mac": device.mac, "hostname": device.hostname,
                    "role": ann.role if ann else "unspecified", "trust": ann.trust if ann else "unreviewed",
                    "half_life_days": half_life, **profile,
                }
            )  # fmt: skip
        out.sort(key=lambda p: (-p["score"], p["device_id"]))
        return out


COUNTED = ("open", "acknowledged", "investigating", "resolved")


def device_risk_profile(
    alerts: Iterable[Any], now: datetime, half_life_days: float
) -> dict[str, Any]:
    """The documented formula. `false_positive` and `suppressed` count zero; each contribution is listed."""
    survive = 1.0
    parts = []
    for a in alerts:
        if a.status not in COUNTED:
            continue
        age_days = max(0.0, (now - a.updated_at).total_seconds() / 86400.0)
        decay = 0.5 ** (age_days / half_life_days)
        survive *= 1.0 - (a.risk_score / 100.0) * decay
        parts.append(
            {
                "alert_id": a.id,
                "rule_id": a.rule_id,
                "title": a.title,
                "status": a.status,
                "risk": a.risk_score,
                "decay": round(decay, 4),
            }
        )
    parts.sort(key=lambda p: (-p["risk"] * p["decay"], p["alert_id"]))
    return {
        "score": round(100 * (1 - survive)),
        "contributing": parts[:50],
        "alerts_counted": len(parts),
    }
