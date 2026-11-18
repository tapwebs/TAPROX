"""Rule configuration, suppressions, device annotations, baselines and device risk (Phase 4 M5, M6, M9)."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Any

from fastapi import APIRouter, Path, Request, Response
from sqlalchemy.exc import OperationalError

from app.core.errors import ApiProblem
from app.schemas import behaviour as schemas
from app.schemas.detection import DetectionParam
from app.services.detection.config_store import ConfigStore, Invalid, NotFound
from app.services.detection.registry import RuleConfigError
from app.services.detection.service import DetectionService

router = APIRouter(tags=["detection"])

RuleId = Annotated[
    str, Path(pattern=r"^TT-[A-Z]{3}-\d{3}$", description="Rule id, for example TT-REC-001.")
]


def _service(request: Request) -> DetectionService:
    service: DetectionService = request.app.state.detection
    return service


def _config(request: Request) -> ConfigStore:
    config = _service(request).config
    if config is None:
        raise ApiProblem(503, "detection_unavailable", "Detection settings are not available.")
    return config


@contextmanager
def _errors() -> Iterator[None]:
    try:
        yield
    except NotFound as exc:
        raise ApiProblem(404, "not_found", str(exc)) from None
    except (Invalid, RuleConfigError) as exc:
        raise ApiProblem(422, "validation_error", str(exc)) from None
    except OperationalError:
        raise ApiProblem(
            503, "database_unavailable", "The database is not available right now."
        ) from None


def _rule(request: Request, rule_id: str, with_changes: bool) -> schemas.RuleConfig:
    service, config = _service(request), _config(request)
    spec = service.registry.get(rule_id)
    meta = spec.meta
    row = config.rule_rows().get(rule_id)
    enabled = row.enabled if row is not None and row.enabled is not None else meta.default_enabled
    values = service.registry.validate(rule_id, row.overrides if row else {})
    state = next((r for r in service.status()["rules"] if r["id"] == rule_id), None)
    return schemas.RuleConfig(
        id=meta.id, name=meta.name, category=meta.category, version=meta.version, severity=meta.severity,
        description=meta.description, benign_explanations=list(meta.benign), blind_spots=list(meta.blind_spots),
        default_enabled=meta.default_enabled, enabled=enabled, requires_baseline=meta.requires_baseline,
        requires_direction=meta.requires_direction,
        state=state["state"] if state and enabled else ("evaluating" if enabled else "disabled"),
        reason=state["reason"] if state and enabled else ("" if enabled else "switched off"),
        customised=bool(row and ((row.enabled is not None and row.enabled != meta.default_enabled) or row.overrides)),
        params=[
            DetectionParam(name=p.name, value=values[p.name], default=p.default, minimum=p.minimum, maximum=p.maximum, unit=p.unit)
            for p in meta.params
        ],
        changes=[schemas.RuleChange(**c) for c in config.rule_changes(rule_id)] if with_changes else [],
    )  # fmt: skip


@router.get(
    "/detection/rules",
    summary="Every rule with its saved settings",
    response_model=schemas.RuleConfigList,
)
def list_rules(request: Request) -> schemas.RuleConfigList:
    with _errors():
        return schemas.RuleConfigList(
            items=[_rule(request, s.meta.id, False) for s in _service(request).registry.specs()]
        )


@router.get(
    "/detection/rules/{rule_id}",
    summary="One rule with its recent changes",
    response_model=schemas.RuleConfig,
)
def get_rule(request: Request, rule_id: RuleId) -> schemas.RuleConfig:
    with _errors():
        _config(request)
        _service(request).registry.get(rule_id)
        return _rule(request, rule_id, True)


@router.put(
    "/detection/rules/{rule_id}",
    summary="Switch a rule or change its values; the next analysed session uses them",
    response_model=schemas.RuleConfig,
)
def put_rule(request: Request, rule_id: RuleId, body: schemas.RuleUpdate) -> schemas.RuleConfig:
    with _errors():
        kwargs: dict[str, Any] = {}
        if body.enabled is not None:
            kwargs["enabled"] = body.enabled
        _config(request).put_rule(_service(request).registry, rule_id, params=body.params, **kwargs)
        return _rule(request, rule_id, True)


@router.post(
    "/detection/rules/{rule_id}/reset",
    summary="Return a rule to its defaults",
    response_model=schemas.RuleConfig,
)
def reset_rule(request: Request, rule_id: RuleId) -> schemas.RuleConfig:
    with _errors():
        _config(request).reset_rule(_service(request).registry, rule_id)
        return _rule(request, rule_id, True)


@router.get(
    "/detection/suppressions", summary="Active suppressions", response_model=schemas.SuppressionList
)
def list_suppressions(request: Request) -> schemas.SuppressionList:
    with _errors():
        rows = _config(request).list_suppressions()
        return schemas.SuppressionList(
            items=[
                schemas.Suppression(
                    id=r.id, rule_id=r.rule_id, entity_kind=r.entity_kind, entity_key=r.entity_key,
                    reason=r.reason, created_at=r.created_at, expires_at=r.expires_at,
                )
                for r in rows
            ]
        )  # fmt: skip


@router.put(
    "/detection/suppressions",
    summary="Suppress one rule for one entity",
    response_model=schemas.Suppression,
)
def put_suppression(request: Request, body: schemas.SuppressionIn) -> schemas.Suppression:
    with _errors():
        r = _config(request).put_suppression(
            _service(request).registry,
            body.rule_id,
            body.entity_kind,
            body.entity_key,
            body.reason,
            body.expires_at,
        )
        return schemas.Suppression(
            id=r.id, rule_id=r.rule_id, entity_kind=r.entity_kind, entity_key=r.entity_key,
            reason=r.reason, created_at=r.created_at, expires_at=r.expires_at,
        )  # fmt: skip


@router.delete(
    "/detection/suppressions/{suppression_id}", summary="Remove a suppression", status_code=204
)
def delete_suppression(
    request: Request, suppression_id: Annotated[int, Path(ge=1, le=2**62)]
) -> Response:
    with _errors():
        _config(request).delete_suppression(suppression_id)
    return Response(status_code=204)


@router.get(
    "/detection/networks",
    summary="Observed networks and baseline readiness",
    response_model=schemas.NetworkList,
)
def list_networks(request: Request) -> schemas.NetworkList:
    with _errors():
        return schemas.NetworkList(
            items=[schemas.Network(**n) for n in _config(request).networks()]
        )


@router.delete(
    "/detection/baselines/{network_id}",
    summary="Reset what was learned for one network",
    response_model=schemas.BaselineReset,
)
def reset_baseline(
    request: Request, network_id: Annotated[int, Path(ge=1, le=2**62)]
) -> schemas.BaselineReset:
    with _errors():
        removed = _config(request).delete_baselines(network_id)
        return schemas.BaselineReset(network_id=network_id, devices_removed=removed)


def _settings(values: dict[str, float]) -> schemas.DetectionSettings:
    return schemas.DetectionSettings(
        retention_alert_days=int(values["retention.alert_days"]),
        retention_alert_max=int(values["retention.alert_max"]),
        baseline_hours_min=values["baseline.hours_min"],
        baseline_sessions_min=int(values["baseline.sessions_min"]),
        risk_half_life_days=int(values["risk.half_life_days"]),
    )


@router.get(
    "/detection/settings",
    summary="Retention, baseline and risk settings",
    response_model=schemas.DetectionSettings,
)
def get_settings(request: Request) -> schemas.DetectionSettings:
    with _errors():
        return _settings(_config(request).settings())


@router.put(
    "/detection/settings",
    summary="Change retention, baseline or risk settings",
    response_model=schemas.DetectionSettings,
)
def put_settings(
    request: Request, body: schemas.DetectionSettingsUpdate
) -> schemas.DetectionSettings:
    names = {
        "retention_alert_days": "retention.alert_days", "retention_alert_max": "retention.alert_max",
        "baseline_hours_min": "baseline.hours_min", "baseline_sessions_min": "baseline.sessions_min",
        "risk_half_life_days": "risk.half_life_days",
    }  # fmt: skip
    values = {names[k]: float(v) for k, v in body.model_dump(exclude_none=True).items()}
    with _errors():
        return _settings(_config(request).put_settings(values))


@router.put(
    "/devices/{device_id}/annotation",
    summary="Say what a device is and whether you know it",
    response_model=schemas.Annotation,
    tags=["devices"],
)
def put_annotation(
    request: Request, device_id: Annotated[int, Path(ge=1, le=2**62)], body: schemas.AnnotationIn
) -> schemas.Annotation:
    with _errors():
        row = _config(request).put_annotation(device_id, body.role, body.trust, body.note)
        return schemas.Annotation(
            device_id=row.device_id,
            role=body.role,
            trust=body.trust,
            note=row.note,
            updated_at=row.updated_at,
        )


def _risk(p: dict[str, Any]) -> schemas.DeviceRisk:
    return schemas.DeviceRisk(
        **{**p, "contributing": [schemas.RiskContribution(**c) for c in p["contributing"]]}
    )


@router.get(
    "/risk/devices",
    summary="Devices ranked by risk from their alerts",
    response_model=schemas.DeviceRiskList,
    tags=["risk"],
)
def list_device_risk(request: Request) -> schemas.DeviceRiskList:
    with _errors():
        return schemas.DeviceRiskList(items=[_risk(p) for p in _config(request).device_risk()])


@router.get(
    "/risk/devices/{device_id}",
    summary="Risk and contributing alerts of one device",
    response_model=schemas.DeviceRisk,
    tags=["risk"],
)
def get_device_risk(
    request: Request, device_id: Annotated[int, Path(ge=1, le=2**62)]
) -> schemas.DeviceRisk:
    with _errors():
        found = _config(request).device_risk(device_id)
        if not found:
            raise NotFound("This device has no counted alerts.")
        return _risk(found[0])
