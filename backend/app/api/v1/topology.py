"""Network topology (Phase 4 / M7): the graph of one session, or the history of live sessions."""

import dataclasses
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Request
from sqlalchemy.exc import OperationalError

from app.core.errors import ApiProblem
from app.schemas import topology as schemas
from app.schemas.errors import ErrorResponse
from app.services.topology.model import Coverage, Edge, Graph, Node
from app.services.topology.service import TopologyError, TopologyService

router = APIRouter(prefix="/topology", tags=["topology"])

Session = Annotated[
    str, Query(pattern=r"^(current|[1-9]\d{0,15})$", description="'current' or a flow session id.")
]
Window = Annotated[
    str,
    Query(
        pattern=r"^(session|24h|7d|30d|all)$",
        description="'session' for one session, or a history window.",
    ),
]
GroupBy = Annotated[
    str,
    Query(
        pattern=r"^(auto|none|role|vendor|segment)$",
        description="Merge devices into groups. auto groups by segment above 150 devices; none never groups.",
    ),
]
NodeKey = Annotated[str, Path(min_length=1, max_length=70, pattern=r"^[A-Za-z0-9_:.\-]+$")]
EdgeId = Annotated[str, Path(pattern=r"^e[0-9a-f]{14}$")]
_ERRORS: dict[int | str, dict[str, Any]] = {
    404: {
        "model": ErrorResponse,
        "description": "The session, node or relationship does not exist",
    },
    503: {"model": ErrorResponse, "description": "The database is not available right now"},
}
MAX_NODE_EDGES = 25


def _service(request: Request) -> TopologyService:
    service: TopologyService = request.app.state.topology
    return service


def _node(n: Node) -> schemas.TopologyNode:
    return schemas.TopologyNode(**dataclasses.asdict(n))


def _edge(e: Edge) -> schemas.TopologyEdge:
    data = dataclasses.asdict(e)
    data.pop("days")
    return schemas.TopologyEdge(**data)


def _coverage(c: Coverage) -> schemas.TopologyCoverage:
    return schemas.TopologyCoverage(**dataclasses.asdict(c))


def _guard(call: Any) -> Any:
    try:
        return call()
    except TopologyError as exc:
        raise ApiProblem(exc.status, exc.code, exc.message) from None
    except OperationalError:
        raise ApiProblem(
            503, "database_unavailable", "The database is not available right now."
        ) from None


@router.get(
    "",
    summary="The network graph of a session, or the history of live sessions",
    response_model=schemas.TopologyGraph,
    responses=_ERRORS,
)
def topology(
    request: Request,
    session: Session = "current",
    window: Window = "session",
    group_by: GroupBy = "auto",
) -> schemas.TopologyGraph:
    g: Graph = _guard(lambda: _service(request).graph(session, window, group_by))
    return schemas.TopologyGraph(
        session_id=g.session_id, window=g.window, source=g.source,  # type: ignore[arg-type]
        nodes=[_node(n) for n in g.nodes], edges=[_edge(e) for e in g.edges], coverage=_coverage(g.coverage),
        total_nodes=g.total_nodes, total_edges=g.total_edges, reduced=g.reduced,
        grouped_remote_hosts=g.grouped_remote_hosts, grouped_by=g.grouped_by,  # type: ignore[arg-type]
    )  # fmt: skip


@router.get(
    "/nodes/{key}",
    summary="One node with its busiest relationships",
    response_model=schemas.TopologyNodeDetail,
    responses=_ERRORS,
)
def node_detail(
    request: Request,
    key: NodeKey,
    session: Session = "current",
    window: Window = "session",
    group_by: GroupBy = "auto",
) -> schemas.TopologyNodeDetail:
    node, edges, g = _guard(lambda: _service(request).node(key, session, window, group_by))
    return schemas.TopologyNodeDetail(
        node=_node(node), edges=[_edge(e) for e in edges[:MAX_NODE_EDGES]],
        more_edges=max(0, len(edges) - MAX_NODE_EDGES), coverage=_coverage(g.coverage),
    )  # fmt: skip


@router.get(
    "/edges/{edge_id}",
    summary="One relationship with its evidence",
    response_model=schemas.TopologyEdgeDetail,
    responses=_ERRORS,
)
def edge_detail(
    request: Request,
    edge_id: EdgeId,
    session: Session = "current",
    window: Window = "session",
    group_by: GroupBy = "auto",
) -> schemas.TopologyEdgeDetail:
    edge, a, b, g = _guard(lambda: _service(request).edge(edge_id, session, window, group_by))
    return schemas.TopologyEdgeDetail(
        edge=_edge(edge), a=_node(a), b=_node(b),
        days=[schemas.TopologyDay(day=d, flows=f, bytes=n) for d, f, n in edge.days], coverage=_coverage(g.coverage),
    )  # fmt: skip
