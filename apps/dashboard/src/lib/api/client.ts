import type {
  CaptureInterfaceList,
  CapturePrerequisites,
  CaptureStatus,
  ApplicationStats,
  ConversationList,
  CurrentScan,
  DeviceDetail,
  DeviceList,
  DeviceObservationList,
  DeviceQuery,
  FilterCheck,
  FlowDetail,
  FlowPage,
  FlowQuery,
  FlowSessionList,
  FlowSummary,
  FlowTimeline,
  Health,
  InterfaceEventList,
  InterfaceList,
  PacketDetail,
  PacketPage,
  PacketQuery,
  ProtocolStats,
  SavedCapture,
  Scan,
  ScanList,
  ScanRequest,
  StartCaptureRequest,
  AlertDetail,
  AlertEventPage,
  AlertPage,
  AlertPatch,
  AlertQuery,
  AlertSummary,
  AlertSummaryRange,
  Annotation,
  AnnotationIn,
  BaselineReset,
  DeleteHistoryResult,
  DetectionSettings,
  DetectionSettingsUpdate,
  DetectionStatus,
  DeviceRisk,
  DeviceRiskList,
  NetworkList,
  RuleConfig,
  RuleConfigList,
  RuleUpdate,
  StoredRunPage,
  Suppression,
  SuppressionIn,
  SuppressionList,
  TopologyEdgeDetail,
  TopologyGraph,
  TopologyNodeDetail,
  TopologyQuery,
  DeleteWebHistoryResult,
  DeleteWebInspectionResult,
  WebInspectionDetail,
  WebInspectionList,
  WebInspectionQuery,
  WebInspectionRequest,
  WebInspectionSummary,
  AddNoteRequest,
  AttachEvidenceRequest,
  AuditEventList,
  AuditListQuery,
  BundleVerificationResponse,
  CaseIntegrityVerdict,
  CaseList,
  CaseListQuery,
  CaseStatusRequest,
  CaseSummary,
  CorrelationList,
  CreateCaseRequest,
  CustodyList,
  DeleteCaseResult,
  EvidenceDetail,
  EvidenceList,
  ExportCaseRequest,
  ExportList,
  ExportSummary,
  NoteList,
  NoteSummary,
  ReportsOverviewResponse,
  TimelineList,
  VerifyAllResponse,
  VerifyLocalBundleRequest,
} from "./types";

export type ApiErrorKind = "auth" | "network" | "server";

/** Any failed backend call. Messages are safe to show to the user and never contain the token. */
export class ApiError extends Error {
  override readonly name = "ApiError";

  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }

  /** auth: credentials rejected. network: backend unreachable or too slow. server: anything else. */
  get kind(): ApiErrorKind {
    if (this.status === 401 || this.status === 403) return "auth";
    if (this.status === 0) return "network";
    return "server";
  }
}

export type Paging = { limit?: number; offset?: number };

export interface ApiClient {
  getHealth(signal?: AbortSignal): Promise<Health>;
  getCapturePrerequisites(signal?: AbortSignal): Promise<CapturePrerequisites>;

  /** `refresh` makes the backend re-read the operating system instead of using its 2 s cache. */
  getInterfaces(options?: { refresh?: boolean; signal?: AbortSignal }): Promise<InterfaceList>;
  refreshInterfaces(signal?: AbortSignal): Promise<InterfaceList>;
  getInterfaceEvents(limit?: number, signal?: AbortSignal): Promise<InterfaceEventList>;

  getDevices(query?: DeviceQuery, signal?: AbortSignal): Promise<DeviceList>;
  getDevice(id: number, signal?: AbortSignal): Promise<DeviceDetail>;
  getDeviceObservations(
    id: number,
    paging?: Paging,
    signal?: AbortSignal,
  ): Promise<DeviceObservationList>;

  startScan(request: ScanRequest, signal?: AbortSignal): Promise<Scan>;
  getCurrentScan(signal?: AbortSignal): Promise<CurrentScan>;
  getScan(id: string, signal?: AbortSignal): Promise<Scan>;
  cancelScan(id: string, signal?: AbortSignal): Promise<Scan>;
  listScans(paging?: Paging, signal?: AbortSignal): Promise<ScanList>;

  getCaptureStatus(signal?: AbortSignal): Promise<CaptureStatus>;
  getCaptureInterfaces(signal?: AbortSignal): Promise<CaptureInterfaceList>;
  startCapture(request: StartCaptureRequest, signal?: AbortSignal): Promise<CaptureStatus>;
  stopCapture(signal?: AbortSignal): Promise<CaptureStatus>;
  getPackets(query?: PacketQuery, signal?: AbortSignal): Promise<PacketPage>;
  getPacket(number: number, signal?: AbortSignal): Promise<PacketDetail>;
  validateFilter(displayFilter: string, signal?: AbortSignal): Promise<FilterCheck>;
  saveCapture(path: string, signal?: AbortSignal): Promise<SavedCapture>;
  openCapture(path: string, signal?: AbortSignal): Promise<CaptureStatus>;

  /** `session` is "current" (the default) or the id of a saved flow session. */
  getFlowSummary(session?: string, signal?: AbortSignal): Promise<FlowSummary>;
  getFlows(query?: FlowQuery, signal?: AbortSignal): Promise<FlowPage>;
  getFlow(id: string, signal?: AbortSignal): Promise<FlowDetail>;
  getFlowProtocols(session?: string, signal?: AbortSignal): Promise<ProtocolStats>;
  getFlowApplications(session?: string, signal?: AbortSignal): Promise<ApplicationStats>;
  getFlowConversations(session?: string, signal?: AbortSignal): Promise<ConversationList>;
  getFlowTimeline(session?: string, signal?: AbortSignal): Promise<FlowTimeline>;
  getFlowSessions(paging?: Paging, signal?: AbortSignal): Promise<FlowSessionList>;
  // --- Phase 4: threat detection ---
  getAlerts(query?: AlertQuery, signal?: AbortSignal): Promise<AlertPage>;
  getAlert(id: number, signal?: AbortSignal): Promise<AlertDetail>;
  patchAlert(id: number, body: AlertPatch, signal?: AbortSignal): Promise<AlertDetail>;
  getAlertEvents(id: number, paging?: Paging, signal?: AbortSignal): Promise<AlertEventPage>;
  /** `range` is the timeline range of the chart: 24h (default), 7d, 30d or all. */
  getAlertSummary(range?: AlertSummaryRange, signal?: AbortSignal): Promise<AlertSummary>;
  getDetectionStatus(signal?: AbortSignal): Promise<DetectionStatus>;
  getDetectionRuns(paging?: Paging, signal?: AbortSignal): Promise<StoredRunPage>;
  deleteDetectionHistory(signal?: AbortSignal): Promise<DeleteHistoryResult>;
  getRules(signal?: AbortSignal): Promise<RuleConfigList>;
  getRule(id: string, signal?: AbortSignal): Promise<RuleConfig>;
  putRule(id: string, body: RuleUpdate, signal?: AbortSignal): Promise<RuleConfig>;
  resetRule(id: string, signal?: AbortSignal): Promise<RuleConfig>;
  getDetectionSettings(signal?: AbortSignal): Promise<DetectionSettings>;
  putDetectionSettings(body: DetectionSettingsUpdate, signal?: AbortSignal): Promise<DetectionSettings>;
  getSuppressions(signal?: AbortSignal): Promise<SuppressionList>;
  putSuppression(body: SuppressionIn, signal?: AbortSignal): Promise<Suppression>;
  deleteSuppression(id: number, signal?: AbortSignal): Promise<void>;
  getNetworks(signal?: AbortSignal): Promise<NetworkList>;
  resetBaseline(networkId: number, signal?: AbortSignal): Promise<BaselineReset>;
  getDeviceRisks(signal?: AbortSignal): Promise<DeviceRiskList>;
  getDeviceRisk(deviceId: number, signal?: AbortSignal): Promise<DeviceRisk>;
  putAnnotation(deviceId: number, body: AnnotationIn, signal?: AbortSignal): Promise<Annotation>;
  getTopology(query?: TopologyQuery, signal?: AbortSignal): Promise<TopologyGraph>;
  getTopologyNode(key: string, query?: TopologyQuery, signal?: AbortSignal): Promise<TopologyNodeDetail>;
  getTopologyEdge(id: string, query?: TopologyQuery, signal?: AbortSignal): Promise<TopologyEdgeDetail>;
  // --- Phase 5: Web Inspector ---
  startWebInspection(body: WebInspectionRequest, signal?: AbortSignal): Promise<WebInspectionSummary>;
  listWebInspections(query?: WebInspectionQuery, signal?: AbortSignal): Promise<WebInspectionList>;
  getWebInspection(id: number, signal?: AbortSignal): Promise<WebInspectionDetail>;
  cancelWebInspection(id: number, signal?: AbortSignal): Promise<WebInspectionSummary>;
  deleteWebInspection(id: number, signal?: AbortSignal): Promise<DeleteWebInspectionResult>;
  deleteWebHistory(signal?: AbortSignal): Promise<DeleteWebHistoryResult>;
  exportWebInspection(id: number, format: "json" | "markdown", signal?: AbortSignal): Promise<string>;
  // --- Phase 6: Investigations, Reports & Audit ---
  listCases(query?: CaseListQuery, signal?: AbortSignal): Promise<CaseList>;
  createCase(body: CreateCaseRequest, signal?: AbortSignal): Promise<CaseSummary>;
  getCase(caseId: number, signal?: AbortSignal): Promise<CaseSummary>;
  updateCaseStatus(caseId: number, body: CaseStatusRequest, signal?: AbortSignal): Promise<CaseSummary>;
  purgeDraftCase(caseId: number, actor?: string, signal?: AbortSignal): Promise<DeleteCaseResult>;
  listCaseEvidence(caseId: number, signal?: AbortSignal): Promise<EvidenceList>;
  attachCaseEvidence(caseId: number, body: AttachEvidenceRequest, signal?: AbortSignal): Promise<EvidenceDetail>;
  getCaseEvidence(caseId: number, evidenceId: number, signal?: AbortSignal): Promise<EvidenceDetail>;
  listCaseCustody(caseId: number, signal?: AbortSignal): Promise<CustodyList>;
  verifyCaseIntegrity(caseId: number, actor?: string, signal?: AbortSignal): Promise<CaseIntegrityVerdict>;
  getCaseTimeline(caseId: number, signal?: AbortSignal): Promise<TimelineList>;
  runCaseCorrelations(caseId: number, actor?: string, signal?: AbortSignal): Promise<CorrelationList>;
  listCaseCorrelations(caseId: number, signal?: AbortSignal): Promise<CorrelationList>;
  listCaseNotes(caseId: number, signal?: AbortSignal): Promise<NoteList>;
  addCaseNote(caseId: number, body: AddNoteRequest, signal?: AbortSignal): Promise<NoteSummary>;
  listCaseExports(caseId: number, signal?: AbortSignal): Promise<ExportList>;
  exportCase(caseId: number, body: ExportCaseRequest, signal?: AbortSignal): Promise<ExportSummary>;
  downloadCaseExport(caseId: number, exportId: number, signal?: AbortSignal): Promise<Blob>;
  verifyBundleUpload(data: Blob | ArrayBuffer, signal?: AbortSignal): Promise<BundleVerificationResponse>;
  verifyLocalBundle(body: VerifyLocalBundleRequest, signal?: AbortSignal): Promise<BundleVerificationResponse>;
  getReportsOverview(signal?: AbortSignal): Promise<ReportsOverviewResponse>;
  verifyAllCases(actor?: string, signal?: AbortSignal): Promise<VerifyAllResponse>;
  listAuditEvents(query?: AuditListQuery, signal?: AbortSignal): Promise<AuditEventList>;
}

export interface ApiClientOptions {
  baseUrl: string;
  token: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function errorFromResponse(status: number, body: unknown): ApiError {
  const envelope = isRecord(body) ? body.error : undefined;
  if (isRecord(envelope) && typeof envelope.code === "string" && typeof envelope.message === "string") {
    return new ApiError(status, envelope.code, envelope.message);
  }
  return new ApiError(status, "http_error", `The backend returned HTTP ${String(status)}.`);
}

type QueryValue = string | number | boolean | null | undefined;

/** `path?a=1&b=2` from the values that are actually set; empty and unset values are left out. */
function withQuery(path: string, params?: Record<string, QueryValue>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `${path}?${text}` : path;
}

export function createApiClient(options: ApiClientOptions): ApiClient {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // `accept` names a documented non-2xx status whose body is a success-shaped payload, plus a
  // guard that proves the body really has that shape (an error envelope must never pass for it).
  async function request<T>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    signal: AbortSignal | undefined,
    extra: { body?: unknown; accept?: { status: number; isBody: (body: unknown) => boolean } } = {},
  ): Promise<T> {
    const { accept } = extra;
    // One controller merges the caller's signal with our timeout (AbortSignal.any is not
    // available in every embedded WebKit we target).
    const controller = new AbortController();
    const forwardAbort = () => {
      controller.abort(signal?.reason);
    };
    if (signal?.aborted) forwardAbort();
    else signal?.addEventListener("abort", forwardAbort, { once: true });
    const timer = setTimeout(() => {
      controller.abort(new DOMException("Request timed out", "TimeoutError"));
    }, timeoutMs);

    try {
      let response: Response;
      try {
        const headers: Record<string, string> = {
          Accept: "application/json",
          Authorization: `Bearer ${options.token}`,
        };
        if (extra.body !== undefined) headers["Content-Type"] = "application/json";
        response = await fetchImpl(`${baseUrl}${path}`, {
          method,
          headers,
          body: extra.body === undefined ? undefined : JSON.stringify(extra.body),
          signal: controller.signal,
        });
      } catch (cause) {
        if (signal?.aborted) throw cause; // the caller cancelled; let them ignore it
        if (isRecord(controller.signal.reason) && controller.signal.reason.name === "TimeoutError") {
          throw new ApiError(0, "timeout", "The backend did not respond in time.");
        }
        throw new ApiError(0, "network_error", "Cannot reach the TAPROX backend.");
      }

      const text = await response.text();
      let body: unknown;
      try {
        body = text ? (JSON.parse(text) as unknown) : undefined;
      } catch {
        body = undefined; // non-JSON (e.g. a proxy error page); never surfaced to the user
      }
      if (response.ok || (response.status === accept?.status && accept.isBody(body))) {
        return body as T;
      }
      throw errorFromResponse(response.status, body);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", forwardAbort);
    }
  }

  // A 503 from /health is a real report ("unhealthy"), not a failure; it has the Health shape.
  const isHealthBody = (body: unknown) =>
    isRecord(body) && typeof body.status === "string" && isRecord(body.database);

  const get = <T>(path: string, signal?: AbortSignal) => request<T>("GET", path, signal);
  const post = <T>(path: string, signal?: AbortSignal, body?: unknown) =>
    request<T>("POST", path, signal, { body });
  const send = <T>(method: "PUT" | "PATCH" | "DELETE", path: string, signal: AbortSignal | undefined, body?: unknown) =>
    request<T>(method, path, signal, { body });
  const encode = (id: number | string) => encodeURIComponent(String(id));

  return {
    getHealth: (signal) =>
      request<Health>("GET", "/api/v1/health", signal, {
        accept: { status: 503, isBody: isHealthBody },
      }),
    getCapturePrerequisites: (signal) =>
      get<CapturePrerequisites>("/api/v1/system/capture-prerequisites", signal),

    getInterfaces: ({ refresh, signal } = {}) =>
      get<InterfaceList>(withQuery("/api/v1/interfaces", { refresh }), signal),
    refreshInterfaces: (signal) => post<InterfaceList>("/api/v1/interfaces/refresh", signal),
    getInterfaceEvents: (limit, signal) =>
      get<InterfaceEventList>(withQuery("/api/v1/interfaces/events", { limit }), signal),

    getDevices: (query, signal) =>
      get<DeviceList>(withQuery("/api/v1/devices", query), signal),
    getDevice: (id, signal) => get<DeviceDetail>(`/api/v1/devices/${encode(id)}`, signal),
    getDeviceObservations: (id, paging, signal) =>
      get<DeviceObservationList>(
        withQuery(`/api/v1/devices/${encode(id)}/observations`, paging),
        signal,
      ),

    startScan: (body, signal) => post<Scan>("/api/v1/discovery/scans", signal, body),
    getCurrentScan: (signal) => get<CurrentScan>("/api/v1/discovery/scans/current", signal),
    getScan: (id, signal) => get<Scan>(`/api/v1/discovery/scans/${encode(id)}`, signal),
    cancelScan: (id, signal) => post<Scan>(`/api/v1/discovery/scans/${encode(id)}/cancel`, signal),
    listScans: (paging, signal) =>
      get<ScanList>(withQuery("/api/v1/discovery/scans", paging), signal),

    getCaptureStatus: (signal) => get<CaptureStatus>("/api/v1/capture/status", signal),
    getCaptureInterfaces: (signal) =>
      get<CaptureInterfaceList>("/api/v1/capture/interfaces", signal),
    startCapture: (body, signal) => post<CaptureStatus>("/api/v1/capture/start", signal, body),
    stopCapture: (signal) => post<CaptureStatus>("/api/v1/capture/stop", signal),
    getPackets: (query, signal) =>
      get<PacketPage>(withQuery("/api/v1/capture/packets", query), signal),
    getPacket: (number, signal) => get<PacketDetail>(`/api/v1/capture/packets/${encode(number)}`, signal),
    validateFilter: (displayFilter, signal) =>
      post<FilterCheck>("/api/v1/capture/filter/validate", signal, { display_filter: displayFilter }),
    saveCapture: (path, signal) => post<SavedCapture>("/api/v1/capture/save", signal, { path }),
    openCapture: (path, signal) => post<CaptureStatus>("/api/v1/capture/open", signal, { path }),

    getFlowSummary: (session, signal) =>
      get<FlowSummary>(withQuery("/api/v1/flows/summary", { session }), signal),
    getFlows: (query, signal) => get<FlowPage>(withQuery("/api/v1/flows", query), signal),
    getFlow: (id, signal) => get<FlowDetail>(`/api/v1/flows/${encode(id)}`, signal),
    getFlowProtocols: (session, signal) =>
      get<ProtocolStats>(withQuery("/api/v1/flows/protocols", { session }), signal),
    getFlowApplications: (session, signal) =>
      get<ApplicationStats>(withQuery("/api/v1/flows/applications", { session }), signal),
    getFlowConversations: (session, signal) =>
      get<ConversationList>(withQuery("/api/v1/flows/conversations", { session }), signal),
    getFlowTimeline: (session, signal) =>
      get<FlowTimeline>(withQuery("/api/v1/flows/timeline", { session }), signal),
    getFlowSessions: (paging, signal) =>
      get<FlowSessionList>(withQuery("/api/v1/flows/sessions", paging), signal),
    getAlerts: (query, signal) => get<AlertPage>(withQuery("/api/v1/alerts", query), signal),
    getAlert: (id, signal) => get<AlertDetail>(`/api/v1/alerts/${encode(id)}`, signal),
    patchAlert: (id, body, signal) => send<AlertDetail>("PATCH", `/api/v1/alerts/${encode(id)}`, signal, body),
    getAlertEvents: (id, paging, signal) =>
      get<AlertEventPage>(withQuery(`/api/v1/alerts/${encode(id)}/events`, paging), signal),
    getAlertSummary: (range, signal) =>
      get<AlertSummary>(withQuery("/api/v1/alerts/summary", { range: range === "24h" ? undefined : range }), signal),
    getDetectionStatus: (signal) => get<DetectionStatus>("/api/v1/detection/status", signal),
    getDetectionRuns: (paging, signal) =>
      get<StoredRunPage>(withQuery("/api/v1/detection/runs", paging), signal),
    deleteDetectionHistory: (signal) =>
      send<DeleteHistoryResult>("DELETE", "/api/v1/detection/history", signal, { confirm: true }),
    getRules: (signal) => get<RuleConfigList>("/api/v1/detection/rules", signal),
    getRule: (id, signal) => get<RuleConfig>(`/api/v1/detection/rules/${encode(id)}`, signal),
    putRule: (id, body, signal) => send<RuleConfig>("PUT", `/api/v1/detection/rules/${encode(id)}`, signal, body),
    resetRule: (id, signal) => post<RuleConfig>(`/api/v1/detection/rules/${encode(id)}/reset`, signal),
    getDetectionSettings: (signal) => get<DetectionSettings>("/api/v1/detection/settings", signal),
    putDetectionSettings: (body, signal) =>
      send<DetectionSettings>("PUT", "/api/v1/detection/settings", signal, body),
    getSuppressions: (signal) => get<SuppressionList>("/api/v1/detection/suppressions", signal),
    putSuppression: (body, signal) => send<Suppression>("PUT", "/api/v1/detection/suppressions", signal, body),
    deleteSuppression: (id, signal) =>
      send<void>("DELETE", `/api/v1/detection/suppressions/${encode(id)}`, signal),
    getNetworks: (signal) => get<NetworkList>("/api/v1/detection/networks", signal),
    resetBaseline: (networkId, signal) =>
      send<BaselineReset>("DELETE", `/api/v1/detection/baselines/${encode(networkId)}`, signal),
    getDeviceRisks: (signal) => get<DeviceRiskList>("/api/v1/risk/devices", signal),
    getDeviceRisk: (deviceId, signal) => get<DeviceRisk>(`/api/v1/risk/devices/${encode(deviceId)}`, signal),
    putAnnotation: (deviceId, body, signal) =>
      send<Annotation>("PUT", `/api/v1/devices/${encode(deviceId)}/annotation`, signal, body),
    getTopology: (query, signal) => get<TopologyGraph>(withQuery("/api/v1/topology", query), signal),
    getTopologyNode: (key, query, signal) =>
      get<TopologyNodeDetail>(withQuery(`/api/v1/topology/nodes/${encode(key)}`, query), signal),
    getTopologyEdge: (id, query, signal) =>
      get<TopologyEdgeDetail>(withQuery(`/api/v1/topology/edges/${encode(id)}`, query), signal),
    startWebInspection: (body, signal) =>
      post<WebInspectionSummary>("/api/v1/web-inspector/inspections", signal, body),
    listWebInspections: (query, signal) =>
      get<WebInspectionList>(withQuery("/api/v1/web-inspector/inspections", query), signal),
    getWebInspection: (id, signal) =>
      get<WebInspectionDetail>(`/api/v1/web-inspector/inspections/${encode(id)}`, signal),
    cancelWebInspection: (id, signal) =>
      post<WebInspectionSummary>(`/api/v1/web-inspector/inspections/${encode(id)}/cancel`, signal),
    deleteWebInspection: (id, signal) =>
      send<DeleteWebInspectionResult>("DELETE", `/api/v1/web-inspector/inspections/${encode(id)}`, signal),
    deleteWebHistory: (signal) =>
      send<DeleteWebHistoryResult>("DELETE", "/api/v1/web-inspector/history", signal, { confirm: true }),
    exportWebInspection: async (id, format, signal) => {
      const response = await fetchImpl(
        `${baseUrl}${withQuery(`/api/v1/web-inspector/inspections/${encode(id)}/export`, { format })}`,
        {
          method: "GET",
          headers: { Authorization: `Bearer ${options.token}` },
          signal,
        },
      );
      const text = await response.text();
      if (!response.ok) {
        let parsed: unknown;
        try {
          parsed = text ? (JSON.parse(text) as unknown) : undefined;
        } catch {
          parsed = undefined;
        }
        throw errorFromResponse(response.status, parsed);
      }
      return text;
    },
    listCases: (query, signal) => get<CaseList>(withQuery("/api/v1/investigations", query), signal),
    createCase: (body, signal) => post<CaseSummary>("/api/v1/investigations", signal, body),
    getCase: (caseId, signal) => get<CaseSummary>(`/api/v1/investigations/${encode(caseId)}`, signal),
    updateCaseStatus: (caseId, body, signal) =>
      send<CaseSummary>("PATCH", `/api/v1/investigations/${encode(caseId)}/status`, signal, body),
    purgeDraftCase: (caseId, actor, signal) =>
      send<DeleteCaseResult>(
        "DELETE",
        withQuery(`/api/v1/investigations/${encode(caseId)}`, { confirm_action: true, actor }),
        signal,
      ),
    listCaseEvidence: (caseId, signal) =>
      get<EvidenceList>(`/api/v1/investigations/${encode(caseId)}/evidence`, signal),
    attachCaseEvidence: (caseId, body, signal) =>
      post<EvidenceDetail>(`/api/v1/investigations/${encode(caseId)}/evidence`, signal, body),
    getCaseEvidence: (caseId, evidenceId, signal) =>
      get<EvidenceDetail>(
        `/api/v1/investigations/${encode(caseId)}/evidence/${encode(evidenceId)}`,
        signal,
      ),
    listCaseCustody: (caseId, signal) =>
      get<CustodyList>(`/api/v1/investigations/${encode(caseId)}/custody`, signal),
    verifyCaseIntegrity: (caseId, actor, signal) =>
      post<CaseIntegrityVerdict>(
        `/api/v1/investigations/${encode(caseId)}/verify`,
        signal,
        actor ? { actor } : {},
      ),
    getCaseTimeline: (caseId, signal) =>
      get<TimelineList>(`/api/v1/investigations/${encode(caseId)}/timeline`, signal),
    runCaseCorrelations: (caseId, actor, signal) =>
      post<CorrelationList>(
        `/api/v1/investigations/${encode(caseId)}/correlate`,
        signal,
        actor ? { actor } : {},
      ),
    listCaseCorrelations: (caseId, signal) =>
      get<CorrelationList>(`/api/v1/investigations/${encode(caseId)}/correlations`, signal),
    listCaseNotes: (caseId, signal) =>
      get<NoteList>(`/api/v1/investigations/${encode(caseId)}/notes`, signal),
    addCaseNote: (caseId, body, signal) =>
      post<NoteSummary>(`/api/v1/investigations/${encode(caseId)}/notes`, signal, body),
    listCaseExports: (caseId, signal) =>
      get<ExportList>(`/api/v1/investigations/${encode(caseId)}/exports`, signal),
    exportCase: (caseId, body, signal) =>
      post<ExportSummary>(`/api/v1/investigations/${encode(caseId)}/export`, signal, body),
    downloadCaseExport: async (caseId, exportId, signal) => {
      const response = await fetchImpl(
        `${baseUrl}/api/v1/investigations/${encode(caseId)}/exports/${encode(exportId)}/download`,
        { method: "GET", headers: { Authorization: `Bearer ${options.token}` }, signal },
      );
      if (!response.ok) {
        let parsed: unknown;
        try {
          parsed = (await response.json()) as unknown;
        } catch {
          parsed = undefined;
        }
        throw errorFromResponse(response.status, parsed);
      }
      return response.blob();
    },
    verifyBundleUpload: async (data, signal) => {
      const response = await fetchImpl(`${baseUrl}/api/v1/investigations/verify-bundle`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${options.token}`,
          "Content-Type": "application/octet-stream",
        },
        body: data,
        signal,
      });
      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = text ? (JSON.parse(text) as unknown) : undefined;
      } catch {
        parsed = undefined;
      }
      if (!response.ok) throw errorFromResponse(response.status, parsed);
      return parsed as BundleVerificationResponse;
    },
    verifyLocalBundle: (body, signal) =>
      post<BundleVerificationResponse>("/api/v1/investigations/verify-local-bundle", signal, body),
    getReportsOverview: (signal) => get<ReportsOverviewResponse>("/api/v1/reports/overview", signal),
    verifyAllCases: (actor, signal) =>
      post<VerifyAllResponse>("/api/v1/reports/verify-all", signal, actor ? { actor } : {}),
    listAuditEvents: (query, signal) =>
      get<AuditEventList>(withQuery("/api/v1/audit/events", query), signal),
  };
}
