import type { components, paths } from "@tapnettrack/api-contracts";

// Types come from the generated contract; never hand-write API shapes here.
type Schemas = components["schemas"];

export type Health = Schemas["HealthResponse"];
export type CapturePrerequisites = Schemas["CapturePrerequisitesResponse"];
export type PrerequisiteCheck = Schemas["PrerequisiteCheck"];
export type PlatformInfo = Schemas["PlatformInfo"];

export type NetworkInterface = Schemas["NetworkInterface"];
export type InterfaceList = Schemas["InterfaceList"];
export type InterfaceEvent = Schemas["InterfaceEvent"];
export type InterfaceEventList = Schemas["InterfaceEventList"];
export type AddressInfo = Schemas["AddressInfo"];

export type Device = Schemas["Device"];
export type DeviceDetail = Schemas["DeviceDetail"];
export type DeviceList = Schemas["DeviceList"];
export type DeviceAddress = Schemas["DeviceAddress"];
export type DeviceObservation = Schemas["DeviceObservation"];
export type DeviceObservationList = Schemas["DeviceObservationList"];
export type DeviceQuery = NonNullable<paths["/api/v1/devices"]["get"]["parameters"]["query"]>;
export type DeviceState = NonNullable<DeviceQuery["state"]>;
export type DeviceSort = NonNullable<DeviceQuery["sort"]>;

export type Scan = Schemas["Scan"];
export type ScanList = Schemas["ScanList"];
export type ScanRequest = Schemas["ScanRequest"];
export type CurrentScan = Schemas["CurrentScan"];

export type CaptureStatus = Schemas["CaptureStatus"];
export type CaptureState = CaptureStatus["state"];
export type CaptureInterface = Schemas["CaptureInterface"];
export type CaptureInterfaceList = Schemas["CaptureInterfaceList"];
export type StartCaptureRequest = Schemas["StartCaptureRequest"];
export type PacketRow = Schemas["PacketRow"];
export type PacketPage = Schemas["PacketPage"];
export type PacketDetail = Schemas["PacketDetail"];
export type PacketField = Schemas["PacketField"];
export type PacketLayer = Schemas["PacketLayer"];
export type FilterCheck = Schemas["FilterCheck"];
export type SavedCapture = Schemas["SavedCapture"];
export type PacketQuery = NonNullable<paths["/api/v1/capture/packets"]["get"]["parameters"]["query"]>;
export type PacketSort = NonNullable<PacketQuery["sort"]>;

export type FlowSummary = Schemas["FlowSummary"];
export type FlowPage = Schemas["FlowPage"];
export type Flow = Schemas["Flow"];
export type FlowDetail = Schemas["FlowDetail"];
export type FlowState = Schemas["Flow"]["state"];
export type FlowSessionInfo = Schemas["FlowSessionInfo"];
export type FlowSessionList = Schemas["FlowSessionList"];
export type ProtocolStats = Schemas["ProtocolStats"];
export type ApplicationStats = Schemas["ApplicationStats"];
export type ApplicationStat = Schemas["ApplicationStat"];
export type DeviceApplicationStat = Schemas["DeviceApplicationStat"];
export type ConversationList = Schemas["ConversationList"];
export type FlowTimeline = Schemas["Timeline"];
export type EndpointRef = Schemas["EndpointRef"];
export type DeviceRef = Schemas["DeviceRef"];
export type FlowQuery = NonNullable<paths["/api/v1/flows"]["get"]["parameters"]["query"]>;
export type FlowSort = NonNullable<FlowQuery["sort"]>;

// --- Phase 4: threat detection ---
export type AlertListItem = Schemas["AlertListItem"];
export type AlertDetail = Schemas["AlertDetail"];
export type AlertPage = Schemas["AlertPage"];
export type AlertPatch = Schemas["AlertPatch"];
export type AlertEventPage = Schemas["AlertEventPage"];
export type AlertSummary = Schemas["AlertSummary"];
export type AlertSummaryRange = "24h" | "7d" | "30d" | "all";
export type AlertStatus = Schemas["AlertListItem"]["status"];
export type AlertSeverity = Schemas["AlertListItem"]["severity"];
export type AlertQuery = NonNullable<paths["/api/v1/alerts"]["get"]["parameters"]["query"]>;
export type DetectionStatus = Schemas["DetectionStatus"];
export type DetectionRun = Schemas["DetectionRun"];
export type StoredRunPage = Schemas["StoredRunPage"];
export type StoredRun = Schemas["StoredRun"];
export type DeleteHistoryResult = Schemas["DeleteHistoryResult"];
export type RuleConfig = Schemas["RuleConfig"];
export type RuleConfigList = Schemas["RuleConfigList"];
export type RuleUpdate = Schemas["RuleUpdate"];
export type DetectionSettings = Schemas["DetectionSettings"];
export type DetectionSettingsUpdate = Schemas["DetectionSettingsUpdate"];
export type Suppression = Schemas["Suppression"];
export type SuppressionIn = Schemas["SuppressionIn"];
export type SuppressionList = Schemas["SuppressionList"];
export type NetworkList = Schemas["NetworkList"];
export type Network = Schemas["Network"];
export type BaselineReset = Schemas["BaselineReset"];
export type DeviceRisk = Schemas["DeviceRisk"];
export type DeviceRiskList = Schemas["DeviceRiskList"];
export type Annotation = Schemas["Annotation"];
export type AnnotationIn = Schemas["AnnotationIn"];
export type TopologyGraph = Schemas["TopologyGraph"];
export type TopologyNode = Schemas["TopologyNode"];
export type TopologyEdge = Schemas["TopologyEdge"];
export type TopologyCoverage = Schemas["TopologyCoverage"];
export type TopologyNodeDetail = Schemas["TopologyNodeDetail"];
export type TopologyEdgeDetail = Schemas["TopologyEdgeDetail"];
export type TopologyQuery = NonNullable<paths["/api/v1/topology"]["get"]["parameters"]["query"]>;

// --- Phase 5: Web Inspector ---
export type WebInspectionRequest = Schemas["WebInspectionRequest"];
export type WebInspectionSummary = Schemas["WebInspectionSummary"];
export type WebInspectionDetail = Schemas["WebInspectionDetail"];
export type WebInspectionList = Schemas["WebInspectionList"];
export type WebHopSchema = Schemas["WebHopSchema"];
export type WebCertificateSchema = Schemas["WebCertificateSchema"];
export type WebCookieSchema = Schemas["WebCookieSchema"];
export type WebFindingSchema = Schemas["WebFindingSchema"];
export type HeaderMatrixEntry = Schemas["HeaderMatrixEntry"];
export type DeleteWebInspectionResult = Schemas["DeleteWebInspectionResult"];
export type DeleteWebHistoryResult = Schemas["DeleteWebHistoryResult"];
export type WebInspectionQuery = NonNullable<paths["/api/v1/web-inspector/inspections"]["get"]["parameters"]["query"]>;

// --- Phase 6: Investigations & Forensics ---
export type CaseSummary = Schemas["CaseSummary"];
export type CaseStatus = CaseSummary["status"];
export type CaseClassification = NonNullable<Schemas["CreateCaseRequest"]["classification"]>;
export type CaseSeverity = NonNullable<Schemas["CreateCaseRequest"]["severity"]>;
export type CaseTransitionStatus = Schemas["CaseStatusRequest"]["target_status"];
export type ArtifactKind = Schemas["AttachEvidenceRequest"]["kind"];
export type NoteKind = NonNullable<Schemas["AddNoteRequest"]["note_kind"]>;
export type ExportFormat = Schemas["ExportSummary"]["format"];
export type CaseList = Schemas["CaseList"];
export type CreateCaseRequest = Schemas["CreateCaseRequest"];
export type CaseStatusRequest = Schemas["CaseStatusRequest"];
export type EvidenceSummary = Schemas["EvidenceSummary"];
export type EvidenceDetail = Schemas["EvidenceDetail"];
export type EvidenceList = Schemas["EvidenceList"];
export type AttachEvidenceRequest = Schemas["AttachEvidenceRequest"];
export type NoteSummary = Schemas["NoteSummary"];
export type NoteList = Schemas["NoteList"];
export type AddNoteRequest = Schemas["AddNoteRequest"];
export type CorrelationSummary = Schemas["CorrelationSummary"];
export type CorrelationList = Schemas["CorrelationList"];
export type TimelineEventItem = Schemas["TimelineEventItem"];
export type TimelineList = Schemas["TimelineList"];
export type CustodyEventItem = Schemas["CustodyEventItem"];
export type CustodyList = Schemas["CustodyList"];
export type CaseIntegrityVerdict = Schemas["CaseIntegrityVerdict"];
export type ExportSummary = Schemas["ExportSummary"];
export type ExportList = Schemas["ExportList"];
export type ExportCaseRequest = Schemas["ExportCaseRequest"];
export type BundleVerificationResponse = Schemas["BundleVerificationResponse"];
export type VerifyLocalBundleRequest = Schemas["VerifyLocalBundleRequest"];
export type DeleteCaseResult = Schemas["DeleteCaseResult"];
export type ReportsOverviewResponse = Schemas["ReportsOverviewResponse"];
export type VerifyAllResponse = Schemas["VerifyAllResponse"];
export type AuditEventItem = Schemas["AuditEventItem"];
export type AuditEventList = Schemas["AuditEventList"];
export type CaseListQuery = NonNullable<paths["/api/v1/investigations"]["get"]["parameters"]["query"]>;
export type AuditListQuery = NonNullable<paths["/api/v1/audit/events"]["get"]["parameters"]["query"]>;


