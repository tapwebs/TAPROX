import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { DetailPanel } from "@/components/ui/DetailPanel";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatTile } from "@/components/ui/StatTile";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import { RowTh, Table, Td, Th } from "@/components/ui/Table";
import {
  BasisBadge,
  ConfidenceChip,
  SeverityBadge,
  When,
} from "@/features/security/common";
import { ApiError } from "@/lib/api/client";
import type {
  CaseIntegrityVerdict,
  CaseSeverity,
  ExportFormat,
  NoteKind,
} from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useRequest } from "@/lib/useRequest";

type TabId =
  | "overview"
  | "evidence"
  | "timeline"
  | "correlations"
  | "notes"
  | "custody"
  | "export";

const ALLOWED_TABS: readonly TabId[] = [
  "overview",
  "evidence",
  "timeline",
  "correlations",
  "notes",
  "custody",
  "export",
];

const CASE_STATUS_TONE: Record<string, Tone> = {
  open: "neutral",
  active: "info",
  sealed: "warning",
  closed: "success",
};

const INTEGRITY_TONE: Record<string, Tone> = {
  verified: "success",
  mismatch: "critical",
  missing_external: "critical",
  unverified: "warning",
};

function initialTabFromHash(): TabId {
  const hash = window.location.hash;
  const idx = hash.indexOf("?");
  if (idx === -1) return "overview";
  const tab = new URLSearchParams(hash.slice(idx + 1)).get("tab");
  return ALLOWED_TABS.find((t) => t === tab) ?? "overview";
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 500);
}

export function CaseWorkspace({ caseId }: { caseId: number }) {
  const { client } = useReadyBackend();
  const [tab, setTab] = useState<TabId>(initialTabFromHash);
  const [actor, setActor] = useState("local-operator");
  const [actionError, setActionError] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<CaseIntegrityVerdict | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Case transitions
  const [transitionTarget, setTransitionTarget] = useState<"" | "sealed" | "closed" | "active">("");
  const [transitionReason, setTransitionReason] = useState("");
  const [transitioning, setTransitioning] = useState(false);

  // Evidence viewer & PCAPNG attach
  const [selectedEvId, setSelectedEvId] = useState<number | null>(null);
  const [pcapPath, setPcapPath] = useState("");
  const [pcapVaultCopy, setPcapVaultCopy] = useState(true);
  const [pcapAuth, setPcapAuth] = useState(false);
  const [attaching, setAttaching] = useState(false);

  // Timeline filters
  const [basisFilter, setBasisFilter] = useState("");

  // Notes composer
  const [noteKind, setNoteKind] = useState<NoteKind>("observation");
  const [noteConfidence, setNoteConfidence] = useState<"low" | "medium" | "high">("medium");
  const [noteTitle, setNoteTitle] = useState("");
  const [noteBody, setNoteBody] = useState("");
  const [supersedesId, setSupersedesId] = useState<number | null>(null);
  const [savingNote, setSavingNote] = useState(false);

  // Correlations
  const [correlating, setCorrelating] = useState(false);

  // Exports
  const [exportFmt, setExportFmt] = useState<ExportFormat>("markdown");
  const [includeVault, setIncludeVault] = useState(false);
  const [exporting, setExporting] = useState(false);

  const caseReq = useRequest((s) => client.getCase(caseId, s), [client, caseId]);
  const evReq = useRequest((s) => client.listCaseEvidence(caseId, s), [client, caseId]);
  const tlReq = useRequest((s) => client.getCaseTimeline(caseId, s), [client, caseId]);
  const corrReq = useRequest((s) => client.listCaseCorrelations(caseId, s), [client, caseId]);
  const notesReq = useRequest((s) => client.listCaseNotes(caseId, s), [client, caseId]);
  const custodyReq = useRequest((s) => client.listCaseCustody(caseId, s), [client, caseId]);
  const exportsReq = useRequest((s) => client.listCaseExports(caseId, s), [client, caseId]);
  const evDetailReq = useRequest(
    (s) =>
      selectedEvId === null
        ? Promise.resolve(null)
        : client.getCaseEvidence(caseId, selectedEvId, s),
    [client, caseId, selectedEvId],
  );

  const reloadAll = () => {
    caseReq.reload();
    evReq.reload();
    tlReq.reload();
    corrReq.reload();
    notesReq.reload();
    custodyReq.reload();
    exportsReq.reload();
  };

  if (caseReq.isLoading && !caseReq.data) {
    return <StateView variant="loading" title="Loading investigation" />;
  }
  if (!caseReq.data) {
    return caseReq.error ? (
      <RequestError error={caseReq.error} what="investigation" onRetry={caseReq.reload} />
    ) : null;
  }

  const c = caseReq.data;
  const isLocked = c.status === "sealed" || c.status === "closed";
  const evidenceItems = evReq.data?.items ?? [];
  const timelineItems = tlReq.data?.items ?? [];
  const correlations = corrReq.data?.items ?? [];
  const notes = notesReq.data?.items ?? [];
  const custodyEvents = custodyReq.data?.items ?? [];
  const exportsList = exportsReq.data?.items ?? [];

  const anyMismatch =
    verdict?.all_verified === false ||
    evidenceItems.some((e) => e.integrity_status !== "verified");

  const handleVerify = async () => {
    setActionError(null);
    setVerifying(true);
    try {
      const res = await client.verifyCaseIntegrity(c.id, actor.trim() || "local-operator");
      setVerdict(res);
      setStatusNotice(
        res.all_verified
          ? `Integrity verified across ${String(res.evidence_results.length)} artifact(s) and ${String(res.chain_checked_links)} custody link(s).`
          : "Integrity mismatch detected! Review Evidence & Chain of Custody immediately.",
      );
      reloadAll();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : "Verification failed.");
    } finally {
      setVerifying(false);
    }
  };

  const handleTransition = async () => {
    if (!transitionTarget || !transitionReason.trim()) return;
    setActionError(null);
    setTransitioning(true);
    try {
      await client.updateCaseStatus(c.id, {
        target_status: transitionTarget,
        reason: transitionReason.trim(),
        actor: actor.trim() || "local-operator",
        confirm_action: true,
      });
      setTransitionTarget("");
      setTransitionReason("");
      setStatusNotice(`Case transitioned to ${transitionTarget}.`);
      reloadAll();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : "Status update failed.");
    } finally {
      setTransitioning(false);
    }
  };

  const handleAttachPcap = async () => {
    setActionError(null);
    setAttaching(true);
    try {
      await client.attachCaseEvidence(c.id, {
        kind: "pcapng_file",
        source_path: pcapPath.trim(),
        vault_copy: pcapVaultCopy,
        actor: actor.trim() || "local-operator",
        confirm_action: pcapAuth,
      });
      setPcapPath("");
      setPcapAuth(false);
      setStatusNotice("PCAPNG capture attached with SHA-256 verification.");
      reloadAll();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : "Failed to attach PCAPNG.");
    } finally {
      setAttaching(false);
    }
  };

  const handleCorrelate = async () => {
    setActionError(null);
    setCorrelating(true);
    try {
      const res = await client.runCaseCorrelations(c.id, actor.trim() || "local-operator");
      setStatusNotice(`Deterministic correlation completed (${String(res.items.length)} indicator link(s)).`);
      reloadAll();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : "Correlation failed.");
    } finally {
      setCorrelating(false);
    }
  };

  const handleAddNote = async () => {
    setActionError(null);
    setSavingNote(true);
    try {
      await client.addCaseNote(c.id, {
        note_kind: noteKind,
        confidence: noteConfidence,
        title: noteTitle.trim(),
        body: noteBody.trim(),
        cited_evidence_ids: [],
        supersedes_note_id: supersedesId,
        actor: actor.trim() || "local-operator",
      });
      setNoteTitle("");
      setNoteBody("");
      setSupersedesId(null);
      setStatusNotice("Immutable forensic note appended to custody chain.");
      reloadAll();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : "Could not append note.");
    } finally {
      setSavingNote(false);
    }
  };

  const handleExport = async () => {
    setActionError(null);
    setExporting(true);
    try {
      const created = await client.exportCase(c.id, {
        format: exportFmt,
        include_vault_files: exportFmt === "zip_bundle" && includeVault,
        actor: actor.trim() || "local-operator",
      });
      const blob = await client.downloadCaseExport(c.id, created.id);
      const ext = exportFmt === "markdown" ? "md" : exportFmt === "json_dossier" ? "json" : "zip";
      downloadBlob(blob, `${c.case_ref}_${created.export_ref}.${ext}`);
      setStatusNotice(`Exported ${created.export_ref} (SHA-256: ${created.bundle_sha256}).`);
      reloadAll();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : "Export failed.");
    } finally {
      setExporting(false);
    }
  };

  const filteredTimeline = basisFilter
    ? timelineItems.filter((t) => t.epistemic_basis === basisFilter)
    : timelineItems;

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <a href="#/investigations" className="text-sm text-link underline underline-offset-2">
          Back to investigations
        </a>
        <div className="w-56">
          <TextField
            label="Active operator ID"
            value={actor}
            onChange={(e) => {
              setActor(e.target.value);
            }}
          />
        </div>
      </div>

      {anyMismatch && (
        <div
          role="alert"
          className="rounded-md border border-critical bg-inset px-4 py-3 text-sm text-critical"
        >
          Tamper or missing-file mismatch detected in this investigation. Original hashes no longer match all stored items—review Evidence and Chain of Custody.
        </div>
      )}

      {isLocked && (
        <div
          role="status"
          className="rounded-md border border-warning bg-inset px-4 py-2.5 text-sm text-warning"
        >
          This case is <strong>{c.status}</strong>. Evidence acquisition, correlation runs, and note additions are locked until reopened with a recorded custody reason.
        </div>
      )}

      <Panel
        title={`${c.case_ref}: ${c.title}`}
        description={`Lead: ${c.lead_actor} · Scope: ${c.scope_note}`}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              className="h-7 px-2.5 text-xs"
              variant="primary"
              loading={verifying}
              onClick={() => {
                void handleVerify();
              }}
            >
              Verify Integrity
            </Button>
            {c.status === "open" || c.status === "active" ? (
              <Button
                className="h-7 px-2.5 text-xs"
                onClick={() => {
                  setTransitionTarget("sealed");
                }}
              >
                Seal Case…
              </Button>
            ) : (
              <Button
                className="h-7 px-2.5 text-xs"
                onClick={() => {
                  setTransitionTarget("active");
                }}
              >
                Reopen Case…
              </Button>
            )}
            {c.status !== "closed" && (
              <Button
                className="h-7 px-2.5 text-xs"
                onClick={() => {
                  setTransitionTarget("closed");
                }}
              >
                Close Case…
              </Button>
            )}
          </div>
        }
      >
        <div className="grid gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge tone={CASE_STATUS_TONE[c.status] ?? "neutral"}>
              {c.status[0]?.toUpperCase()}{c.status.slice(1)}
            </StatusBadge>
            <SeverityBadge level={c.severity as CaseSeverity} />
            <span className="font-mono text-xs text-fg-muted">
              Custody Head: Seq #{String(c.custody_head_seq)} · {c.custody_head_sha256.slice(0, 16)}…
            </span>
          </div>

          {transitionTarget && (
            <div className="grid gap-3 rounded-md border border-line-strong bg-inset p-3">
              <p className="text-sm text-fg">
                Confirm transition to <strong>{transitionTarget}</strong> (recorded in custody ledger & audit log):
              </p>
              <TextField
                label="Custody reason (required)"
                value={transitionReason}
                placeholder="e.g. Investigation complete and bundle exported"
                onChange={(e) => {
                  setTransitionReason(e.target.value);
                }}
              />
              <div className="flex gap-2">
                <Button
                  variant="primary"
                  loading={transitioning}
                  disabled={!transitionReason.trim()}
                  onClick={() => {
                    void handleTransition();
                  }}
                >
                  Confirm {transitionTarget}
                </Button>
                <Button
                  onClick={() => {
                    setTransitionTarget("");
                    setTransitionReason("");
                  }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {statusNotice && (
            <p role="status" className="text-xs text-fg-muted">
              {statusNotice}
            </p>
          )}
          {actionError && (
            <p role="alert" className="text-sm text-critical">
              {actionError}
            </p>
          )}

          <div className="flex flex-wrap gap-2 border-t border-line pt-3">
            {(
              [
                ["overview", "Overview"],
                ["evidence", `Evidence (${String(evidenceItems.length)})`],
                ["timeline", `Timeline (${String(timelineItems.length)})`],
                ["correlations", `Correlations (${String(correlations.length)})`],
                ["notes", `Forensic Notes (${String(notes.length)})`],
                ["custody", `Chain of Custody (${String(custodyEvents.length)})`],
                ["export", "Export Report"],
              ] as const
            ).map(([id, label]) => (
              <Button
                key={id}
                className="h-7 px-2.5 text-xs"
                aria-pressed={tab === id}
                variant={tab === id ? "primary" : "secondary"}
                onClick={() => {
                  setTab(id);
                }}
              >
                {label}
              </Button>
            ))}
          </div>

          {tab === "overview" && (
            <div className="grid gap-4">
              <dl className="grid gap-3 sm:grid-cols-4">
                <StatTile label="Evidence items" value={String(c.evidence_count)} />
                <StatTile label="Timeline events" value={String(timelineItems.length)} />
                <StatTile label="Inferred correlations" value={String(correlations.length)} />
                <StatTile label="Custody links" value={String(c.custody_head_seq)} />
              </dl>
              <DefinitionList
                items={[
                  { label: "Case UID", value: c.case_uid, mono: true },
                  { label: "Classification", value: c.classification },
                  { label: "Summary", value: c.summary || "—" },
                  { label: "Created", value: <When iso={c.created_at} /> },
                  ...(c.closure_reason ? [{ label: "Custody transition note", value: c.closure_reason }] : []),
                ]}
              />
              <p className="rounded-md border border-line bg-inset px-3 py-2 text-xs text-fg-muted">
                Local-first integrity note: SQLite SHA-256 chains verify snapshot and vaulted artifact consistency offline, but cannot defeat an attacker with full OS or database administrator access unless exported manifest digests are stored independently.
              </p>
            </div>
          )}

          {tab === "evidence" && (
            <div className="grid gap-4">
              {!isLocked && (
                <div className="grid gap-3 rounded-md border border-line bg-inset p-3">
                  <h3 className="text-xs font-semibold text-fg">Acquire Local PCAPNG Capture</h3>
                  <div className="grid gap-2 md:grid-cols-[1fr_auto]">
                    <TextField
                      label="Absolute .pcapng path"
                      value={pcapPath}
                      placeholder="C:\Captures\incident.pcapng"
                      onChange={(e) => {
                        setPcapPath(e.target.value);
                      }}
                    />
                    <div className="flex items-end">
                      <Button
                        variant="primary"
                        loading={attaching}
                        disabled={!pcapPath.trim() || !pcapAuth}
                        onClick={() => {
                          void handleAttachPcap();
                        }}
                      >
                        Acquire PCAPNG
                      </Button>
                    </div>
                  </div>
                  <div className="grid gap-1 md:grid-cols-2">
                    <CheckboxField
                      label="Copy read-only into case vault (512 MiB/file cap)"
                      checked={pcapVaultCopy}
                      onChange={(e) => {
                        setPcapVaultCopy(e.target.checked);
                      }}
                    />
                    <CheckboxField
                      label="Confirm authorized local PCAPNG acquisition"
                      checked={pcapAuth}
                      onChange={(e) => {
                        setPcapAuth(e.target.checked);
                      }}
                    />
                  </div>
                </div>
              )}

              {evidenceItems.length === 0 ? (
                <StateView
                  variant="empty"
                  title="No evidence attached"
                  description="Attach alerts, flows, devices, web inspections, or PCAPNG captures using the drawers on those screens or the PCAPNG form above."
                />
              ) : (
                <Table label="Case evidence">
                  <thead>
                    <tr>
                      <Th>Ref</Th>
                      <Th>Kind</Th>
                      <Th>Basis</Th>
                      <Th>Preservation</Th>
                      <Th>SHA-256</Th>
                      <Th>Integrity</Th>
                      <Th>Title</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidenceItems.map((ev) => (
                      <tr key={ev.id}>
                        <RowTh>
                          <button
                            type="button"
                            className="cursor-pointer font-mono text-link underline underline-offset-2"
                            onClick={() => {
                              setSelectedEvId(ev.id);
                            }}
                          >
                            {ev.evidence_ref}
                          </button>
                        </RowTh>
                        <Td mono>{ev.artifact_kind}</Td>
                        <Td>
                          <BasisBadge basis={ev.epistemic_basis} />
                        </Td>
                        <Td mono>{ev.storage_mode}</Td>
                        <Td mono>{ev.content_sha256.slice(0, 14)}…</Td>
                        <Td>
                          <StatusBadge tone={INTEGRITY_TONE[ev.integrity_status] ?? "neutral"}>
                            {ev.integrity_status}
                          </StatusBadge>
                        </Td>
                        <Td>{ev.title}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}

              {selectedEvId !== null && (
                <DetailPanel
                  title={evDetailReq.data?.evidence_ref ?? "Evidence Detail"}
                  onClose={() => {
                    setSelectedEvId(null);
                  }}
                >
                  {evDetailReq.isLoading && <StateView variant="loading" title="Loading snapshot" />}
                  {evDetailReq.data && (
                    <div className="grid gap-3">
                      <DefinitionList
                        items={[
                          { label: "SHA-256", value: evDetailReq.data.content_sha256, mono: true },
                          { label: "Storage mode", value: evDetailReq.data.storage_mode, mono: true },
                          { label: "Acquired by", value: evDetailReq.data.acquired_by, mono: true },
                          { label: "Source", value: `${evDetailReq.data.source_table ?? "file"} #${evDetailReq.data.source_record_id ?? "—"}`, mono: true },
                        ]}
                      />
                      <h4 className="text-xs font-medium text-fg-muted">Immutable Snapshot (JSON)</h4>
                      <pre className="max-h-80 overflow-auto rounded-md border border-line bg-inset p-3 font-mono text-xs text-fg">
                        {JSON.stringify(evDetailReq.data.snapshot, null, 2)}
                      </pre>
                    </div>
                  )}
                </DetailPanel>
              )}
            </div>
          )}

          {tab === "timeline" && (
            <div className="grid gap-3">
              <div className="w-60">
                <SelectField
                  label="Epistemic basis filter"
                  value={basisFilter}
                  onChange={(e) => {
                    setBasisFilter(e.target.value);
                  }}
                >
                  <option value="">All bases</option>
                  <option value="observed">Observed</option>
                  <option value="inventory">Inventory</option>
                  <option value="analyst_note">Analyst Note</option>
                </SelectField>
              </div>
              {filteredTimeline.length === 0 ? (
                <StateView
                  variant="empty"
                  title="No timeline events"
                  description="Attach case evidence or notes to reconstruct a chronological sequence."
                />
              ) : (
                <Table label="Reconstructed timeline">
                  <thead>
                    <tr>
                      <Th>UTC Timestamp</Th>
                      <Th>Clock Source</Th>
                      <Th>Basis</Th>
                      <Th>Ref</Th>
                      <Th>Title</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTimeline.map((item, idx) => (
                      <tr key={`${item.ref}-${String(idx)}`}>
                        <Td mono>{item.timestamp_utc}</Td>
                        <Td mono>{item.time_source}</Td>
                        <Td>{item.epistemic_basis}</Td>
                        <Td mono>{item.ref}</Td>
                        <Td>{item.title}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </div>
          )}

          {tab === "correlations" && (
            <div className="grid gap-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs text-fg-muted">
                  Deterministic rule-based correlations across evidence inside this case (inferred).
                </p>
                <Button
                  variant="primary"
                  className="h-7 px-2.5 text-xs"
                  disabled={isLocked}
                  loading={correlating}
                  onClick={() => {
                    void handleCorrelate();
                  }}
                >
                  Run Deterministic Correlation
                </Button>
              </div>
              {correlations.length === 0 ? (
                <StateView
                  variant="empty"
                  title="No correlations computed"
                  description="Attach at least two related evidence items and run deterministic correlation."
                />
              ) : (
                <div className="grid gap-3">
                  {correlations.map((corr) => (
                    <div key={corr.id} className="grid gap-2 rounded-md border border-line bg-inset p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <ConfidenceChip level={corr.confidence as "low" | "medium" | "high"} />
                        <BasisBadge basis={corr.epistemic_basis} />
                        <span className="font-mono text-xs text-fg-subtle">{corr.rule_id}</span>
                      </div>
                      <h4 className="text-sm font-semibold text-fg">{corr.summary}</h4>
                      <p className="text-sm text-fg-muted">{corr.rationale}</p>
                      <p className="text-xs text-fg-subtle">
                        Limitations: {corr.limitations.join(" · ")}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === "notes" && (
            <div className="grid gap-4">
              {!isLocked && (
                <div className="grid gap-3 rounded-md border border-line bg-inset p-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-fg">
                      {supersedesId ? `Append revision superseding note #${String(supersedesId)}` : "Append Immutable Forensic Note"}
                    </h3>
                    {supersedesId && (
                      <Button
                        className="h-6 px-2 text-xs"
                        onClick={() => {
                          setSupersedesId(null);
                        }}
                      >
                        Clear revision link
                      </Button>
                    )}
                  </div>
                  <div className="grid gap-3 md:grid-cols-3">
                    <TextField
                      label="Note title"
                      value={noteTitle}
                      onChange={(e) => {
                        setNoteTitle(e.target.value);
                      }}
                    />
                    <SelectField
                      label="Note kind"
                      value={noteKind}
                      onChange={(e) => {
                        setNoteKind(e.target.value as NoteKind);
                      }}
                    >
                      <option value="observation">Observation</option>
                      <option value="hypothesis">Hypothesis</option>
                      <option value="correlation_review">Correlation review</option>
                      <option value="conclusion">Conclusion</option>
                      <option value="limitation">Limitation</option>
                    </SelectField>
                    <SelectField
                      label="Confidence"
                      value={noteConfidence}
                      onChange={(e) => {
                        setNoteConfidence(e.target.value as "low" | "medium" | "high");
                      }}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </SelectField>
                  </div>
                  <label className="grid gap-1 text-xs font-medium text-fg-muted">
                    <span>Forensic note body (append-only, hashed into custody)</span>
                    <textarea
                      rows={3}
                      value={noteBody}
                      onChange={(e) => {
                        setNoteBody(e.target.value);
                      }}
                      className="rounded-md border border-line-strong bg-canvas px-3 py-2 text-sm text-fg"
                    />
                  </label>
                  <div className="flex justify-end">
                    <Button
                      variant="primary"
                      loading={savingNote}
                      disabled={!noteTitle.trim() || !noteBody.trim()}
                      onClick={() => {
                        void handleAddNote();
                      }}
                    >
                      Append Note
                    </Button>
                  </div>
                </div>
              )}

              {notes.length === 0 ? (
                <StateView
                  variant="empty"
                  title="No forensic notes"
                  description="Notes are recorded as append-only revisions inside the custody chain."
                />
              ) : (
                <div className="grid gap-3">
                  {notes.map((n) => (
                    <div key={n.id} className="grid gap-2 rounded-md border border-line bg-inset p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs text-fg-subtle">{n.note_ref}</span>
                          <ConfidenceChip level={n.confidence as "low" | "medium" | "high"} />
                          {n.supersedes_note_id && (
                            <span className="text-xs text-warning">
                              Supersedes #{String(n.supersedes_note_id)}
                            </span>
                          )}
                        </div>
                        {!isLocked && (
                          <Button
                            className="h-6 px-2 text-xs"
                            onClick={() => {
                              setSupersedesId(n.id);
                              setNoteTitle(n.title);
                            }}
                          >
                            Append Revision
                          </Button>
                        )}
                      </div>
                      <h4 className="text-sm font-semibold text-fg">{n.title}</h4>
                      <p className="whitespace-pre-wrap text-sm text-fg-muted">{n.body}</p>
                      <p className="font-mono text-[11px] text-fg-subtle">
                        {n.actor} · <When iso={n.created_at} /> · SHA-256: {n.content_sha256.slice(0, 16)}…
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === "custody" && (
            <div className="grid gap-3">
              {custodyEvents.length === 0 ? (
                <StateView
                  variant="empty"
                  title="No custody events yet"
                  description="Attaching evidence, adding notes, or sealing starts the append-only SHA-256 chain."
                />
              ) : (
                <Table label="Chain of custody ledger">
                  <thead>
                    <tr>
                      <Th>Seq</Th>
                      <Th>Timestamp</Th>
                      <Th>Actor</Th>
                      <Th>Action</Th>
                      <Th>Prev Hash</Th>
                      <Th>Event Hash</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {custodyEvents.map((cu) => (
                      <tr key={cu.id}>
                        <Td mono>{cu.seq}</Td>
                        <Td><When iso={cu.occurred_at} /></Td>
                        <Td mono>{cu.actor}</Td>
                        <Td mono>{cu.action}</Td>
                        <Td mono>{cu.prev_event_sha256.slice(0, 12)}…</Td>
                        <Td mono>{cu.event_sha256.slice(0, 12)}…</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </div>
          )}

          {tab === "export" && (
            <div className="grid gap-4">
              <div className="grid gap-3 rounded-md border border-line bg-inset p-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <SelectField
                    label="Report format"
                    value={exportFmt}
                    onChange={(e) => {
                      setExportFmt(e.target.value as ExportFormat);
                    }}
                  >
                    <option value="markdown">Markdown Report (.md)</option>
                    <option value="json_dossier">Canonical JSON Dossier (.json)</option>
                    <option value="zip_bundle">Verifiable ZIP Bundle (.zip + manifest.sha256)</option>
                  </SelectField>
                  {exportFmt === "zip_bundle" && (
                    <div className="flex items-end">
                      <CheckboxField
                        label="Include vaulted PCAPNG artifacts in ZIP"
                        checked={includeVault}
                        onChange={(e) => {
                          setIncludeVault(e.target.checked);
                        }}
                      />
                    </div>
                  )}
                </div>
                <div className="flex justify-end">
                  <Button
                    variant="primary"
                    loading={exporting}
                    onClick={() => {
                      void handleExport();
                    }}
                  >
                    Generate & Download Export
                  </Button>
                </div>
              </div>

              {exportsList.length > 0 && (
                <Table label="Case export history">
                  <thead>
                    <tr>
                      <Th>Ref</Th>
                      <Th>Format</Th>
                      <Th>Custody Seq</Th>
                      <Th>Bundle SHA-256</Th>
                      <Th>Created</Th>
                      <Th>Download</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {exportsList.map((ex) => (
                      <tr key={ex.id}>
                        <RowTh>{ex.export_ref}</RowTh>
                        <Td mono>{ex.format}</Td>
                        <Td mono>{ex.custody_head_seq}</Td>
                        <Td mono>{ex.bundle_sha256.slice(0, 16)}…</Td>
                        <Td><When iso={ex.created_at} /></Td>
                        <Td>
                          <Button
                            className="h-7 px-2 text-xs"
                            onClick={() => {
                              void client.downloadCaseExport(c.id, ex.id).then((blob) => {
                                const ext =
                                  ex.format === "markdown"
                                    ? "md"
                                    : ex.format === "json_dossier"
                                      ? "json"
                                      : "zip";
                                downloadBlob(blob, `${c.case_ref}_${ex.export_ref}.${ext}`);
                              });
                            }}
                          >
                            Download
                          </Button>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
