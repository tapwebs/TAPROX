import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatTile } from "@/components/ui/StatTile";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import { RowTh, Table, Td, Th } from "@/components/ui/Table";
import { SeverityBadge, When, parseId } from "@/features/security/common";
import { ApiError } from "@/lib/api/client";
import type { CaseClassification, CaseSeverity, CaseStatus } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { useRequest } from "@/lib/useRequest";
import { CaseWorkspace } from "./CaseWorkspace";

const PAGE_SIZE = 25;

const CASE_TONE: Record<string, Tone> = {
  open: "neutral",
  active: "info",
  sealed: "warning",
  closed: "success",
};

export function InvestigationsPage({ param }: { param: string | null }) {
  const caseId = parseId(param);
  if (param !== null && caseId === null) {
    return (
      <StateView
        variant="error"
        title="Invalid investigation ID"
        description="Open an investigation from the case registry."
      />
    );
  }
  if (caseId !== null) {
    return <CaseWorkspace caseId={caseId} />;
  }
  return <CaseRegistry />;
}

function CaseRegistry() {
  const { client } = useReadyBackend();
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [classification, setClassification] = useState<CaseClassification>("incident");
  const [severity, setSeverity] = useState<CaseSeverity>("medium");
  const [actor, setActor] = useState("local-operator");
  const [scopeNote, setScopeNote] = useState("Authorized local workstation investigation");
  const [authorized, setAuthorized] = useState(false);
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const debounced = useDebouncedValue(search, 250);
  const [statusFilter, setStatusFilter] = useState<"" | CaseStatus>("");
  const [offset, setOffset] = useState(0);
  const [confirmPurgeId, setConfirmPurgeId] = useState<number | null>(null);

  const list = useRequest(
    (signal) =>
      client.listCases(
        {
          q: debounced.trim() || undefined,
          status: statusFilter || undefined,
          limit: PAGE_SIZE,
          offset,
        },
        signal,
      ),
    [client, debounced, statusFilter, offset],
  );

  const handleCreate = async () => {
    setFormError(null);
    setCreating(true);
    try {
      const created = await client.createCase({
        title: title.trim(),
        summary: summary.trim(),
        classification,
        severity,
        actor: actor.trim() || "local-operator",
        scope_note: scopeNote.trim(),
        confirm_authorized: authorized,
      });
      setTitle("");
      setSummary("");
      setAuthorized(false);
      window.location.hash = `#/investigations/${String(created.id)}`;
    } catch (cause) {
      setFormError(cause instanceof ApiError ? cause.message : "Could not create investigation.");
    } finally {
      setCreating(false);
    }
  };

  const handlePurgeDraft = async (id: number) => {
    try {
      await client.purgeDraftCase(id, actor.trim() || "local-operator");
      setConfirmPurgeId(null);
      list.reload();
    } catch (cause) {
      setFormError(cause instanceof ApiError ? cause.message : "Could not purge draft case.");
    }
  };

  const items = list.data?.items ?? [];

  return (
    <div className="grid gap-4">
      <dl className="grid gap-3 sm:grid-cols-3">
        <StatTile label="Total investigations" value={String(list.data?.total ?? 0)} />
        <StatTile
          label="Open or active"
          value={String(items.filter((i) => i.status === "open" || i.status === "active").length)}
        />
        <StatTile
          label="Sealed or closed"
          value={String(items.filter((i) => i.status === "sealed" || i.status === "closed").length)}
        />
      </dl>

      <Panel
        title="New Investigation Case"
        description="Open a local-first forensic workspace. Evidence-bearing cases are preserved archival-only."
      >
        <div className="grid gap-3">
          <div className="grid gap-3 md:grid-cols-4">
            <div className="md:col-span-2">
              <TextField
                label="Case title"
                value={title}
                placeholder="Unexpected outbound TLS host from workstation"
                onChange={(e) => {
                  setTitle(e.target.value);
                }}
              />
            </div>
            <SelectField
              label="Classification"
              value={classification}
              onChange={(e) => {
                setClassification(e.target.value as CaseClassification);
              }}
            >
              <option value="incident">Incident</option>
              <option value="triage">Triage</option>
              <option value="web_assessment">Web Assessment</option>
              <option value="anomaly_review">Anomaly Review</option>
              <option value="audit">Audit</option>
              <option value="other">Other</option>
            </SelectField>
            <SelectField
              label="Severity"
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value as CaseSeverity);
              }}
            >
              <option value="info">Info</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </SelectField>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <TextField
              label="Operator / Examiner ID"
              value={actor}
              onChange={(e) => {
                setActor(e.target.value);
              }}
            />
            <TextField
              label="Scope / Authorization note"
              value={scopeNote}
              onChange={(e) => {
                setScopeNote(e.target.value);
              }}
            />
          </div>

          <TextField
            label="Initial summary"
            value={summary}
            placeholder="Brief scope or hypothesis statement"
            onChange={(e) => {
              setSummary(e.target.value);
            }}
          />

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3">
            <CheckboxField
              label="I am authorized to open and preserve forensic evidence for this scope"
              checked={authorized}
              onChange={(e) => {
                setAuthorized(e.target.checked);
              }}
            />
            <Button
              variant="primary"
              loading={creating}
              disabled={!authorized || !title.trim()}
              onClick={() => {
                void handleCreate();
              }}
            >
              Create Investigation
            </Button>
          </div>

          {formError && (
            <p role="alert" className="text-sm text-critical">
              {formError}
            </p>
          )}
        </div>
      </Panel>

      <Panel title="Case Registry" description="Isolated investigation workspaces.">
        <div className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-2">
            <TextField
              label="Search case ref, title, or actor"
              value={search}
              placeholder="CASE-2026"
              onChange={(e) => {
                setSearch(e.target.value);
                setOffset(0);
              }}
            />
            <SelectField
              label="Case status"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as "" | CaseStatus);
                setOffset(0);
              }}
            >
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="active">Active</option>
              <option value="sealed">Sealed</option>
              <option value="closed">Closed</option>
            </SelectField>
          </div>

          {list.isLoading && !list.data ? (
            <StateView variant="loading" title="Loading investigations" />
          ) : list.error ? (
            <RequestError error={list.error} what="investigations" onRetry={list.reload} />
          ) : items.length === 0 ? (
            <StateView
              variant="empty"
              title="No investigations recorded"
              description="Open an authorized case above or attach evidence from Alerts, Flows, Devices, Packets, or Web Inspector."
            />
          ) : (
            <>
              <Table label="Investigations list">
                <thead>
                  <tr>
                    <Th>Case Ref</Th>
                    <Th>Title</Th>
                    <Th>Status</Th>
                    <Th>Severity</Th>
                    <Th>Evidence</Th>
                    <Th>Lead</Th>
                    <Th>Updated</Th>
                    <Th>Actions</Th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((c) => {
                    const canPurgeDraft =
                      c.status === "open" && c.evidence_count === 0 && c.custody_head_seq === 0;
                    return (
                      <tr key={c.id}>
                        <RowTh>
                          <a
                            href={`#/investigations/${String(c.id)}`}
                            className="font-mono text-link underline underline-offset-2"
                          >
                            {c.case_ref}
                          </a>
                        </RowTh>
                        <Td>{c.title}</Td>
                        <Td>
                          <StatusBadge tone={CASE_TONE[c.status] ?? "neutral"}>
                            {c.status[0]?.toUpperCase()}{c.status.slice(1)}
                          </StatusBadge>
                        </Td>
                        <Td>
                          <SeverityBadge level={c.severity as CaseSeverity} />
                        </Td>
                        <Td mono>{c.evidence_count}</Td>
                        <Td mono>{c.lead_actor}</Td>
                        <Td><When iso={c.updated_at} /></Td>
                        <Td>
                          {canPurgeDraft ? (
                            confirmPurgeId === c.id ? (
                              <div className="flex gap-1">
                                <Button
                                  className="h-7 px-2 text-xs"
                                  variant="primary"
                                  onClick={() => {
                                    void handlePurgeDraft(c.id);
                                  }}
                                >
                                  Confirm purge
                                </Button>
                                <Button
                                  className="h-7 px-2 text-xs"
                                  onClick={() => {
                                    setConfirmPurgeId(null);
                                  }}
                                >
                                  Cancel
                                </Button>
                              </div>
                            ) : (
                              <Button
                                className="h-7 px-2 text-xs"
                                onClick={() => {
                                  setConfirmPurgeId(c.id);
                                }}
                              >
                                Purge draft…
                              </Button>
                            )
                          ) : (
                            <span className="text-xs text-fg-subtle">Archival</span>
                          )}
                        </Td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
              {list.data && (
                <Pagination
                  label="Investigations pages"
                  total={list.data.total}
                  limit={list.data.limit}
                  offset={list.data.offset}
                  onChange={setOffset}
                />
              )}
            </>
          )}
        </div>
      </Panel>
    </div>
  );
}
