import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { SelectField, TextField } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { Table, Td, Th } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import type { AlertStatus } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useRequest } from "@/lib/useRequest";
import { packetFilterFor } from "./packetFilter";
import { buildWebInspectorHref } from "@/features/web_inspector/prefill";
import { AttachToCasePanel } from "@/features/investigations/AttachToCaseModal";
import {
  BasisBadge,
  ConfidenceChip,
  Footnote,
  RISK_NOTE,
  RiskScore,
  STATUSES,
  SeverityBadge,
  StatusTag,
  When,
  parseId,
  statusLabel,
} from "./common";

function describe(error: unknown): string {
  return error instanceof ApiError ? error.message : "The change could not be saved.";
}

export function AlertDetailPage({ param }: { param: string | null }) {
  const { client } = useReadyBackend();
  const id = parseId(param);
  const alert = useRequest(
    (signal) => (id === null ? Promise.reject(new ApiError(422, "invalid_id", "This is not a valid alert number.")) : client.getAlert(id, signal)),
    [client, id],
  );
  const events = useRequest(
    (signal) => (id === null ? Promise.resolve(null) : client.getAlertEvents(id, { limit: 50 }, signal)),
    [client, id],
  );
  const [status, setStatus] = useState<AlertStatus | "">("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [asking, setAsking] = useState(false);
  const [suppressed, setSuppressed] = useState(false);
  const [copied, setCopied] = useState<"yes" | "no" | null>(null);
  const [attachOpen, setAttachOpen] = useState(false);
  if (id === null) return <StateView variant="error" title="This is not a valid alert number" description="Open an alert from the list." />;
  if (alert.isLoading) return <StateView variant="loading" title="Loading alert" />;
  if (!alert.data) {
    return alert.error ? <RequestError error={alert.error} what="the alert" onRetry={alert.reload} /> : null;
  }
  const a = alert.data;
  const chosen = status || a.status;
  const filter = packetFilterFor(a);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(filter ?? "");
      setCopied("yes");
    } catch {
      setCopied("no"); // the field stays selectable, so the text can still be copied by hand
    }
  };
  const save = async () => {
    setSaving(true);
    setProblem(null);
    setMessage(null);
    try {
      await client.patchAlert(a.id, {
        status: chosen === a.status ? undefined : chosen,
        note: note.trim() || undefined,
      });
      setNote("");
      setStatus("");
      setMessage("Saved.");
      alert.reload();
      events.reload();
    } catch (cause) {
      setProblem(describe(cause));
    } finally {
      setSaving(false);
    }
  };
  const suppress = async () => {
    setProblem(null);
    try {
      await client.putSuppression({
        rule_id: a.rule_id,
        entity_kind: a.entity_kind as "ip" | "mac" | "device" | "domain" | "network",
        entity_key: a.entity_key,
        reason: reason.trim(),
      });
      setSuppressed(true);
      setAsking(false);
    } catch (cause) {
      setProblem(describe(cause));
    }
  };

  return (
    <div className="grid gap-4">
      <a href="#/alerts" className="text-sm text-link underline underline-offset-2">
        Back to alerts
      </a>
      <Panel
        title={a.title}
        description={`${a.rule_id} · version ${String(a.rule_version)} · ${a.category}`}
        actions={
          <Button
            className="h-7 px-2.5 text-xs"
            onClick={() => {
              setAttachOpen(true);
            }}
          >
            Attach to Investigation…
          </Button>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <SeverityBadge level={a.severity} />
          <ConfidenceChip level={a.confidence} />
          <span className="text-sm text-fg-muted">
            Risk <RiskScore value={a.risk_score} />
          </span>
          <StatusTag status={a.status} />
        </div>
        <p className="text-sm text-fg">{a.summary}</p>
        <p className="mt-2 text-sm text-fg-muted">{a.why}</p>
        <div className="mt-4">
          <DefinitionList
            items={[
              { label: "About", value: `${a.entity_key}${a.secondary_key ? ` → ${a.secondary_key}` : ""}`, mono: true },
              { label: "Observed", value: <><When iso={a.observed_start} file={a.source === "file"} /> to <When iso={a.observed_end} /></> },
              { label: "Seen", value: `${String(a.occurrence_count)} time(s); returned in ${String(a.recurrence_count)} earlier episode(s)` },
              { label: "Source", value: a.source === "file" ? "An opened capture file" : "A live capture" },
              ...(a.entity_device_id !== null
                ? [{ label: "Device", value: <a className="text-link underline underline-offset-2" href={`#/risk/${String(a.entity_device_id)}`}>Risk profile of device {String(a.entity_device_id)}</a> }]
                : []),
              ...(() => {
                const candidateHost =
                  a.entity_kind === "domain"
                    ? a.entity_key
                    : typeof a.observed.http_host === "string"
                      ? a.observed.http_host
                      : typeof a.observed.sni === "string"
                        ? a.observed.sni
                        : null;
                const href = buildWebInspectorHref(candidateHost, {
                  alertId: a.id,
                  deviceId: a.entity_device_id,
                });
                return href
                  ? [
                      {
                        label: "Web Inspector",
                        value: (
                          <a className="text-link underline underline-offset-2" href={href}>
                            Inspect in Web Inspector
                          </a>
                        ),
                      },
                    ]
                  : [];
              })(),
            ]}
          />
        </div>
      </Panel>

      {attachOpen && (
        <AttachToCasePanel
          target={{ kind: "alert", sourceId: a.id, label: `Alert #${String(a.id)}: ${a.rule_id} — ${a.title}` }}
          onClose={() => {
            setAttachOpen(false);
          }}
        />
      )}

      <Panel title="What was observed" description="Each line says whether it was seen, inferred or taken from the inventory.">
        <ol className="grid gap-2">
          {a.evidence.map((e) => (
            <li key={e.seq} className="rounded-md border border-line bg-inset px-3 py-2 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <BasisBadge basis={e.basis} />
                {e.observed_at !== null && <span className="text-xs text-fg-subtle">{new Date(e.observed_at * 1000).toLocaleString()}</span>}
              </div>
              <p className="mt-1 break-words text-fg">{e.text}</p>
              {Object.keys(e.data).length > 0 && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-xs text-fg-muted">Details</summary>
                  <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs text-fg-muted">{JSON.stringify(e.data, null, 2)}</pre>
                </details>
              )}
            </li>
          ))}
        </ol>
        {a.evidence_dropped > 0 && <Footnote>{String(a.evidence_dropped)} further evidence items were counted but not kept.</Footnote>}
      </Panel>

      {filter && (
        <Panel title="Find these packets" description="A display filter for the Packet Explorer, built from the addresses and port of this alert.">
          <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
            <TextField label="Display filter" readOnly value={filter} className="font-mono" onFocus={(e) => { e.currentTarget.select(); }} />
            <div className="flex gap-2">
              <Button onClick={() => { void copy(); }}>Copy filter</Button>
              <a href="#/packets" className="inline-flex h-8 items-center rounded-md border border-line-strong bg-raised px-3 text-sm text-fg hover:bg-line">Open Packet Explorer</a>
            </div>
          </div>
          <div role="status" className="mt-2 text-sm text-fg-muted">{copied === "yes" ? "Copied." : copied === "no" ? "Could not copy; select the filter and copy it." : ""}</div>
          <Footnote>
            Paste it into the display filter of the Packet Explorer. It finds packets of the capture or file that is open now; the packets themselves are not stored with the alert{a.source === "file" ? ", so open the same file again" : ", so save the capture if you want to keep them"}.
          </Footnote>
        </Panel>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="What else it could be">
          <ul className="list-disc pl-5 text-sm">
            {a.benign_explanations.map((t) => (<li key={t}>{t}</li>))}
          </ul>
        </Panel>
        <Panel title="What this rule cannot see">
          <ul className="list-disc pl-5 text-sm">
            {a.blind_spots.map((t) => (<li key={t}>{t}</li>))}
          </ul>
        </Panel>
      </div>

      <Panel title="How the score was made" description={a.risk.explanation}>
        <Table label="Score factors">
          <thead><tr><Th>Factor</Th><Th>Change</Th><Th>Reason</Th></tr></thead>
          <tbody>
            {a.risk.factors.map((f) => (
              <tr key={f.name}><Td>{f.name}</Td><Td mono>{f.pct > 0 ? `+${String(f.pct)}` : String(f.pct)}%</Td><Td>{f.reason}</Td></tr>
            ))}
            <tr><Td>Severity and confidence</Td><Td mono>{a.risk.severity_pct}% × {a.risk.confidence_pct}%</Td><Td>Context multiplier {a.risk.multiplier_pct}%; result {a.risk.value}</Td></tr>
          </tbody>
        </Table>
        <Footnote>{RISK_NOTE}</Footnote>
      </Panel>

      <Panel title="Decide">
        <div className="grid gap-3 md:grid-cols-[14rem_1fr_auto] md:items-end">
          <SelectField label="Status" value={chosen} onChange={(e) => { setStatus(e.target.value as AlertStatus); }}>
            {STATUSES.map((s) => (<option key={s} value={s}>{statusLabel(s)}</option>))}
          </SelectField>
          <TextField label="Note" value={note} maxLength={500} onChange={(e) => { setNote(e.target.value); }} hint="Plain text, up to 500 characters." />
          <Button variant="primary" loading={saving} onClick={() => { void save(); }}>Save</Button>
        </div>
        <div role="status" className="mt-2 text-sm text-fg-muted">{message}</div>
        {problem && <p role="alert" className="mt-2 text-sm text-critical">{problem}</p>}
        <div className="mt-4 border-t border-line pt-3">
          {suppressed ? (
            <p role="status" className="text-sm text-fg-muted">
              {a.rule_id} will not raise alerts for {a.entity_key} from the next analysed session. Remove it under Detection Rules.
            </p>
          ) : asking ? (
            <div className="grid gap-2 rounded-md border border-line-strong p-3">
              <p className="text-sm text-fg">Stop {a.rule_id} from alerting about {a.entity_key}? Findings will still be counted.</p>
              <TextField label="Reason" value={reason} maxLength={300} onChange={(e) => { setReason(e.target.value); }} />
              <div className="flex gap-2">
                <Button variant="primary" disabled={reason.trim() === ""} onClick={() => { void suppress(); }}>Suppress</Button>
                <Button onClick={() => { setAsking(false); }}>Cancel</Button>
              </div>
            </div>
          ) : (
            <Button onClick={() => { setAsking(true); }}>Suppress this rule for {a.entity_key}</Button>
          )}
        </div>
      </Panel>

      {a.related.length > 0 && (
        <Panel title="Related alerts" description="Other alerts about the same entity close in time.">
          <ul className="grid gap-1 text-sm">
            {a.related.map((r) => (
              <li key={r.id}><a className="text-link underline underline-offset-2" href={`#/alerts/${String(r.id)}`}>{r.title}</a> · {r.severity} · {r.status}</li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="History of this alert">
        {events.data && events.data.items.length > 0 ? (
          <ol className="grid gap-1 text-sm">
            {events.data.items.map((e) => (
              <li key={e.id}><When iso={e.at} /> · {e.kind}{e.to_status ? ` → ${e.to_status}` : ""}{e.note ? ` · ${e.note}` : ""}</li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-fg-muted">No changes recorded.</p>
        )}
      </Panel>
    </div>
  );
}
