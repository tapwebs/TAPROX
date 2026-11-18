import { useState } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { StateView } from "@/components/ui/StateView";
import { StatTile } from "@/components/ui/StatTile";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import { RowTh, Table, Td, Th } from "@/components/ui/Table";
import { useHashQuery } from "@/features/flows/common";
import { AttachToCasePanel } from "@/features/investigations/AttachToCaseModal";
import { ConfidenceChip, SeverityBadge, When, parseId } from "@/features/security/common";
import { ApiError } from "@/lib/api/client";
import type {
  HeaderMatrixEntry,
  WebCertificateSchema,
  WebCookieSchema,
  WebFindingSchema,
  WebHopSchema,
  WebInspectionDetail,
} from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";

type DetailSection = "findings" | "headers" | "tls" | "cookies" | "hops";
type StatusFilter = "" | "running" | "completed" | "failed" | "cancelled";
type SeverityFilter = "" | "high" | "medium" | "low" | "info";
type CategoryFilter = "" | "tls" | "headers" | "cookies" | "http";

const PAGE_SIZE = 25;

const STATUS_TONE: Record<string, Tone> = {
  running: "info",
  completed: "success",
  failed: "critical",
  cancelled: "neutral",
};

const MATRIX_TONE: Record<HeaderMatrixEntry["status"], { tone: Tone; label: string }> = {
  present: { tone: "success", label: "Present" },
  weak: { tone: "warning", label: "Weak" },
  missing: { tone: "critical", label: "Missing" },
  limited: { tone: "warning", label: "Limited" },
  inconclusive: { tone: "neutral", label: "Inconclusive" },
  not_applicable: { tone: "neutral", label: "N/A (HTTP)" },
};

const PROFILE_DESCRIPTIONS: Record<"standard" | "browser_compatible" | "custom", string> = {
  standard: "Existing TAPROX request headers and User-Agent.",
  browser_compatible: "Browser-compatible request headers with transparent TAPROX identification.",
  custom: "User-specified User-Agent, validated by the existing backend.",
};

function parseOptionalInt(raw: string | null): number | undefined {
  const n = parseId(raw);
  return n === null ? undefined : n;
}

function triggerDownload(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function FindingsView({ findings }: { findings: WebFindingSchema[] }) {
  const [sev, setSev] = useState<SeverityFilter>("");
  const [cat, setCat] = useState<CategoryFilter>("");

  const filtered = findings.filter(
    (f) => (!sev || f.severity === sev) && (!cat || f.category === cat),
  );

  return (
    <div className="grid gap-3">
      <div className="grid gap-3 md:grid-cols-2">
        <SelectField
          label="Finding severity"
          value={sev}
          onChange={(e) => {
            setSev(e.target.value as SeverityFilter);
          }}
        >
          <option value="">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </SelectField>
        <SelectField
          label="Finding category"
          value={cat}
          onChange={(e) => {
            setCat(e.target.value as CategoryFilter);
          }}
        >
          <option value="">All categories</option>
          <option value="tls">TLS</option>
          <option value="headers">Headers</option>
          <option value="cookies">Cookies</option>
          <option value="http">HTTP</option>
        </SelectField>
      </div>

      {filtered.length === 0 ? (
        <p className="text-sm text-fg-muted">
          No observations matched the current filters for this single-URL inspection.
        </p>
      ) : (
        <ul className="grid gap-3">
          {filtered.map((f, idx) => (
            <li key={`${f.rule_id}-${String(idx)}`} className="rounded-md border border-line bg-inset p-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge level={f.severity} />
                <ConfidenceChip level={f.confidence} />
                <span className="font-mono text-xs text-fg-subtle">{f.rule_id}</span>
                <span className="text-sm font-semibold text-fg">{f.title}</span>
              </div>
              <p className="mt-2 text-sm text-fg">{f.summary}</p>
              {typeof f.evidence === "object" && f.evidence !== null && "method" in f.evidence && "status_code" in f.evidence && (
                <div className="mt-1 font-mono text-xs text-fg-subtle">
                  Assessed from: {String(f.evidence.method)} {String(f.evidence.status_code)}
                  {"response_type" in f.evidence ? ` (${String(f.evidence.response_type)})` : ""}
                </div>
              )}
              <p className="mt-1 text-xs text-fg-muted">
                <strong className="font-medium text-fg">Rationale:</strong> {f.why}
              </p>
              <p className="mt-1 text-xs text-fg-muted">
                <strong className="font-medium text-fg">Hardening guidance:</strong> {f.remediation}
              </p>
              <div className="mt-2 grid gap-2 text-xs text-fg-muted md:grid-cols-2">
                <div>
                  <div className="font-medium text-fg">What else this could be</div>
                  <ul className="list-disc pl-4">
                    {f.benign_explanations.map((b) => (
                      <li key={b}>{b}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="font-medium text-fg">Limitations</div>
                  <ul className="list-disc pl-4">
                    {f.blind_spots.map((b) => (
                      <li key={b}>{b}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <details className="mt-2 text-xs text-fg-muted">
                <summary className="cursor-pointer hover:text-fg">Structured evidence</summary>
                <pre className="mt-1 overflow-x-auto rounded-sm bg-surface p-2 font-mono text-xs text-fg">
                  {JSON.stringify(f.evidence, null, 2)}
                </pre>
              </details>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function MatrixView({ rows }: { rows: HeaderMatrixEntry[] }) {
  if (rows.length === 0) {
    return (
      <StateView
        variant="empty"
        title="No HTTP response headers recorded"
        description="HTTP headers were not fetched (for example, TLS trust verification stopped the request or the connection failed)."
      />
    );
  }
  return (
    <Table label="Security headers matrix">
      <thead>
        <tr>
          <Th>Header</Th>
          <Th>Status</Th>
          <Th>Observed value</Th>
          <Th>Guidance</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const badge = MATRIX_TONE[r.status];
          return (
            <tr key={r.header}>
              <RowTh className="font-mono text-[13px]">{r.header}</RowTh>
              <Td>
                <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>
              </Td>
              <Td mono className="max-w-xs break-all">
                {r.observed_value ?? "—"}
              </Td>
              <Td>{r.note}</Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

function TlsView({
  hops,
  certificates,
}: {
  hops: WebHopSchema[];
  certificates: WebCertificateSchema[];
}) {
  const httpsHop = [...hops].reverse().find((h) => h.tls !== null);
  const cert = certificates[certificates.length - 1] ?? null;
  if (!httpsHop?.tls && !cert) {
    return (
      <StateView
        variant="empty"
        title="Plaintext HTTP inspection"
        description="No TLS handshake occurred on the inspected hops."
      />
    );
  }
  const tls = httpsHop?.tls;
  return (
    <div className="grid gap-4">
      {tls && (
        <DefinitionList
          items={[
            { label: "Protocol", value: tls.version ?? "Unknown", mono: true },
            { label: "Cipher suite", value: tls.cipher ?? "Unknown", mono: true },
            { label: "ALPN", value: tls.alpn ?? "None", mono: true },
            {
              label: "Trust store check",
              value: (
                <StatusBadge tone={tls.trust_verified ? "success" : "warning"}>
                  {tls.trust_verified ? "Verified" : "Verification failed"}
                </StatusBadge>
              ),
            },
            ...(tls.trust_error ? [{ label: "Trust error", value: tls.trust_error }] : []),
          ]}
        />
      )}
      {cert && (
        <div className="grid gap-2 border-t border-line pt-3">
          <h3 className="text-xs font-medium text-fg-muted">Leaf X.509 Certificate</h3>
          <DefinitionList
            items={[
              { label: "Subject", value: cert.subject, mono: true },
              { label: "Issuer", value: cert.issuer, mono: true },
              { label: "Hostname match", value: cert.hostname_matched ? "Matched" : "Mismatch" },
              { label: "Self-signed", value: cert.is_self_signed ? "Yes" : "No" },
              {
                label: "Public key",
                value: cert.key_bits ? `${cert.key_algorithm} (${String(cert.key_bits)} bits)` : cert.key_algorithm,
              },
              { label: "Signature algorithm", value: cert.sig_algorithm, mono: true },
              { label: "Valid from", value: <When iso={cert.not_before} /> },
              { label: "Valid until", value: <When iso={cert.not_after} /> },
              { label: "Serial", value: cert.serial_hex, mono: true },
              { label: "SHA-256 fingerprint", value: cert.sha256_fingerprint, mono: true },
              {
                label: "Subject Alt Names",
                value: cert.sans.length > 0 ? cert.sans.join(", ") : "None",
                mono: true,
              },
            ]}
          />
        </div>
      )}
    </div>
  );
}

function CookiesView({ cookies }: { cookies: WebCookieSchema[] }) {
  return (
    <div className="grid gap-3">
      <p className="text-xs text-fg-muted">
        Cookie values are discarded immediately after measuring byte length and are never stored or displayed.
      </p>
      {cookies.length === 0 ? (
        <StateView
          variant="empty"
          title="No Set-Cookie headers observed"
          description="The inspected HTTP responses did not return Set-Cookie headers."
        />
      ) : (
        <Table label="Observed Set-Cookie attributes">
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Hop</Th>
              <Th>Secure</Th>
              <Th>HttpOnly</Th>
              <Th>SameSite</Th>
              <Th>Prefix</Th>
              <Th>Domain / Path</Th>
              <Th>Value length</Th>
            </tr>
          </thead>
          <tbody>
            {cookies.map((ck, idx) => {
              const prefix = ck.has_host_prefix ? "__Host-" : ck.has_secure_prefix ? "__Secure-" : "None";
              return (
                <tr key={`${ck.name}-${String(ck.hop_index)}-${String(idx)}`}>
                  <RowTh className="font-mono text-[13px]">{ck.name}</RowTh>
                  <Td mono>{ck.hop_index}</Td>
                  <Td>
                    <StatusBadge tone={ck.secure ? "success" : "warning"}>
                      {ck.secure ? "Yes" : "No"}
                    </StatusBadge>
                  </Td>
                  <Td>
                    <StatusBadge tone={ck.http_only ? "success" : "warning"}>
                      {ck.http_only ? "Yes" : "No"}
                    </StatusBadge>
                  </Td>
                  <Td mono>{ck.same_site}</Td>
                  <Td mono>{prefix}</Td>
                  <Td mono>{`${ck.domain ?? "(host-only)"} ${ck.path ?? "/"}`}</Td>
                  <Td mono>{`${String(ck.value_length)} B`}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}
    </div>
  );
}

function HopsView({ hops }: { hops: WebHopSchema[] }) {
  const [selectedHop, setSelectedHop] = useState(0);
  if (hops.length === 0) {
    return (
      <StateView
        variant="empty"
        title="No network hops completed"
        description="The inspection ended before any HTTP or TLS hop could be recorded."
      />
    );
  }
  const active = hops.find((h) => h.hop_index === selectedHop) ?? hops[0];
  return (
    <div className="grid gap-4">
      <Table label="HTTP redirect hops">
        <thead>
          <tr>
            <Th>Hop</Th>
            <Th>Method</Th>
            <Th>Target URL (sanitized)</Th>
            <Th>Pinned IP</Th>
            <Th>Status</Th>
            <Th>Latency</Th>
            <Th>Body read</Th>
            <Th>Inspect</Th>
          </tr>
        </thead>
        <tbody>
          {hops.map((h) => (
            <tr key={h.hop_index}>
              <RowTh className="font-mono text-[13px]">{h.hop_index}</RowTh>
              <Td mono>{h.method ?? "HEAD"}</Td>
              <Td mono className="max-w-xs break-all">
                {h.url_sanitized}
                {h.blocked_reason && (
                  <div className="text-xs text-critical">Blocked redirect: {h.blocked_reason}</div>
                )}
              </Td>
              <Td mono>{h.resolved_ip ?? "—"}</Td>
              <Td mono>{h.status_code ?? "Skipped"}</Td>
              <Td mono>{`${String(h.latency_ms)} ms`}</Td>
              <Td mono>{`${String(h.body_bytes_read)} B`}</Td>
              <Td>
                <Button
                  className="h-7 px-2.5 text-xs"
                  aria-pressed={active?.hop_index === h.hop_index}
                  onClick={() => {
                    setSelectedHop(h.hop_index);
                  }}
                >
                  Headers ({h.headers.length})
                </Button>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>

      {active && (
        <div className="grid gap-2">
          <h3 className="text-xs font-medium text-fg-muted">
            Redacted headers for hop {active.hop_index} ({active.host})
          </h3>
          {active.headers.length === 0 ? (
            <p className="text-sm text-fg-muted">No HTTP headers captured on this hop.</p>
          ) : (
            <Table label={`Redacted response headers for hop ${String(active.hop_index)}`}>
              <thead>
                <tr>
                  <Th>Header</Th>
                  <Th>Value (redacted)</Th>
                </tr>
              </thead>
              <tbody>
                {active.headers.map((hdr, idx) => (
                  <tr key={`${hdr.name}-${String(idx)}`}>
                    <RowTh className="font-mono text-[13px]">{hdr.name}</RowTh>
                    <Td mono className="break-all">
                      {hdr.value}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </div>
      )}
    </div>
  );
}

export function WebInspectorPage({
  param,
  pollMs = 500,
}: {
  param: string | null;
  pollMs?: number;
}) {
  const { client } = useReadyBackend();
  const query = useHashQuery();

  const prefillUrl = query.get("url");
  const [prevPrefill, setPrevPrefill] = useState(prefillUrl);
  const [urlInput, setUrlInput] = useState(() => prefillUrl ?? "");
  if (prefillUrl !== prevPrefill) {
    setPrevPrefill(prefillUrl);
    if (prefillUrl) setUrlInput(prefillUrl);
  }
  const [method, setMethod] = useState<"HEAD" | "GET">("HEAD");
  const [requestProfile, setRequestProfile] = useState<"standard" | "browser_compatible" | "custom">("standard");
  const [customUserAgent, setCustomUserAgent] = useState("");
  const [followRedirects, setFollowRedirects] = useState(true);
  const [maxRedirects, setMaxRedirects] = useState("5");
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [allowInsecureTls, setAllowInsecureTls] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const routeId = parseId(param);
  const [prevRouteId, setPrevRouteId] = useState(routeId);
  const [activeId, setActiveId] = useState<number | null>(routeId);
  if (routeId !== prevRouteId) {
    setPrevRouteId(routeId);
    if (routeId !== null) setActiveId(routeId);
  }
  const [section, setSection] = useState<DetailSection>("findings");
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search.trim(), 300);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("");
  const [offset, setOffset] = useState(0);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [attachOpen, setAttachOpen] = useState(false);

  const history = useRequest(
    (signal) =>
      client.listWebInspections(
        {
          limit: PAGE_SIZE,
          offset,
          status: statusFilter || undefined,
          search: debouncedSearch || undefined,
        },
        signal,
      ),
    [client, offset, statusFilter, debouncedSearch],
  );

  const selectedId = activeId ?? history.data?.inspections[0]?.id ?? null;

  const detail = useRequest<WebInspectionDetail | null>(
    (signal) => (selectedId === null ? Promise.resolve(null) : client.getWebInspection(selectedId, signal)),
    [client, selectedId],
  );

  const isRunning = detail.data?.status === "running";
  usePolling(
    () => {
      detail.reloadQuietly();
      history.reloadQuietly();
    },
    isRunning ? pollMs : null,
  );

  const handleInspect = async () => {
    setSubmitting(true);
    setFormError(null);
    setExportMessage(null);
    try {
      const hopsNum = Number(maxRedirects);
      const created = await client.startWebInspection({
        url: urlInput.trim(),
        method,
        follow_redirects: followRedirects,
        max_redirects: Number.isInteger(hopsNum) && hopsNum >= 0 && hopsNum <= 10 ? hopsNum : 5,
        allow_private_network: allowPrivate,
        allow_insecure_tls: allowInsecureTls,
        confirm_authorized: authorized,
        source_session_id: parseOptionalInt(query.get("session_id")) ?? null,
        source_device_id: parseOptionalInt(query.get("device_id")) ?? null,
        source_alert_id: parseOptionalInt(query.get("alert_id")) ?? null,
        request_profile: requestProfile,
        custom_user_agent:
          requestProfile === "custom" && customUserAgent.trim() ? customUserAgent.trim() : null,
      });
      setActiveId(created.id);
      setSection("findings");
      history.reloadQuietly();
    } catch (cause) {
      setFormError(cause instanceof ApiError ? cause.message : "Could not start inspection.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = async () => {
    if (selectedId === null) return;
    try {
      await client.cancelWebInspection(selectedId);
      detail.reloadQuietly();
      history.reloadQuietly();
    } catch (cause) {
      setFormError(cause instanceof ApiError ? cause.message : "Could not cancel inspection.");
    }
  };

  const handleExport = async (format: "json" | "markdown") => {
    if (!detail.data) return;
    setExportMessage(null);
    try {
      const content = await client.exportWebInspection(detail.data.id, format);
      const ext = format === "markdown" ? "md" : "json";
      const mime = format === "markdown" ? "text/markdown;charset=utf-8" : "application/json;charset=utf-8";
      triggerDownload(`taprox-web-inspection-${String(detail.data.id)}.${ext}`, content, mime);
      setExportMessage(`Exported ${format.toUpperCase()} report.`);
    } catch (cause) {
      setExportMessage(cause instanceof ApiError ? cause.message : "Export failed.");
    }
  };

  const handleClearHistory = async () => {
    setClearing(true);
    setFormError(null);
    try {
      await client.deleteWebHistory();
      setConfirmClear(false);
      setActiveId(null);
      setOffset(0);
      history.reload();
    } catch (cause) {
      setFormError(cause instanceof ApiError ? cause.message : "Could not clear history.");
    } finally {
      setClearing(false);
    }
  };

  const current = detail.data;

  return (
    <div className="grid gap-4">
      <Panel
        title="Target & Authorization"
        description="Passive, read-only single-URL HTTP/HTTPS and TLS inspection. Requires explicit authorization."
      >
        <div className="grid gap-3">
          <div className="grid gap-3 md:grid-cols-[1fr_12rem_14rem_9rem]">
            <TextField
              label="Target URL"
              value={urlInput}
              placeholder="https://example.com"
              onChange={(e) => {
                setUrlInput(e.target.value);
              }}
              hint="Only http:// and https:// URLs without embedded credentials."
            />
            <SelectField
              label="Method"
              value={method}
              onChange={(e) => {
                setMethod(e.target.value as "HEAD" | "GET");
              }}
            >
              <option value="HEAD">HEAD (headers & TLS)</option>
              <option value="GET">GET (+64 KiB body hash)</option>
            </SelectField>
            <SelectField
              label="Request profile"
              value={requestProfile}
              onChange={(e) => {
                setRequestProfile(e.target.value as "standard" | "browser_compatible" | "custom");
              }}
              hint={PROFILE_DESCRIPTIONS[requestProfile]}
            >
              <option value="standard">Standard (default)</option>
              <option value="browser_compatible">Browser-Compatible</option>
              <option value="custom">Custom</option>
            </SelectField>
            <SelectField
              label="Max redirects"
              value={maxRedirects}
              disabled={!followRedirects}
              onChange={(e) => {
                setMaxRedirects(e.target.value);
              }}
            >
              <option value="0">0</option>
              <option value="3">3</option>
              <option value="5">5 (default)</option>
              <option value="10">10 (max)</option>
            </SelectField>
          </div>

          {requestProfile === "custom" && (
            <div className="rounded-md border border-line bg-surface-subtle p-3">
              <TextField
                label="Custom User-Agent"
                value={customUserAgent}
                placeholder="e.g. MySecurityScanner/1.0 (+https://example.com/audit)"
                onChange={(e) => {
                  setCustomUserAgent(e.target.value);
                }}
                hint="User-specified User-Agent, validated by the existing backend. Max 512 chars; control characters are rejected."
              />
            </div>
          )}

          <div className="grid gap-2 md:grid-cols-3">
            <CheckboxField
              label="Follow redirects"
              checked={followRedirects}
              onChange={(e) => {
                setFollowRedirects(e.target.checked);
              }}
              description="Re-validates DNS and SSRF policy on every hop."
            />
            <CheckboxField
              label="Allow private LAN targets"
              checked={allowPrivate}
              onChange={(e) => {
                setAllowPrivate(e.target.checked);
              }}
              description="Allows RFC 1918/ULA LAN hosts. Loopback and metadata stay blocked."
            />
            <CheckboxField
              label="Continue HTTP if TLS trust fails"
              checked={allowInsecureTls}
              onChange={(e) => {
                setAllowInsecureTls(e.target.checked);
              }}
              description="Off by default: skips HTTP request when certificate verification fails."
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3">
            <CheckboxField
              label="I am authorized to inspect this target"
              checked={authorized}
              onChange={(e) => {
                setAuthorized(e.target.checked);
              }}
              description="Passive HEAD/GET only. Cookie values and auth headers are never persisted."
            />
            <div className="flex gap-2">
              {isRunning && (
                <Button onClick={() => { void handleCancel(); }}>Cancel</Button>
              )}
              <Button
                variant="primary"
                loading={submitting}
                disabled={!authorized || urlInput.trim() === "" || isRunning}
                onClick={() => {
                  void handleInspect();
                }}
              >
                Inspect target
              </Button>
            </div>
          </div>

          {formError && (
            <p role="alert" className="text-sm text-critical">
              {formError}
            </p>
          )}
        </div>
      </Panel>

      <Panel
        title={current ? `Inspection #${String(current.id)}: ${current.host}` : "Inspection Result"}
        description={current ? current.target_url_sanitized : "Select a historical run or start a new inspection above."}
        actions={
          current && current.status !== "running" ? (
            <div className="flex flex-wrap gap-2">
              <Button
                className="h-7 px-2.5 text-xs"
                onClick={() => {
                  setAttachOpen(true);
                }}
              >
                Attach to Investigation…
              </Button>
              <Button className="h-7 px-2.5 text-xs" onClick={() => { void handleExport("json"); }}>
                Export JSON
              </Button>
              <Button className="h-7 px-2.5 text-xs" onClick={() => { void handleExport("markdown"); }}>
                Export Markdown
              </Button>
            </div>
          ) : undefined
        }
      >
        {detail.isLoading && !current ? (
          <StateView variant="loading" title="Loading inspection" />
        ) : !current ? (
          detail.error ? (
            <RequestError error={detail.error} what="the inspection" onRetry={detail.reload} />
          ) : (
            <StateView
              variant="empty"
              title="No inspection selected"
              description="Enter an authorized URL above to inspect TLS, security headers, and cookie attributes."
            />
          )
        ) : (
          <div className="grid gap-4">
            {detail.error && (
              <StaleNotice
                error={detail.error}
                what="the inspection"
                asOf={detail.dataUpdatedAt}
                onRetry={detail.reload}
              />
            )}
            {exportMessage && (
              <p role="status" className="text-xs text-fg-muted">
                {exportMessage}
              </p>
            )}
            {attachOpen && (
              <AttachToCasePanel
                target={{
                  kind: "web_inspection",
                  sourceId: current.id,
                  label: `Web Inspection #${String(current.id)}: ${current.host}`,
                }}
                onClose={() => {
                  setAttachOpen(false);
                }}
              />
            )}

            <div className="flex flex-wrap items-center gap-3 text-sm">
              <StatusBadge tone={STATUS_TONE[current.status] ?? "neutral"}>
                {current.status[0]?.toUpperCase()}{current.status.slice(1)}
              </StatusBadge>
              <StatusBadge tone="neutral">
                Profile: {current.request_profile === "browser_compatible" ? "Browser-Compatible" : current.request_profile === "custom" ? "Custom" : "Standard"}
              </StatusBadge>
              {current.assessment_classification === "inconclusive" && (
                <StatusBadge tone="warning">Assessment Inconclusive</StatusBadge>
              )}
              {current.assessment_classification === "provisional" && (
                <StatusBadge tone="neutral">Provisional Assessment</StatusBadge>
              )}
              {current.fallback_performed ? (
                <span className="font-mono text-xs text-fg-muted">
                  HEAD: HTTP {current.hops[0]?.status_code ?? "—"} → {current.fallback_method} fallback: HTTP {current.fallback_status ?? "—"} · Primary assessment based on {current.assessment_response_method ?? "GET"} response · IP {current.final_ip ?? "—"}
                </span>
              ) : (
                <span className="font-mono text-xs text-fg-muted">
                  {current.method} · HTTP {current.http_status ?? "—"} · IP {current.final_ip ?? "—"}
                </span>
              )}
              {current.tls_version && (
                <span className="font-mono text-xs text-fg-muted">
                  {current.tls_version} · {current.cert_verified ? "Cert verified" : "Cert unverified"}
                </span>
              )}
              {current.duration_ms !== null && (
                <span className="font-mono text-xs text-fg-subtle">{current.duration_ms} ms</span>
              )}
            </div>
            {current.inconclusive_reason && (
              <div className="rounded-md border border-warning/40 bg-inset p-2.5 text-xs text-warning">
                <strong className="font-medium text-fg">Assessment Notice:</strong> {current.inconclusive_reason}
              </div>
            )}

            {current.status === "running" && (
              <div className="grid gap-2">
                <ProgressBar label="Inspection in progress" value={0} max={0} />
                <p role="status" className="text-xs text-fg-muted">
                  Inspecting target…
                </p>
              </div>
            )}

            {current.error_code && (
              <div role="alert" className="rounded-md border border-critical/50 bg-inset p-3 text-sm">
                <div className="font-mono text-xs text-critical">{current.error_code}</div>
                <div className="mt-1 text-fg">{current.error_message ?? "Inspection did not complete."}</div>
              </div>
            )}

            {current.warnings.length > 0 && (
              <ul className="grid gap-1 rounded-md border border-warning/50 bg-inset p-3 text-xs text-warning">
                {current.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}

            <dl className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <StatTile label="High findings" value={String(current.findings_high)} />
              <StatTile label="Medium findings" value={String(current.findings_medium)} />
              <StatTile label="Low findings" value={String(current.findings_low)} />
              <StatTile label="Info findings" value={String(current.findings_info)} />
            </dl>

            <p className="text-xs text-fg-subtle">
              Scope notice: passive single-URL HEAD/GET observation only. Does not execute JavaScript, crawl pages, or actively probe endpoints.
            </p>

            <div role="toolbar" aria-label="Inspection detail sections" className="flex flex-wrap gap-1 border-b border-line pb-2">
              {(
                [
                  ["findings", `Findings (${String(current.findings.length)})`],
                  ["headers", "Headers Matrix"],
                  ["tls", "TLS & Cert"],
                  ["cookies", `Cookies (${String(current.cookies.length)})`],
                  ["hops", `Hops (${String(current.hops.length)})`],
                ] as const
              ).map(([id, label]) => (
                <Button
                  key={id}
                  className="h-7 px-2.5 text-xs"
                  aria-pressed={section === id}
                  variant={section === id ? "primary" : "secondary"}
                  onClick={() => {
                    setSection(id);
                  }}
                >
                  {label}
                </Button>
              ))}
            </div>

            {section === "findings" && <FindingsView findings={current.findings} />}
            {section === "headers" && <MatrixView rows={current.header_matrix} />}
            {section === "tls" && <TlsView hops={current.hops} certificates={current.certificates} />}
            {section === "cookies" && <CookiesView cookies={current.cookies} />}
            {section === "hops" && <HopsView hops={current.hops} />}
          </div>
        )}
      </Panel>

      <Panel
        title="Inspection History"
        actions={
          confirmClear ? (
            <div className="flex items-center gap-2">
              <Button
                className="h-7 px-2.5 text-xs"
                variant="primary"
                loading={clearing}
                onClick={() => {
                  void handleClearHistory();
                }}
              >
                Confirm clear history
              </Button>
              <Button
                className="h-7 px-2.5 text-xs"
                onClick={() => {
                  setConfirmClear(false);
                }}
              >
                Cancel
              </Button>
            </div>
          ) : (
            <Button
              className="h-7 px-2.5 text-xs"
              disabled={!history.data || history.data.total === 0 || isRunning}
              onClick={() => {
                setConfirmClear(true);
              }}
            >
              Clear history…
            </Button>
          )
        }
      >
        <div className="grid gap-3">
          <div className="grid gap-3 md:grid-cols-[1fr_14rem]">
            <TextField
              label="Search host or URL"
              value={search}
              placeholder="example.com"
              onChange={(e) => {
                setSearch(e.target.value);
                setOffset(0);
              }}
            />
            <SelectField
              label="History status"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as StatusFilter);
                setOffset(0);
              }}
            >
              <option value="">All statuses</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
              <option value="running">Running</option>
            </SelectField>
          </div>

          {history.isLoading && !history.data ? (
            <StateView variant="loading" title="Loading inspection history" />
          ) : !history.data ? (
            history.error ? (
              <RequestError error={history.error} what="inspection history" onRetry={history.reload} />
            ) : null
          ) : history.data.inspections.length === 0 ? (
            <StateView
              variant="empty"
              title="No inspections recorded"
              description="Completed and failed authorized inspections appear here."
            />
          ) : (
            <>
              <Table label="Saved web inspections">
                <thead>
                  <tr>
                    <Th>Started</Th>
                    <Th>Target</Th>
                    <Th>Status</Th>
                    <Th>HTTP / TLS</Th>
                    <Th>Findings (H/M/L)</Th>
                    <Th>Open</Th>
                  </tr>
                </thead>
                <tbody>
                  {history.data.inspections.map((item) => (
                    <tr key={item.id}>
                      <RowTh>
                        <When iso={item.started_at} />
                      </RowTh>
                      <Td mono className="max-w-xs break-all">
                        {item.target_url_sanitized}
                      </Td>
                      <Td>
                        <StatusBadge tone={STATUS_TONE[item.status] ?? "neutral"}>
                          {item.status}
                        </StatusBadge>
                      </Td>
                      <Td mono>
                        <div>{item.http_status ?? "—"} / {item.tls_version ?? "HTTP"}</div>
                        <span className="block text-[11px] text-fg-subtle">
                          {item.request_profile === "browser_compatible"
                            ? "browser-compat"
                            : item.request_profile === "custom"
                              ? "custom"
                              : "standard"}
                        </span>
                      </Td>
                      <Td mono>
                        {item.findings_high}/{item.findings_medium}/{item.findings_low}
                      </Td>
                      <Td>
                        <Button
                          className="h-7 px-2.5 text-xs"
                          aria-pressed={current?.id === item.id}
                          onClick={() => {
                            setActiveId(item.id);
                          }}
                        >
                          View #{item.id}
                        </Button>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Pagination
                offset={history.data.offset}
                limit={history.data.limit}
                total={history.data.total}
                onChange={setOffset}
              />
            </>
          )}
        </div>
      </Panel>
    </div>
  );
}
