import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatTile } from "@/components/ui/StatTile";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { RowTh, Table, Td, Th } from "@/components/ui/Table";
import { formatBytes } from "@/features/packets/hexdump";
import { When } from "@/features/security/common";
import { ApiError } from "@/lib/api/client";
import type { BundleVerificationResponse, VerifyAllResponse } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { useRequest } from "@/lib/useRequest";

const AUDIT_PAGE_SIZE = 50;

export function ReportsPage() {
  const { client } = useReadyBackend();
  const overview = useRequest((s) => client.getReportsOverview(s), [client]);

  const [categoryFilter, setCategoryFilter] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("");
  const [auditSearch, setAuditSearch] = useState("");
  const debouncedSearch = useDebouncedValue(auditSearch, 250);
  const [auditOffset, setAuditOffset] = useState(0);

  const auditReq = useRequest(
    (s) =>
      client.listAuditEvents(
        {
          category: categoryFilter || undefined,
          outcome: outcomeFilter || undefined,
          q: debouncedSearch.trim() || undefined,
          limit: AUDIT_PAGE_SIZE,
          offset: auditOffset,
        },
        s,
      ),
    [client, categoryFilter, outcomeFilter, debouncedSearch, auditOffset],
  );

  const [verifyingAll, setVerifyingAll] = useState(false);
  const [verifyAllRes, setVerifyAllRes] = useState<VerifyAllResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  // Offline bundle verifier state
  const [bundleVerdict, setBundleVerdict] = useState<BundleVerificationResponse | null>(null);
  const [checkingBundle, setCheckingBundle] = useState(false);
  const [localBundlePath, setLocalBundlePath] = useState("");
  const [confirmLocal, setConfirmLocal] = useState(false);

  const handleVerifyAll = async () => {
    setVerifyError(null);
    setVerifyingAll(true);
    try {
      const res = await client.verifyAllCases("local-operator");
      setVerifyAllRes(res);
      overview.reload();
      auditReq.reload();
    } catch (cause) {
      setVerifyError(cause instanceof ApiError ? cause.message : "Batch verification failed.");
    } finally {
      setVerifyingAll(false);
    }
  };

  const handleUploadBundle = async (file: File | null) => {
    if (!file) return;
    setVerifyError(null);
    setCheckingBundle(true);
    try {
      const res = await client.verifyBundleUpload(file);
      setBundleVerdict(res);
    } catch (cause) {
      setVerifyError(cause instanceof ApiError ? cause.message : "Bundle verification failed.");
    } finally {
      setCheckingBundle(false);
    }
  };

  const handleVerifyLocalPath = async () => {
    setVerifyError(null);
    setCheckingBundle(true);
    try {
      const res = await client.verifyLocalBundle({
        path: localBundlePath.trim(),
        confirm_action: confirmLocal,
      });
      setBundleVerdict(res);
    } catch (cause) {
      setVerifyError(cause instanceof ApiError ? cause.message : "Local bundle check failed.");
    } finally {
      setCheckingBundle(false);
    }
  };

  const ov = overview.data;

  return (
    <div className="grid gap-4">
      <Panel
        title="Vault & Integrity Overview"
        description="Cross-case forensic storage quota and cryptographic integrity verification."
        actions={
          <Button
            className="h-7 px-2.5 text-xs"
            variant="primary"
            loading={verifyingAll}
            onClick={() => {
              void handleVerifyAll();
            }}
          >
            Verify All Cases
          </Button>
        }
      >
        {overview.isLoading && !ov ? (
          <StateView variant="loading" title="Loading reports overview" />
        ) : overview.error ? (
          <RequestError error={overview.error} what="reports overview" onRetry={overview.reload} />
        ) : (
          ov && (
            <div className="grid gap-4">
              <dl className="grid gap-3 sm:grid-cols-4">
                <StatTile label="Total cases" value={String(ov.total_cases)} />
                <StatTile label="Open / active" value={String(ov.open_or_active_cases)} />
                <StatTile label="Sealed / closed" value={String(ov.sealed_cases + ov.closed_cases)} />
                <StatTile
                  label="Vault used"
                  value={formatBytes(ov.vault_used_bytes)}
                  note={`Quota ${formatBytes(ov.vault_max_total_bytes)}`}
                />
              </dl>

              {verifyAllRes && (
                <div className="grid gap-2">
                  <h3 className="text-xs font-semibold text-fg">Latest Global Integrity Run</h3>
                  <Table label="Global integrity verification">
                    <thead>
                      <tr>
                        <Th>Case</Th>
                        <Th>Custody Chain</Th>
                        <Th>Artifacts Checked</Th>
                        <Th>Overall Verdict</Th>
                      </tr>
                    </thead>
                    <tbody>
                      {verifyAllRes.items.map((r) => (
                        <tr key={r.investigation_id}>
                          <RowTh>
                            <a
                              href={`#/investigations/${String(r.investigation_id)}`}
                              className="font-mono text-link underline underline-offset-2"
                            >
                              {r.case_ref}
                            </a>
                          </RowTh>
                          <Td>
                            <StatusBadge tone={r.chain_valid ? "success" : "critical"}>
                              {r.chain_valid ? "Intact" : "Chain Broken"}
                            </StatusBadge>
                          </Td>
                          <Td mono>{r.evidence_results.length}</Td>
                          <Td>
                            <StatusBadge tone={r.all_verified ? "success" : "critical"}>
                              {r.all_verified ? "Verified" : "Mismatch Detected"}
                            </StatusBadge>
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </div>
              )}
            </div>
          )
        )}
      </Panel>

      <Panel
        title="Offline Bundle Verifier"
        description="Verify exported ZIP bundles offline (up to 64 MiB upload, or up to 1 GiB by local archive path)."
      >
        <div className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-xs font-medium text-fg-muted">
              <span>Select ZIP bundle file (max 64 MiB upload)</span>
              <input
                type="file"
                accept=".zip"
                disabled={checkingBundle}
                onChange={(e) => {
                  void handleUploadBundle(e.target.files?.[0] ?? null);
                }}
                className="rounded-md border border-line-strong bg-inset px-3 py-1.5 text-sm text-fg"
              />
            </label>
            <div className="grid gap-2">
              <TextField
                label="Or verify local archive path (max 1 GiB)"
                value={localBundlePath}
                placeholder="C:\Exports\CASE-2026-0001_RPT-0001.zip"
                onChange={(e) => {
                  setLocalBundlePath(e.target.value);
                }}
              />
              <div className="flex flex-wrap items-center justify-between gap-2">
                <CheckboxField
                  label="Confirm local archive inspection"
                  checked={confirmLocal}
                  onChange={(e) => {
                    setConfirmLocal(e.target.checked);
                  }}
                />
                <Button
                  className="h-7 px-2.5 text-xs"
                  loading={checkingBundle}
                  disabled={!localBundlePath.trim() || !confirmLocal}
                  onClick={() => {
                    void handleVerifyLocalPath();
                  }}
                >
                  Verify Local ZIP
                </Button>
              </div>
            </div>
          </div>

          {verifyError && (
            <p role="alert" className="text-sm text-critical">
              {verifyError}
            </p>
          )}

          {bundleVerdict && (
            <div className="grid gap-2 rounded-md border border-line-strong bg-inset p-3 text-sm">
              <div className="flex items-center gap-3">
                <StatusBadge tone={bundleVerdict.valid ? "success" : "critical"}>
                  {bundleVerdict.valid ? "Bundle Verified" : "Bundle Verification Failed"}
                </StatusBadge>
                {bundleVerdict.case_ref && (
                  <span className="font-mono text-xs text-fg-muted">{bundleVerdict.case_ref}</span>
                )}
                {bundleVerdict.error && (
                  <span className="font-mono text-xs text-critical">{bundleVerdict.error}</span>
                )}
              </div>
              <p className="text-xs text-fg-muted">
                Dossier SHA-256: {bundleVerdict.dossier_sha256_valid ? "Verified" : "Failed"} · Custody Chain:{" "}
                {bundleVerdict.custody_chain_valid ? "Intact" : "Invalid"} · Files Verified:{" "}
                {String(bundleVerdict.verified_files.length)} · Failed:{" "}
                {String(bundleVerdict.failed_files.length)}
              </p>
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Installation Audit Log" description="Append-only hash-chained log of forensic & access events.">
        <div className="grid gap-4">
          <div className="grid gap-3 md:grid-cols-3">
            <TextField
              label="Search action, resource, or actor"
              value={auditSearch}
              onChange={(e) => {
                setAuditSearch(e.target.value);
                setAuditOffset(0);
              }}
            />
            <SelectField
              label="Category"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setAuditOffset(0);
              }}
            >
              <option value="">All categories</option>
              <option value="case">Case</option>
              <option value="evidence">Evidence</option>
              <option value="integrity">Integrity</option>
              <option value="export">Export</option>
              <option value="isolation">Isolation</option>
            </SelectField>
            <SelectField
              label="Outcome"
              value={outcomeFilter}
              onChange={(e) => {
                setOutcomeFilter(e.target.value);
                setAuditOffset(0);
              }}
            >
              <option value="">All outcomes</option>
              <option value="allowed">Allowed</option>
              <option value="refused">Refused</option>
              <option value="mismatch">Mismatch</option>
            </SelectField>
          </div>

          {auditReq.isLoading && !auditReq.data ? (
            <StateView variant="loading" title="Loading audit log" />
          ) : auditReq.error ? (
            <RequestError error={auditReq.error} what="audit log" onRetry={auditReq.reload} />
          ) : (auditReq.data?.items.length ?? 0) === 0 ? (
            <StateView
              variant="empty"
              title="No audit events"
              description="System forensic events appear automatically as cases are created and verified."
            />
          ) : (
            <>
              <Table label="Audit log">
                <thead>
                  <tr>
                    <Th>Seq</Th>
                    <Th>Time</Th>
                    <Th>Actor</Th>
                    <Th>Category</Th>
                    <Th>Action</Th>
                    <Th>Outcome</Th>
                    <Th>Resource</Th>
                    <Th>Audit SHA-256</Th>
                  </tr>
                </thead>
                <tbody>
                  {(auditReq.data?.items ?? []).map((ev) => (
                    <tr key={ev.id}>
                      <Td mono>{ev.seq}</Td>
                      <Td><When iso={ev.occurred_at} /></Td>
                      <Td mono>{ev.actor}</Td>
                      <Td mono>{ev.category}</Td>
                      <Td mono>{ev.action}</Td>
                      <Td>
                        <StatusBadge
                          tone={
                            ev.outcome === "allowed"
                              ? "success"
                              : ev.outcome === "refused"
                                ? "warning"
                                : "critical"
                          }
                        >
                          {ev.outcome}
                        </StatusBadge>
                      </Td>
                      <Td mono>{ev.resource_ref ?? "—"}</Td>
                      <Td mono>{ev.audit_sha256.slice(0, 12)}…</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              {auditReq.data && (
                <Pagination
                  label="Audit log pages"
                  total={auditReq.data.total}
                  limit={auditReq.data.limit}
                  offset={auditReq.data.offset}
                  onChange={setAuditOffset}
                />
              )}
            </>
          )}
        </div>
      </Panel>
    </div>
  );
}
