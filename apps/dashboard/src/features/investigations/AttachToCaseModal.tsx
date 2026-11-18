import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { ApiError } from "@/lib/api/client";
import type { ArtifactKind, CaseSummary, EvidenceDetail } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useRequest } from "@/lib/useRequest";

export interface AttachTarget {
  kind: ArtifactKind;
  sourceId?: number;
  sourcePath?: string;
  label: string;
}

export function AttachToCasePanel({
  target,
  onAttached,
  onClose,
}: {
  target: AttachTarget;
  onAttached?: (ev: EvidenceDetail) => void;
  onClose: () => void;
}) {
  const { client } = useReadyBackend();
  const cases = useRequest((signal) => client.listCases({ limit: 50 }, signal), [client]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [createNew, setCreateNew] = useState(false);
  const [newTitle, setNewTitle] = useState(target.label.slice(0, 120));
  const [actor, setActor] = useState("local-operator");
  const [vaultCopy, setVaultCopy] = useState(true);
  const [confirmAttach, setConfirmAttach] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attached, setAttached] = useState<EvidenceDetail | null>(null);

  const openCases: CaseSummary[] = (cases.data?.items ?? []).filter(
    (c) => c.status === "open" || c.status === "active",
  );
  const effectiveCaseId =
    selectedCaseId || (openCases[0] ? String(openCases[0].id) : "");

  const handleSubmit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      let caseId: number;
      if (createNew || openCases.length === 0) {
        const created = await client.createCase({
          title: newTitle.trim() || target.label.slice(0, 120),
          summary: `Opened while attaching ${target.kind}: ${target.label}`,
          classification: "triage",
          severity: "medium",
          actor: actor.trim() || "local-operator",
          scope_note: "Authorized workstation forensic triage",
          confirm_authorized: true,
        });
        caseId = created.id;
      } else {
        caseId = Number(effectiveCaseId);
      }

      const ev = await client.attachCaseEvidence(caseId, {
        kind: target.kind,
        source_id: target.sourceId,
        source_path: target.sourcePath,
        vault_copy: target.kind === "pcapng_file" ? vaultCopy : true,
        actor: actor.trim() || "local-operator",
        confirm_action: target.kind === "pcapng_file" ? confirmAttach : true,
      });
      setAttached(ev);
      onAttached?.(ev);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : "Could not attach evidence.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Panel
      title="Attach to Investigation"
      description="Preserves an immutable SHA-256 snapshot or vaulted copy without altering original records."
      actions={
        <Button className="h-7 px-2.5 text-xs" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="grid gap-3">
        <p className="rounded-md border border-line bg-inset px-3 py-2 text-xs text-fg-muted">
          Selected artifact: <span className="font-mono text-fg">{target.label}</span>
        </p>

        {cases.error && <RequestError error={cases.error} what="investigations" onRetry={cases.reload} />}

        {attached ? (
          <div role="status" className="grid gap-2 rounded-md border border-line-strong bg-inset p-3 text-sm">
            <p className="text-fg">
              Attached as <span className="font-mono">{attached.evidence_ref}</span> (SHA-256:{" "}
              <span className="font-mono text-xs">{attached.content_sha256.slice(0, 16)}…</span>).
            </p>
            <a
              href={`#/investigations/${String(attached.investigation_id)}?tab=evidence`}
              className="text-sm text-link underline underline-offset-2"
            >
              Open case workspace
            </a>
          </div>
        ) : (
          <>
            <div className="grid gap-3 md:grid-cols-2">
              {!createNew && openCases.length > 0 ? (
                <SelectField
                  label="Destination investigation"
                  value={effectiveCaseId}
                  onChange={(e) => {
                    setSelectedCaseId(e.target.value);
                  }}
                >
                  {openCases.map((c) => (
                    <option key={c.id} value={String(c.id)}>
                      {c.case_ref} — {c.title}
                    </option>
                  ))}
                </SelectField>
              ) : (
                <TextField
                  label="New case title"
                  value={newTitle}
                  onChange={(e) => {
                    setNewTitle(e.target.value);
                  }}
                />
              )}
              <TextField
                label="Operator / Examiner ID"
                value={actor}
                onChange={(e) => {
                  setActor(e.target.value);
                }}
              />
            </div>

            {openCases.length > 0 && (
              <CheckboxField
                label="Create a new investigation instead"
                checked={createNew}
                onChange={(e) => {
                  setCreateNew(e.target.checked);
                }}
              />
            )}

            {target.kind === "pcapng_file" && (
              <div className="grid gap-2">
                <CheckboxField
                  label="Copy PCAPNG read-only into isolated case vault (up to 512 MiB/file)"
                  checked={vaultCopy}
                  onChange={(e) => {
                    setVaultCopy(e.target.checked);
                  }}
                />
                <CheckboxField
                  label="Confirm authorization to acquire local PCAPNG capture evidence"
                  checked={confirmAttach}
                  onChange={(e) => {
                    setConfirmAttach(e.target.checked);
                  }}
                />
              </div>
            )}

            {error && (
              <p role="alert" className="text-sm text-critical">
                {error}
              </p>
            )}

            <div className="flex justify-end gap-2">
              <Button onClick={onClose}>Cancel</Button>
              <Button
                variant="primary"
                loading={submitting}
                disabled={target.kind === "pcapng_file" && !confirmAttach}
                onClick={() => {
                  void handleSubmit();
                }}
              >
                Confirm Attach
              </Button>
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}
