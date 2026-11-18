import { TriangleAlert } from "lucide-react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList, type DefinitionItem } from "@/components/ui/DefinitionList";
import { Panel } from "@/components/ui/Panel";
import { Skeleton } from "@/components/ui/Skeleton";
import { StatusBadge } from "@/components/ui/StatusBadge";
import type { PrerequisiteCheck } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { formatDateTime } from "@/lib/format";
import { useRequest } from "@/lib/useRequest";

const OS_LABEL = { windows: "Windows", linux: "Linux", unsupported: "Unsupported" } as const;

function CheckStatus({ status }: { status: PrerequisiteCheck["status"] }) {
  if (status === "ok") return <StatusBadge tone="success">Installed</StatusBadge>;
  if (status === "missing") return <StatusBadge tone="warning">Not found</StatusBadge>;
  return <StatusBadge tone="critical">Problem</StatusBadge>;
}

function CheckItem({ check }: { check: PrerequisiteCheck }) {
  const facts: DefinitionItem[] = [];
  if (check.version) facts.push({ label: "Version", value: check.version, mono: true });
  if (check.path) facts.push({ label: "Location", value: check.path, mono: true });

  return (
    <li className="rounded-md border border-line bg-inset p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium text-fg">{check.name}</h3>
        <CheckStatus status={check.status} />
      </div>
      <p className="mt-0.5 text-xs text-fg-muted">{check.required_for}</p>
      {facts.length > 0 && (
        <div className="mt-3">
          <DefinitionList items={facts} />
        </div>
      )}
      {check.status !== "ok" && check.detail && <p className="mt-3 text-fg-muted">{check.detail}</p>}
      {check.remediation && <p className="mt-2 text-fg">How to fix: {check.remediation}</p>}
    </li>
  );
}

export function SettingsPage() {
  const { client } = useReadyBackend();
  const request = useRequest((signal) => client.getCapturePrerequisites(signal), [client]);
  const data = request.data;

  if (request.isLoading) {
    return (
      <div role="status" aria-label="Loading capture prerequisites" aria-busy="true" className="space-y-3">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }
  if (!data) {
    return request.error ? (
      <RequestError error={request.error} what="capture prerequisites" onRetry={request.reload} />
    ) : null;
  }

  return (
    <div className="space-y-4">
      {request.error && (
        <StaleNotice
          error={request.error}
          what="capture prerequisites"
          asOf={request.dataUpdatedAt}
          onRetry={request.reload}
        />
      )}
      <Panel title="Platform" description="The computer TAPROX is running on">
        <DefinitionList
          items={[
            { label: "Operating system", value: OS_LABEL[data.platform.os] },
            { label: "Version", value: data.platform.os_version },
            { label: "Architecture", value: data.platform.architecture, mono: true },
            {
              label: "Privileges",
              value: data.platform.elevated ? (
                <StatusBadge tone="warning">Elevated</StatusBadge>
              ) : (
                // Not "standard user": an administrator running a non-elevated process lands here too.
                "Not elevated"
              ),
            },
          ]}
        />
        {data.warnings.map((warning) => (
          <p key={warning} className="mt-3 flex items-start gap-2 text-warning">
            <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <span>{warning}</span>
          </p>
        ))}
      </Panel>

      <Panel
        title="Capture prerequisites"
        description="Tools TAPROX uses to capture and read packets"
        actions={
          <Button loading={request.isRefreshing} onClick={request.reload}>
            Re-check
          </Button>
        }
      >
        <ul aria-label="Capture prerequisites" className="space-y-3">
          {data.checks.map((check) => (
            <CheckItem key={check.id} check={check} />
          ))}
        </ul>
        <p className="mt-4 text-xs text-fg-muted">
          Installed tools do not prove that your account may capture on a given network interface.
          That is verified when a capture starts.
        </p>
        <p aria-live="polite" className="mt-1 text-xs text-fg-subtle">
          Last checked {formatDateTime(data.checked_at)}
        </p>
      </Panel>
    </div>
  );
}
