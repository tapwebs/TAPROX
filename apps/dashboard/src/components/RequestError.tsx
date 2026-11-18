import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { StateView } from "@/components/ui/StateView";
import { ApiError } from "@/lib/api/client";
import { formatDateTime } from "@/lib/format";

interface Props {
  error: Error;
  /** What was being loaded, e.g. "backend status"; used in the title. */
  what: string;
  onRetry: () => void;
}

/** Map a failed request to the right state: permission, disconnected or generic error. */
export function RequestError({ error, what, onRetry }: Props) {
  if (error instanceof ApiError && error.status === 401) {
    return (
      <StateView
        variant="permission"
        title="Access to the backend was denied"
        description="The backend rejected this session's credentials. Close and reopen TAPROX to start a new session."
      />
    );
  }
  if (error instanceof ApiError && error.status === 403) {
    // The Host/Origin guard answers 403: the credentials are not the problem.
    return (
      <StateView
        variant="permission"
        title="The backend refused this request"
        description={`It came from an address the backend does not allow (${error.code}). This usually means the app was opened from an unexpected location.`}
      />
    );
  }
  if (error instanceof ApiError && error.code.endsWith("permission_denied")) {
    // The operating system refused the backend (not the user's session): the 503 code says so.
    return (
      <StateView variant="permission" title="Windows did not allow this" description={error.message} />
    );
  }
  if (error instanceof ApiError && error.kind === "network") {
    return (
      <StateView
        variant="disconnected"
        title="Backend not reachable"
        description="TAPROX could not contact its local backend. It may have stopped."
        action={{ label: "Try again", onClick: onRetry }}
      />
    );
  }
  return (
    <StateView
      variant="error"
      title={`Could not load ${what}`}
      description={error.message}
      action={{ label: "Try again", onClick: onRetry }}
    />
  );
}

interface StaleProps {
  error: Error;
  what: string;
  /** When the data still on screen was last loaded successfully. */
  asOf: string | number | undefined;
  onRetry: () => void;
}

/** A refresh failed but older data is still shown: say so, and label that data as stale. */
export function StaleNotice({ error, what, asOf, onRetry }: StaleProps) {
  return (
    <div
      role="alert"
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-warning/40 bg-warning/10 p-3"
    >
      <p className="flex items-start gap-2 text-fg">
        <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-warning" />
        <span>
          <strong className="font-medium">Could not refresh {what}.</strong> {error.message} Showing
          results from {formatDateTime(asOf)}.
        </span>
      </p>
      <Button onClick={onRetry}>Try again</Button>
    </div>
  );
}
