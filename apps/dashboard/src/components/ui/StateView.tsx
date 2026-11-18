import { Inbox, LoaderCircle, LockKeyhole, TriangleAlert, Unplug, type LucideIcon } from "lucide-react";
import { Button } from "./Button";
import { TONE_TEXT, type Tone } from "./StatusBadge";

export type StateVariant = "loading" | "empty" | "error" | "permission" | "disconnected";

const VARIANTS: Record<StateVariant, { icon: LucideIcon; tone: Tone }> = {
  loading: { icon: LoaderCircle, tone: "info" },
  empty: { icon: Inbox, tone: "neutral" },
  error: { icon: TriangleAlert, tone: "critical" },
  permission: { icon: LockKeyhole, tone: "warning" },
  disconnected: { icon: Unplug, tone: "warning" },
};

interface Props {
  variant: StateVariant;
  title: string;
  description?: string;
  action?: { label: string; onClick: () => void };
}

/**
 * The one component for every non-happy screen state, so loading / empty / error / permission /
 * disconnected look and announce themselves consistently.
 * Errors, permission and disconnection are announced assertively (role=alert); loading politely.
 */
export function StateView({ variant, title, description, action }: Props) {
  const { icon: Icon, tone } = VARIANTS[variant];
  const role = variant === "loading" ? "status" : variant === "empty" ? undefined : "alert";
  return (
    <div
      role={role}
      aria-label={variant === "loading" ? title : undefined}
      aria-busy={variant === "loading" || undefined}
      className="flex flex-col items-center gap-2 px-4 py-8 text-center"
    >
      <Icon
        aria-hidden="true"
        className={`size-6 ${TONE_TEXT[tone]} ${variant === "loading" ? "animate-spin motion-reduce:animate-none" : ""}`}
      />
      <p className="text-sm font-medium text-fg">{title}</p>
      {description && <p className="max-w-prose text-sm text-fg-muted">{description}</p>}
      {action && (
        <Button className="mt-2" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
}
