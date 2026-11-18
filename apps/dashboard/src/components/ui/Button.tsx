import { LoaderCircle } from "lucide-react";
import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "ghost";

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-accent text-on-accent hover:bg-accent-strong border border-accent/40 font-semibold shadow-[0_1px_8px_rgba(229,32,58,0.3)]",
  secondary:
    "bg-raised text-fg hover:bg-card hover:border-accent/40 border border-line-strong shadow-[0_1px_3px_rgba(0,0,0,0.4)]",
  ghost:
    "bg-transparent text-fg-muted hover:bg-raised hover:text-fg border border-transparent",
};

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  /** Disables the button and shows a spinner while an async action runs. */
  loading?: boolean;
}

export function Button({
  variant = "secondary",
  loading = false,
  disabled,
  type = "button",
  className = "",
  children,
  ...rest
}: Props) {
  return (
    <button
      type={type}
      disabled={disabled === true || loading}
      aria-busy={loading || undefined}
      className={`inline-flex h-8 cursor-pointer items-center justify-center gap-2 rounded-md px-3 text-sm transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-60 ${VARIANTS[variant]} ${className}`}
      {...rest}
    >
      {loading && (
        <LoaderCircle aria-hidden="true" className="size-4 animate-spin motion-reduce:animate-none" />
      )}
      {children}
    </button>
  );
}
