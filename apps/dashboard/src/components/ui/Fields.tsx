import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

const CONTROL =
  "h-8 w-full rounded-md border border-line-strong/80 bg-inset px-2.5 text-sm text-fg placeholder:text-fg-subtle/80 shadow-[inset_0_1px_2px_rgba(0,0,0,0.3)] transition-colors focus:border-accent focus:ring-1 focus:ring-accent/40 disabled:cursor-not-allowed disabled:opacity-60";
const LABEL = "mb-1 block text-xs font-medium text-fg-muted";

function describedBy(...ids: (string | false | undefined)[]): string | undefined {
  const joined = ids.filter(Boolean).join(" ");
  return joined || undefined;
}

type TextProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & {
  label: string;
  hint?: string;
  error?: string;
};

export function TextField({ label, hint, error, className = "", ...input }: TextProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  return (
    <div className={className}>
      <label htmlFor={id} className={LABEL}>
        {label}
      </label>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(hint && hintId, error && errorId)}
        className={`${CONTROL} ${error ? "border-critical" : ""}`}
        {...input}
      />
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-fg-subtle">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="mt-1 text-xs text-critical">
          {error}
        </p>
      )}
    </div>
  );
}

type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "id"> & {
  label: string;
  hint?: string;
  children: ReactNode;
};

export function SelectField({ label, hint, children, className = "", ...select }: SelectProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className={className}>
      <label htmlFor={id} className={LABEL}>
        {label}
      </label>
      <select id={id} aria-describedby={hint ? hintId : undefined} className={`${CONTROL} cursor-pointer pr-7`} {...select}>
        {children}
      </select>
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-fg-subtle">
          {hint}
        </p>
      )}
    </div>
  );
}

/** One choice of a radio group; wrap the group in a <fieldset> with a <legend>. */
export function RadioField({ label, description, className = "", ...input }: CheckboxProps) {
  const id = useId();
  const descriptionId = `${id}-description`;
  return (
    <div className={`flex items-start gap-2.5 ${className}`}>
      <input
        id={id}
        type="radio"
        aria-describedby={description ? descriptionId : undefined}
        className="mt-0.5 size-4 shrink-0 cursor-pointer accent-accent-strong"
        {...input}
      />
      <div>
        <label htmlFor={id} className="cursor-pointer text-sm text-fg">
          {label}
        </label>
        {description && (
          <p id={descriptionId} className="mt-0.5 text-xs text-fg-muted">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}

type CheckboxProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id" | "type"> & {
  label: string;
  description?: string;
};

/** The description sits outside the <label> so the control's name stays short and exact. */
export function CheckboxField({ label, description, className = "", ...input }: CheckboxProps) {
  const id = useId();
  const descriptionId = `${id}-description`;
  return (
    <div className={`flex items-start gap-2.5 ${className}`}>
      <input
        id={id}
        type="checkbox"
        aria-describedby={description ? descriptionId : undefined}
        className="mt-0.5 size-4 shrink-0 cursor-pointer accent-accent-strong"
        {...input}
      />
      <div>
        <label htmlFor={id} className="cursor-pointer text-sm text-fg">
          {label}
        </label>
        {description && (
          <p id={descriptionId} className="mt-0.5 text-xs text-fg-muted">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}
