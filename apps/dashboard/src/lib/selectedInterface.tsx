import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

export const STORAGE_KEY = "tapnettrack.selectedInterface";

/** Same alphabet the backend accepts for interface ids; anything else in storage is ignored. */
const VALID_ID = /^[A-Za-z0-9._:@-]{1,64}$/;

interface SelectedInterface {
  /** The interface the user picked, or null. Nothing is ever selected on the user's behalf. */
  selectedId: string | null;
  select: (id: string | null) => void;
}

const Context = createContext<SelectedInterface | null>(null);

function readStored(): string | null {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value !== null && VALID_ID.test(value) ? value : null;
  } catch {
    return null; // storage can be blocked (privacy settings, embedded webviews)
  }
}

function writeStored(id: string | null): void {
  try {
    if (id === null) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, id);
  } catch {
    // The choice still holds for this session; it just will not survive a restart.
  }
}

/**
 * The interface the user is working with, shared by the Interfaces and Discovery screens and kept
 * across restarts. The stored id may refer to an adapter that no longer exists: screens must check
 * it against the live list instead of trusting it.
 */
export function SelectedInterfaceProvider({ children }: { children: ReactNode }) {
  const [selectedId, setSelectedId] = useState<string | null>(readStored);

  const select = useCallback((id: string | null) => {
    setSelectedId(id);
    writeStored(id);
  }, []);

  const value = useMemo(() => ({ selectedId, select }), [selectedId, select]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useSelectedInterface(): SelectedInterface {
  const value = useContext(Context);
  if (!value) throw new Error("useSelectedInterface must be used inside <SelectedInterfaceProvider>.");
  return value;
}
