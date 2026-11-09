import type { ReactNode } from "react";
import { useRun } from "../RunContext";
import type { Loaded } from "../useApi";
import type { Status } from "../types";

const STYLE: Record<Status, string> = {
  PASS: "bg-pass text-white",
  FAIL: "bg-fail text-white",
  WARN: "bg-warn text-white",
  INDETERMINATE: "bg-card text-indet border border-indet hatch",
};

export function StatusBadge({ status }: { status: Status }) {
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold tracking-wide ${STYLE[status]}`}>{status}</span>;
}

export function Card({ title, children, aside }: { title?: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="bg-card border border-rule rounded-lg p-4">
      {(title || aside) && (
        <header className="flex items-baseline justify-between mb-3">
          <h2 className="text-lg">{title}</h2>
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-mute">{label}</div>
      <div className="font-display text-3xl">{value}</div>
    </div>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="font-mono text-xs break-all">{children}</code>;
}

/** Renders loading / error / empty states, then the content once data is available. */
export function Async<T>({ state, children }: { state: Loaded<T>; children: (data: T) => ReactNode }) {
  if (state.loading) return <p className="text-mute">Loading…</p>;
  if (state.error) return <p role="alert" className="text-fail">Error: {state.error}</p>;
  if (state.data === null) return null;
  return <>{children(state.data)}</>;
}

export function NeedsRun({ children }: { children: (runId: string) => ReactNode }) {
  const { runId } = useRun();
  if (!runId) return <Card><p className="text-mute">Select or create an analysis on the Projects page first.</p></Card>;
  return <>{children(runId)}</>;
}
