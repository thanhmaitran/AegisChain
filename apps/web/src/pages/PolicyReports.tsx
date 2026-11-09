import { useState } from "react";
import { api } from "../api";
import { Async, Card, NeedsRun, StatusBadge } from "../components/ui";
import type { AnalysisRun, PolicyEvaluation } from "../types";
import { useApi } from "../useApi";

function Engines({ ev }: { ev: PolicyEvaluation }) {
  return (
    <div className="space-y-3">
      {ev.engines.map((e) => (
        <div key={e.engine} className="border border-rule rounded p-3">
          <div className="flex items-center gap-2"><b className="text-sm">{e.engine}</b><StatusBadge status={e.status} />{!e.evaluated && <span className="text-xs text-mute">not required by policy</span>}</div>
          <ul className="mt-2 text-sm space-y-1">{e.rules.map((r, i) => (
            <li key={i}><StatusBadge status={r.status} /> <code className="text-xs text-mute">{r.rule_id}</code> {r.message}
              {r.subjects.length > 0 && <details className="text-xs text-mute ml-4"><summary>{r.subjects.length} subject(s)</summary>{r.subjects.slice(0, 50).map((s) => <div key={s} className="font-mono">{s}</div>)}</details>}</li>))}</ul>
        </div>))}
    </div>
  );
}

function Body({ runId }: { runId: string }) {
  const run = useApi<AnalysisRun>(`/analysis/${runId}`);
  const policies = useApi<string[]>("/policies");
  const md = useApi<string>(`/reports/${runId}?format=markdown`);
  const [alt, setAlt] = useState<PolicyEvaluation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  async function reevaluate(name: string) {
    try { setErr(null); setAlt(await api.postJson<PolicyEvaluation>("/policies/evaluate", { run_id: runId, policy: name })); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  }
  return (
    <>
      <Async state={run}>{(r) => (<Card title={`Decision under ${r.policy_name}`} aside={<StatusBadge status={r.decision} />}><Engines ev={r.policy_evaluation} /></Card>)}</Async>
      <Card title="Re-evaluate the same evidence under another policy">
        <p className="text-xs text-mute mb-2">Evidence is not collected again; the stored report is evaluated deterministically.</p>
        <div className="flex gap-2 flex-wrap">{(policies.data ?? []).map((n) => <button key={n} className="btn" onClick={() => void reevaluate(n)}>{n}</button>)}</div>
        {err && <p role="alert" className="text-fail text-sm mt-2">{err}</p>}
        {alt && <div className="mt-3"><p className="mb-2">Result under <b>{alt.policy_name}</b>: <StatusBadge status={alt.status} /></p><Engines ev={alt} /></div>}
      </Card>
      <Card title="Audit report (Markdown)">
        <Async state={md}>{(text) => (<><a className="btn mb-2 inline-block" download="aegischain-report.md" href={`data:text/markdown;charset=utf-8,${encodeURIComponent(text)}`}>Download</a>
          <pre className="text-xs whitespace-pre-wrap bg-paper p-3 rounded overflow-x-auto">{text}</pre></>)}</Async>
      </Card>
    </>
  );
}

export default function PolicyReports() { return <NeedsRun>{(id) => <Body runId={id} />}</NeedsRun>; }
