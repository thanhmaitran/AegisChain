import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Async, Card, NeedsRun, Stat, StatusBadge } from "../components/ui";
import type { AnalysisRun, DependenciesResponse, VulnerabilityResponse } from "../types";
import { useApi } from "../useApi";

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

function Body({ runId }: { runId: string }) {
  const run = useApi<AnalysisRun>(`/analysis/${runId}`);
  const deps = useApi<DependenciesResponse>(`/dependencies/${runId}`);
  const vuln = useApi<VulnerabilityResponse>(`/vulnerabilities/${runId}`);
  return (
    <>
      <Async state={run}>
        {(r) => (
          <Card>
            <div className="flex flex-wrap items-center gap-4">
              <div>
                <div className="text-xs uppercase tracking-wide text-mute">Final decision</div>
                <div className="mt-1 scale-150 origin-left"><StatusBadge status={r.decision} /></div>
              </div>
              <div className="text-sm text-mute">
                Policy <b>{r.policy_name}</b> v{r.policy_version} · evaluated as of {r.policy_evaluation.as_of}
              </div>
            </div>
            <ul className="mt-4 list-disc pl-5 text-sm space-y-1">
              {r.policy_evaluation.reasons.length === 0 && <li>Every evaluated rule passed.</li>}
              {r.policy_evaluation.reasons.map((x) => <li key={x}>{x}</li>)}
            </ul>
          </Card>
        )}
      </Async>
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Components">
          <Async state={deps}>
            {(d) => {
              const direct = d.components.filter((c) => c.direct).length;
              return (
                <div className="flex gap-8">
                  <Stat label="Total" value={d.components.length} />
                  <Stat label="Direct" value={direct} />
                  <Stat label="Transitive" value={d.components.length - direct} />
                </div>
              );
            }}
          </Async>
        </Card>
        <Card title="Known vulnerabilities (OSV)" aside={<Async state={vuln}>{(v) => <span className="text-xs text-mute">lookup {v.lookup_status}</span>}</Async>}>
          <Async state={vuln}>
            {(v) => {
              const data = ORDER.map((s) => ({ severity: s, count: v.severity_counts[s] ?? 0 }));
              return (
                <>
                  <div style={{ height: 160 }}>
                    <ResponsiveContainer>
                      <BarChart data={data}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="severity" fontSize={11} />
                        <YAxis allowDecimals={false} fontSize={11} />
                        <Tooltip />
                        <Bar dataKey="count" fill="#171A1F" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  {v.matches.length === 0 && (
                    <p className="text-xs text-mute">No matches reported. That is not proof of absence of vulnerabilities.</p>
                  )}
                </>
              );
            }}
          </Async>
        </Card>
      </div>
      <Async state={run}>
        {(r) => (
          <Card title="Engine results">
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {r.policy_evaluation.engines.map((e) => (
                <div key={e.engine} className="border border-rule rounded p-3">
                  <div className="text-sm font-medium">{e.engine}</div>
                  <div className="mt-1 flex items-center gap-2"><StatusBadge status={e.status} />
                    {!e.evaluated && <span className="text-xs text-mute">not required</span>}</div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </Async>
      <Async state={run}>
        {(r) => (
          <Card title="Execution metrics (seconds)">
            <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
              {Object.entries(r.metrics).map(([k, v]) => (<div key={k}><dt className="text-mute">{k}</dt><dd className="font-mono">{v}</dd></div>))}
            </dl>
          </Card>
        )}
      </Async>
    </>
  );
}

export default function Overview() {
  return <NeedsRun>{(id) => <Body runId={id} />}</NeedsRun>;
}
