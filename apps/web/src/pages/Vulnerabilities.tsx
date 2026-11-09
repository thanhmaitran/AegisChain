import { Fragment, useState } from "react";
import { Async, Card, NeedsRun } from "../components/ui";
import type { VulnerabilityResponse } from "../types";
import { useApi } from "../useApi";

const SEV_COLOR: Record<string, string> = { CRITICAL: "bg-fail text-white", HIGH: "bg-warn text-white", MEDIUM: "bg-rule", LOW: "bg-card border border-rule", UNKNOWN: "bg-card text-indet border border-indet hatch" };

function Body({ runId }: { runId: string }) {
  const v = useApi<VulnerabilityResponse>(`/vulnerabilities/${runId}`);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Async state={v}>
      {(r) => (
        <>
          <Card title="Lookup provenance">
            <p className="text-sm">Source: {r.source} · status <b>{r.lookup_status}</b> · queried {r.queried_at ?? "never"}</p>
            {r.unscanned.length > 0 && <p className="text-sm text-warn mt-1">{r.unscanned.length} component(s) were not scanned.</p>}
            {r.errors.map((e) => <p key={e} className="text-sm text-fail">{e}</p>)}
          </Card>
          <Card title={`Findings (${r.matches.length})`}>
            {r.matches.length === 0 ? <p className="text-sm text-mute">No matches. Absence from the database is not proof of safety.</p> : (
              <div className="overflow-x-auto"><table className="table-base w-full">
                <thead><tr><th>Severity</th><th>ID</th><th>Component</th><th>Exposure</th><th>Fix</th><th>Local check</th></tr></thead>
                <tbody>{r.matches.map((m) => {
                  const detail = r.vulnerabilities.find((x) => x.osv_id === m.osv_id);
                  const key = `${m.component_purl}|${m.osv_id}`;
                  return (<Fragment key={key}>
                    <tr className="cursor-pointer hover:bg-rule/30" onClick={() => setOpen(open === key ? null : key)}>
                      <td><span className={`rounded px-2 py-0.5 text-xs ${SEV_COLOR[m.severity] ?? ""}`}>{m.severity}</span></td>
                      <td>{m.osv_id}</td><td className="font-mono text-xs">{m.component_purl}</td>
                      <td>{m.direct ? "direct" : "transitive"}</td>
                      <td>{m.fix_available ? `upgrade to ${m.fixed_versions[0]}` : "no fix known"}</td><td>{m.local_verification}</td></tr>
                    {open === key && detail && (<tr key={`${key}-d`}><td colSpan={6} className="bg-paper">
                      <p>{detail.summary}</p>
                      <p className="text-xs text-mute">Severity source: {detail.severity_source}{detail.cvss_score !== null && ` (CVSS ${detail.cvss_score})`} · aliases: {detail.aliases.join(", ") || "none"} · modified {detail.modified ?? "n/a"}</p>
                      <ul className="text-xs list-disc pl-5">{detail.references.slice(0, 5).map((u) => <li key={u} className="break-all">{u}</li>)}</ul></td></tr>)}
                  </Fragment>);
                })}</tbody></table></div>)}
          </Card>
        </>
      )}
    </Async>
  );
}

export default function Vulnerabilities() { return <NeedsRun>{(id) => <Body runId={id} />}</NeedsRun>; }
