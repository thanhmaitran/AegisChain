import { useState } from "react";
import { api } from "../api";
import { Async, Card, Mono, StatusBadge } from "../components/ui";
import { useRun } from "../RunContext";
import type { Project, RunRow } from "../types";
import { useApi } from "../useApi";

interface Summary { id: string; decision: string }

function Runs({ project }: { project: Project }) {
  const { runId, setRunId } = useRun();
  const runs = useApi<RunRow[]>(`/projects/${project.id}/runs?n=${runId ?? ""}`);
  return (
    <Async state={runs}>
      {(rows) => rows.length === 0 ? <p className="text-sm text-mute">No analyses yet.</p> : (
        <table className="table-base w-full">
          <thead><tr><th>Created</th><th>Decision</th><th>Policy</th><th>Evidence digest</th><th /></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.id}>
              <td>{r.created_at}</td><td><StatusBadge status={r.decision} /></td><td>{r.policy_name}</td>
              <td><Mono>{r.evidence_digest.slice(0, 23)}…</Mono></td>
              <td><button className="btn" disabled={runId === r.id} onClick={() => setRunId(r.id)}>{runId === r.id ? "Selected" : "Open"}</button></td>
            </tr>))}
          </tbody>
        </table>
      )}
    </Async>
  );
}

export default function Projects() {
  const [tick, setTick] = useState(0);
  const projects = useApi<Project[]>(`/projects?t=${tick}`);
  const policies = useApi<string[]>("/policies");
  const { setRunId } = useRun();
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create() {
    try { await api.postJson("/projects", { name }); setName(""); setMsg(null); setTick((t) => t + 1); }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  }
  async function upload(project: Project, form: HTMLFormElement) {
    const data = new FormData(form);
    data.set("project_id", project.id);
    setBusy(true); setMsg(null);
    try {
      const s = await api.postForm<Summary>("/analysis", data);
      setRunId(s.id); setTick((t) => t + 1); setMsg(`Analysis finished: ${s.decision}`);
    } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  }

  return (
    <>
      <Card title="New project">
        <div className="flex gap-2">
          <input className="input" placeholder="project name" value={name} onChange={(e) => setName(e.target.value)} />
          <button className="btn" disabled={!name} onClick={create}>Create</button>
        </div>
        {msg && <p role="status" className="mt-2 text-sm">{msg}</p>}
      </Card>
      <Async state={projects}>
        {(list) => (<>{list.length === 0 && <Card><p className="text-mute">No projects yet.</p></Card>}
          {list.map((p) => (
            <Card key={p.id} title={p.name} aside={<Mono>{p.id}</Mono>}>
              <form className="flex flex-wrap items-end gap-3 mb-4" onSubmit={(e) => { e.preventDefault(); void upload(p, e.currentTarget); }}>
                <label className="text-xs text-mute">Repository archive (.zip / .tar.gz)
                  <input name="archive" type="file" required accept=".zip,.tar,.gz,.tgz,.bz2,.xz" className="block text-sm" /></label>
                <label className="text-xs text-mute">Policy
                  <select name="policy" className="input block"><option value="">built-in default</option>
                    {(policies.data ?? []).map((n) => <option key={n}>{n}</option>)}</select></label>
                <label className="text-xs text-mute flex items-center gap-1"><input type="checkbox" name="include_dev" value="true" defaultChecked />include dev deps</label>
                <button className="btn" disabled={busy}>{busy ? "Analysing…" : "Analyse"}</button>
              </form>
              <Runs project={p} />
            </Card>))}</>)}
      </Async>
    </>
  );
}
