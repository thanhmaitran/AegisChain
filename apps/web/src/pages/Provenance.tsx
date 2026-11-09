import { useState } from "react";
import { api } from "../api";
import { Async, Card, Mono, NeedsRun, StatusBadge } from "../components/ui";
import type { ProvenanceResponse, VerifyResponse } from "../types";
import { useApi } from "../useApi";

function Evidence({ data }: { data: ProvenanceResponse | VerifyResponse }) {
  const i = data.integrity, p = data.provenance;
  return (
    <div className="space-y-4">
      <div><h3 className="text-base mb-1">Artifact digest</h3>
        {i ? (<div className="text-sm space-y-1"><StatusBadge status={i.status} /> {i.detail}
          <div>SHA-256 <Mono>{i.sha256 ?? "—"}</Mono></div><div>Reference <Mono>{i.expected_sha256 ?? "none supplied"}</Mono></div></div>)
          : <p className="text-sm text-mute">No artifact was verified.</p>}</div>
      <div><h3 className="text-base mb-1">Provenance and signature</h3>
        {!p || !p.provided ? <p className="text-sm text-mute">No provenance evidence. Absence of evidence is reported as INDETERMINATE by policy, never as PASS.</p> : (
          <table className="table-base w-full"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>{p.checks.map((c) => <tr key={c.name}><td>{c.name}</td><td><StatusBadge status={c.status} /></td><td>{c.detail}</td></tr>)}</tbody></table>)}
        {p?.builder_id && <p className="text-xs mt-2">Builder: <Mono>{p.builder_id}</Mono></p>}
        {p?.source_uri && <p className="text-xs">Source: <Mono>{p.source_uri}</Mono></p>}</div>
    </div>
  );
}

function Verify() {
  const [res, setRes] = useState<VerifyResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const policies = useApi<string[]>("/policies");
  async function submit(form: HTMLFormElement) {
    const data = new FormData(form);
    for (const k of ["expected_sha256", "policy", "provenance", "signature_bundle"]) {
      const v = data.get(k);
      if (v === "" || (v instanceof File && v.size === 0)) data.delete(k);
    }
    try { setErr(null); setRes(await api.postForm<VerifyResponse>("/artifacts/verify", data)); }
    catch (e) { setRes(null); setErr(e instanceof Error ? e.message : String(e)); }
  }
  return (
    <Card title="Verify an artifact">
      <form className="grid md:grid-cols-2 gap-3 text-xs text-mute" onSubmit={(e) => { e.preventDefault(); void submit(e.currentTarget); }}>
        <label>Artifact<input className="block text-sm" type="file" name="artifact" required /></label>
        <label>Reference SHA-256<input className="input block w-full" name="expected_sha256" placeholder="64 hex characters" /></label>
        <label>Provenance (DSSE / bundle)<input className="block text-sm" type="file" name="provenance" /></label>
        <label>Signature bundle<input className="block text-sm" type="file" name="signature_bundle" /></label>
        <label>Policy<select className="input block" name="policy"><option value="">built-in default</option>{(policies.data ?? []).map((n) => <option key={n}>{n}</option>)}</select></label>
        <div className="flex items-end"><button className="btn">Verify</button></div>
      </form>
      {err && <p role="alert" className="text-fail mt-3 text-sm">{err}</p>}
      {res && <div className="mt-4"><p className="mb-2">Verification result: <StatusBadge status={res.status} /></p><Evidence data={res} /></div>}
    </Card>
  );
}

function Body({ runId }: { runId: string }) {
  const prov = useApi<ProvenanceResponse>(`/provenance/${runId}`);
  return <Card title="Evidence attached to this analysis"><Async state={prov}>{(d) => <Evidence data={d} />}</Async></Card>;
}

export default function Provenance() {
  return (<><NeedsRun>{(id) => <Body runId={id} />}</NeedsRun><Verify /></>);
}
