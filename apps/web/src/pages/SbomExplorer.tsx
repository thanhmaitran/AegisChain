import { useMemo, useState } from "react";
import { Async, Card, Mono, NeedsRun } from "../components/ui";
import { useApi } from "../useApi";

type Fmt = "cyclonedx" | "spdx";
interface Row { name: string; version: string; purl: string; license: string }
interface Doc { [k: string]: unknown }

function rows(fmt: Fmt, doc: Doc): Row[] {
  if (fmt === "cyclonedx") {
    const comps = (doc.components ?? []) as { name: string; version?: string; purl?: string; licenses?: { expression?: string; license?: { name?: string } }[] }[];
    return comps.map((c) => ({ name: c.name, version: c.version ?? "—", purl: c.purl ?? "", license: c.licenses?.[0]?.expression ?? c.licenses?.[0]?.license?.name ?? "NOASSERTION" }));
  }
  const pkgs = (doc.packages ?? []) as { name: string; versionInfo?: string; licenseDeclared?: string; externalRefs?: { referenceType: string; referenceLocator: string }[] }[];
  return pkgs.filter((p) => p.externalRefs?.length).map((p) => ({
    name: p.name, version: p.versionInfo ?? "—", purl: p.externalRefs?.find((r) => r.referenceType === "purl")?.referenceLocator ?? "", license: p.licenseDeclared ?? "NOASSERTION" }));
}

function Body({ runId }: { runId: string }) {
  const [fmt, setFmt] = useState<Fmt>("cyclonedx");
  const [q, setQ] = useState("");
  const sbom = useApi<Doc>(`/sbom/${runId}?format=${fmt}`);
  const href = useMemo(() => (sbom.data ? URL.createObjectURL(new Blob([JSON.stringify(sbom.data, null, 2)], { type: "application/json" })) : undefined), [sbom.data]);
  return (
    <Card title="SBOM Explorer" aside={
      <div className="flex gap-2 items-center">
        {(["cyclonedx", "spdx"] as Fmt[]).map((f) => (
          <button key={f} className={`px-2 py-1 rounded text-sm border border-rule ${f === fmt ? "bg-ink text-paper" : ""}`} onClick={() => setFmt(f)}>{f === "cyclonedx" ? "CycloneDX 1.5" : "SPDX 2.3"}</button>))}
        {href && <a className="btn" href={href} download={`sbom.${fmt === "cyclonedx" ? "cdx" : "spdx"}.json`}>Export JSON</a>}
      </div>}>
      <Async state={sbom}>
        {(doc) => {
          const all = rows(fmt, doc);
          const list = all.filter((r) => q === "" || `${r.name} ${r.purl}`.toLowerCase().includes(q.toLowerCase()));
          return (
            <>
              <input className="input w-full mb-3" placeholder="filter…" value={q} onChange={(e) => setQ(e.target.value)} />
              <p className="text-xs text-mute mb-2">{list.length} of {all.length} components. Licences shown only where declared in the source metadata; otherwise NOASSERTION.</p>
              <div className="overflow-x-auto"><table className="table-base w-full">
                <thead><tr><th>Name</th><th>Version</th><th>Package URL</th><th>License</th></tr></thead>
                <tbody>{list.map((r) => <tr key={r.purl || r.name}><td>{r.name}</td><td>{r.version}</td><td><Mono>{r.purl}</Mono></td><td>{r.license}</td></tr>)}</tbody></table></div>
            </>);
        }}
      </Async>
    </Card>
  );
}

export default function SbomExplorer() { return <NeedsRun>{(id) => <Body runId={id} />}</NeedsRun>; }
