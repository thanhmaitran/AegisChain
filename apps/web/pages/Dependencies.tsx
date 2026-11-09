import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo, useState } from "react";
import { Async, Card, Mono, NeedsRun, StatusBadge } from "../components/ui";
import type { Component, DependenciesResponse } from "../types";
import { useApi } from "../useApi";

function layout(d: DependenciesResponse): { nodes: Node[]; edges: Edge[] } {
  const rows = new Map<number, number>();
  const nodes: Node[] = d.graph.nodes.map((n) => {
    const col = n.depth ?? 0;
    const row = rows.get(col) ?? 0;
    rows.set(col, row + 1);
    return {
      id: n.id, position: { x: col * 240, y: row * 56 }, data: { label: `${n.name}${n.version ? ` ${n.version}` : ""}` },
      style: { background: n.direct ? "#171A1F" : "#FBF9F4", color: n.direct ? "#F4F1EA" : "#171A1F", border: "1px solid #D9D3C5", fontSize: 12, width: 200 },
    };
  });
  const edges: Edge[] = d.graph.edges.map((e) => ({ id: `${e.source}>${e.target}`, source: e.source, target: e.target }));
  return { nodes, edges };
}

function Body({ runId }: { runId: string }) {
  const deps = useApi<DependenciesResponse>(`/dependencies/${runId}`);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"all" | "direct" | "transitive">("all");
  const [selected, setSelected] = useState<Component | null>(null);
  const graph = useMemo(() => (deps.data ? layout(deps.data) : null), [deps.data]);

  return (
    <Async state={deps}>
      {(d) => {
        const rows = d.components.filter((c) =>
          (kind === "all" || (kind === "direct") === c.direct) && (q === "" || c.purl.toLowerCase().includes(q.toLowerCase())));
        return (
          <>
            <Card title="Findings" aside={<StatusBadge status={d.status} />}>
              {d.findings.filter((f) => f.status !== "PASS").length === 0 ? <p className="text-sm text-mute">No warnings.</p> : (
                <ul className="text-sm space-y-1">{d.findings.filter((f) => f.status !== "PASS").map((f, i) => (
                  <li key={i}><StatusBadge status={f.status} /> <b>{f.code}</b> {f.message}</li>))}</ul>)}
            </Card>
            <Card title="Dependency graph" aside={<span className="text-xs text-mute">dark = direct · columns = depth</span>}>
              <div style={{ height: 420 }} aria-label="dependency graph">
                {graph && <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView nodesDraggable={false}
                  onNodeClick={(_, n) => setSelected(d.components.find((c) => c.purl === n.id) ?? null)}>
                  <Background /><Controls showInteractive={false} /></ReactFlow>}
              </div>
            </Card>
            <div className="grid lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2"><Card title={`Component inventory (${rows.length}/${d.components.length})`}>
                <div className="flex gap-2 mb-3">
                  <input className="input flex-1" placeholder="search package URL…" value={q} onChange={(e) => setQ(e.target.value)} />
                  <select className="input" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
                    <option value="all">all</option><option value="direct">direct</option><option value="transitive">transitive</option></select>
                </div>
                <div className="overflow-x-auto"><table className="table-base w-full">
                  <thead><tr><th>Package</th><th>Version</th><th>Type</th><th>Depth</th><th>Scope</th></tr></thead>
                  <tbody>{rows.map((c) => (
                    <tr key={c.purl} className="cursor-pointer hover:bg-rule/30" onClick={() => setSelected(c)}>
                      <td>{c.name}</td><td>{c.version ?? <i className="text-warn">unknown</i>}</td>
                      <td>{c.direct ? "direct" : "transitive"}</td><td>{c.depth ?? "–"}</td><td>{c.scope}</td></tr>))}</tbody>
                </table></div></Card></div>
              <Card title="Component detail">
                {!selected ? <p className="text-sm text-mute">Select a component.</p> : (
                  <dl className="text-sm space-y-2">
                    <div><dt className="text-mute">purl</dt><dd><Mono>{selected.purl}</Mono></dd></div>
                    <div><dt className="text-mute">Declared license</dt><dd>{selected.declared_license ?? "not declared"}</dd></div>
                    <div><dt className="text-mute">Source files</dt><dd>{selected.source_files.join(", ")}</dd></div>
                    <div><dt className="text-mute">Hashes</dt><dd>{Object.keys(selected.hashes).length === 0 ? "none in lockfile" :
                      Object.entries(selected.hashes).map(([a, h]) => <div key={a}>{a}: <Mono>{h}</Mono></div>)}</dd></div>
                    <div><dt className="text-mute">Depends on ({selected.dependencies.length})</dt>
                      <dd>{selected.dependencies.map((x) => <div key={x}><Mono>{x}</Mono></div>)}</dd></div>
                  </dl>)}
              </Card>
            </div>
          </>
        );
      }}
    </Async>
  );
}

export default function Dependencies() { return <NeedsRun>{(id) => <Body runId={id} />}</NeedsRun>; }
