import { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Code, ConnectError, type Interceptor } from "@connectrpc/connect";
import { createControlClients, createControlTransport, type SandboxSummary } from "@cauteum/control-client";
import type { User } from "oidc-client-ts";
import { completeSignIn, currentUser, signIn, signOut } from "./auth";
import "@fontsource-variable/space-grotesk";
import "@fontsource-variable/manrope";
import "@fontsource/ibm-plex-mono/400.css";
import "./style.css";

function ControlApp() {
  const [user, setUser] = useState<User | null>(null);
  const [authError, setAuthError] = useState("");
  const [loadingAuth, setLoadingAuth] = useState(true);
  const [rows, setRows] = useState<SandboxSummary[]>([]);
  const [viewer, setViewer] = useState<{ subject: string; roles: string[] } | null>(null);
  const [overview, setOverview] = useState<{ sandboxCount: bigint; registryRunningCount: bigint; workspace: string } | null>(null);
  const [workspaces, setWorkspaces] = useState<string[]>([]);
  const [nextPageToken, setNextPageToken] = useState("");
  const [selected, setSelected] = useState<SandboxSummary | null>(null);
  const [logs, setLogs] = useState<{ timestampUnixMs: bigint; level: string; source: string; message: string }[]>([]);
  const [workspace, setWorkspace] = useState("");
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        if (window.location.pathname === "/auth/callback") {
          const callbackUser = await completeSignIn();
          if (alive) setUser(callbackUser);
        } else {
          const existing = await currentUser();
          if (alive) setUser(existing);
        }
      } catch (err) {
        if (alive) setAuthError(message(err));
      } finally {
        if (alive) setLoadingAuth(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  const clients = useMemo(() => {
    if (!user?.access_token) return null;
    const bearer: Interceptor = (next) => async (request) => {
      request.header.set("Authorization", `Bearer ${user.access_token}`);
      return next(request);
    };
    return createControlClients(createControlTransport({ baseUrl: window.location.origin, interceptors: [bearer] }));
  }, [user]);

  const refresh = useCallback(async () => {
    if (!clients) return;
    setBusy(true); setError("");
    try {
      const [identity, summary, listed, workspaceList] = await Promise.all([
        clients.console.getViewer({}),
        clients.console.getOverview({ workspace }),
        clients.sandboxes.listSandboxes({ workspace, pageSize: 100 }),
        clients.catalog.listWorkspaces({}),
      ]);
      setViewer({ subject: identity.subject, roles: identity.roles });
      setWorkspaces(workspaceList.workspaces.map((item) => item.name));
      setOverview({ sandboxCount: summary.sandboxCount, registryRunningCount: summary.registryRunningCount, workspace: summary.workspace });
      setRows(listed.sandboxes);
      setNextPageToken(listed.nextPageToken);
      if (selected) setSelected(listed.sandboxes.find((row) => row.name === selected.name) ?? null);
    } catch (err) {
      setError(apiError(err));
    } finally { setBusy(false); }
  }, [clients, workspace, selected]);

  useEffect(() => { void refresh(); }, [refresh]);

  const loadMore = useCallback(async () => {
    if (!clients || !nextPageToken) return;
    setBusy(true);
    try {
      const page = await clients.sandboxes.listSandboxes({ workspace, pageSize: 100, pageToken: nextPageToken });
      setRows((existing) => existing.concat(page.sandboxes));
      setNextPageToken(page.nextPageToken);
    } catch (err) { setError(apiError(err)); }
    finally { setBusy(false); }
  }, [clients, nextPageToken, workspace]);

  useEffect(() => {
    if (!clients || !selected) { setLogs([]); return; }
    let alive = true;
    clients.sandboxes.getSandboxLogs({ workspace, name: selected.name, limit: 120 })
      .then((result) => { if (alive) setLogs(result.lines); })
      .catch((err: unknown) => { if (alive) setError(apiError(err)); });
    return () => { alive = false; };
  }, [clients, selected, workspace]);

  const visibleRows = rows.filter((row) => `${row.name} ${row.image} ${row.computeDriver} ${row.registryStatus}`.toLowerCase().includes(filter.toLowerCase()));

  if (loadingAuth) return <main className="auth-stage"><div className="auth-card"><Brand /><p className="quiet">Connecting to your gateway…</p></div></main>;
  if (!user) return <main className="auth-stage"><div className="auth-card"><Brand /><div className="eyebrow">CONTROL CONSOLE</div><h1>Your sandbox fleet,<br />in one place.</h1><p className="auth-copy">Sign in with your organization identity to inspect the resources available to you.</p>{authError && <div className="callout error">{authError}</div>}<button className="primary-button" onClick={() => void signIn().catch((e) => setAuthError(message(e)))}>Sign in <span>↗</span></button><p className="auth-foot">Access is checked by the gateway for every request.</p></div></main>;

  return <div className="shell">
    <aside className="rail"><Brand compact /><div className="rail-label">WORKSPACE</div><label className="workspace-select"><span className="workspace-dot" /><select value={workspace || "default"} onChange={(event) => setWorkspace(event.target.value)} aria-label="Select workspace">{(workspaces.length ? workspaces : ["default"]).map((name) => <option key={name} value={name}>{name}</option>)}</select><span className="chevron">⌄</span></label><div className="rail-label nav-label">CONTROL</div><a className="nav-link active" href="#fleet"><span className="nav-icon">▦</span>Sandboxes<span className="nav-count">{rows.length}</span></a><div className="rail-bottom"><div className="gateway-mark"><span className="pulse" />GATEWAY ONLINE</div><div className="profile"><div className="avatar">{(viewer?.subject ?? user.profile.sub ?? "U").slice(0, 1).toUpperCase()}</div><div className="profile-copy"><strong>{viewer?.subject ?? user.profile.sub ?? "Signed in"}</strong><span>{viewer?.roles.join(", ") || "viewer"}</span></div><button aria-label="Sign out" className="icon-button" onClick={() => void signOut().then(() => setUser(null))}>↗</button></div></div></aside>
    <main className="main" id="fleet">
      <header className="topbar"><div className="crumb">Cauteum <span>/</span> Control</div><div className="topbar-right"><span className="sync-note"><span className="sync-dot" />Registry snapshot</span><button className="refresh-button" onClick={() => void refresh()} disabled={busy}><span className={busy ? "spin" : ""}>↻</span> Refresh</button></div></header>
      <section className="intro"><div><div className="eyebrow">FLEET LEDGER <span>·</span> {overview?.workspace || workspace || "DEFAULT WORKSPACE"}</div><h1>Sandboxes</h1><p>Resources visible in this workspace, as recorded by the gateway.</p></div><div className="intro-stamp"><span className="stamp-glyph">C</span><span>Cauteum<br />CONTROL PLANE</span></div></section>
      <section className="metric-strip" aria-label="Workspace summary"><div className="metric"><span className="metric-label">REGISTERED SANDBOXES</span><strong>{overview?.sandboxCount.toString() ?? "—"}</strong></div><div className="metric"><span className="metric-label">REGISTRY MARKED RUNNING</span><strong>{overview?.registryRunningCount.toString() ?? "—"}</strong></div><div className="metric metric-note"><span className="metric-label">RUNTIME STATUS</span><strong><i className="status-dash" />Not reported</strong><small>The registry does not confirm process health.</small></div><div className="metric-signal"><div className="signal-line"><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /></div><span>REGISTRY SIGNAL · {rows.length ? "RECEIVED" : "AWAITING DATA"}</span></div></section>
      {error && <div className="callout error global-error">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
      <section className="ledger"><div className="ledger-head"><div><div className="eyebrow">RESOURCE INVENTORY</div><h2>Workspace resources <span>{visibleRows.length.toString().padStart(2, "0")}</span></h2></div><label className="search"><span>⌕</span><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by name, image, status" aria-label="Filter sandboxes"/><kbd>⌘ K</kbd></label></div>
        <div className="table-wrap"><table><thead><tr><th>NAME / ID</th><th>REGISTRY STATE</th><th>COMPUTE</th><th>IMAGE</th><th>UPDATED</th><th /></tr></thead><tbody>{visibleRows.map((row) => <tr key={`${row.workspace}/${row.name}`} className={selected?.name === row.name ? "selected-row" : ""} onClick={() => setSelected(row)} tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter") setSelected(row); }}><td><div className="sandbox-name"><span className={`state-bar ${stateTone(row.registryStatus)}`} /><div><strong>{row.name}</strong><small>{row.id || `${row.workspace}/${row.name}`}</small></div></div></td><td><span className={`state-pill ${stateTone(row.registryStatus)}`}><i />{row.registryStatus || "unknown"}</span></td><td className="mono">{row.computeDriver || "—"}</td><td className="image-cell">{row.image || "—"}</td><td className="mono">{formatTime(row.updatedAtUnixMs)}</td><td className="row-arrow">↗</td></tr>)}</tbody></table>
          {!visibleRows.length && <div className="empty-state"><span>⌁</span><strong>{rows.length ? "No matching sandboxes" : busy ? "Loading registry" : "No sandboxes in this workspace"}</strong><p>{rows.length ? "Try a shorter filter." : "When resources are registered, they will appear here."}</p></div>}
        </div><div className="table-foot"><span>Showing {visibleRows.length}{nextPageToken ? "+" : ""} resources</span>{nextPageToken ? <button className="text-button" disabled={busy} onClick={() => void loadMore()}>Load next page →</button> : <span>Source: gateway registry <i className="foot-dot" /></span>}</div>
      </section>
    </main>
    {selected && <><button className="scrim" aria-label="Close sandbox details" onClick={() => setSelected(null)} /><aside className="detail-panel"><div className="detail-top"><div><div className="eyebrow">SANDBOX RECORD</div><div className="detail-title">{selected.name}</div></div><button className="icon-button close-button" aria-label="Close details" onClick={() => setSelected(null)}>×</button></div><span className={`state-pill ${stateTone(selected.registryStatus)}`}><i />{selected.registryStatus || "unknown"}</span><div className="detail-section"><div className="eyebrow">IDENTITY</div><dl><dt>Workspace</dt><dd>{selected.workspace}</dd><dt>Resource ID</dt><dd>{selected.id || "—"}</dd><dt>Version</dt><dd>{selected.resourceVersion.toString()}</dd><dt>Updated</dt><dd>{formatTime(selected.updatedAtUnixMs)}</dd><dt>Compute driver</dt><dd>{selected.computeDriver || "—"}</dd></dl></div><div className="detail-section"><div className="eyebrow">IMAGE</div><div className="image-detail">{selected.image || "No image recorded"}</div></div><div className="detail-section"><div className="log-heading"><div><div className="eyebrow">RECENT LOGS</div><span>Gateway buffer · latest 120</span></div><button className="text-button" onClick={() => void refresh()}>Reload</button></div><div className="log-window">{logs.length ? logs.map((line, i) => <div className="log-line" key={`${line.timestampUnixMs}-${i}`}><time>{new Date(Number(line.timestampUnixMs)).toLocaleTimeString([], { hour12: false })}</time><b className={`log-level ${line.level.toLowerCase()}`}>{line.level || "INFO"}</b><span>{line.message}</span></div>) : <div className="logs-empty">No buffered log lines.</div>}</div><p className="log-caption">Structured log fields are omitted. The buffer is in memory and may reset.</p></div><div className="runtime-note"><span>i</span><p>Runtime health is not available from this registry view.</p></div></aside></>}
  </div>;
}

function Brand({ compact = false }: { compact?: boolean }) { return <div className={`brand ${compact ? "brand-compact" : ""}`}><span className="brand-symbol"><i /><i /><i /></span><span>cauteum<small>{compact ? "CONTROL" : ""}</small></span></div>; }
function message(err: unknown) { return err instanceof Error ? err.message : "An unexpected error occurred."; }
function apiError(err: unknown) { return err instanceof ConnectError ? (err.code === Code.Unauthenticated ? "Session expired. Sign in again." : err.message) : message(err); }
function stateTone(status: string) { return status.toLowerCase() === "running" ? "green" : status.toLowerCase() === "stopped" ? "amber" : "neutral"; }
function formatTime(ms: bigint) { return ms ? new Date(Number(ms)).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "—"; }

createRoot(document.getElementById("root")!).render(<ControlApp />);
