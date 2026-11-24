import { useEffect, useState } from 'react';
import InvestigationEngine from './InvestigationEngine';

type SecurityState = {
  permissions: { agent_id: string; role: string; cases: string[]; tools: string[] }[];
  requests: { request_id: string; agent_id: string; action: { operation: string; case_id: string }; status: string; approver: string | null }[];
  events: { actor: string; decision: string; reason: string; timestamp: number; request_id: string | null }[];
};


function parseDashboard(value: unknown): SecurityState {
  const record = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;
  const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === 'string');
  if (!record(value) || !Array.isArray(value.permissions) || !Array.isArray(value.requests) || !Array.isArray(value.events)
    || !value.permissions.every(p => record(p) && typeof p.agent_id === 'string' && typeof p.role === 'string' && strings(p.cases) && strings(p.tools))
    || !value.requests.every(r => record(r) && typeof r.request_id === 'string' && typeof r.agent_id === 'string' && typeof r.status === 'string' && record(r.action) && typeof r.action.operation === 'string' && typeof r.action.case_id === 'string')
    || !value.events.every(e => record(e) && typeof e.actor === 'string' && typeof e.decision === 'string' && typeof e.reason === 'string' && typeof e.timestamp === 'number' && Number.isFinite(new Date(e.timestamp * 1000).getTime()))) {
    throw new Error('Invalid security response. No approval actions are available.');
  }
  return value as unknown as SecurityState;
}

export default function SecurityWorkspace({ initialCaseId = '' }: { initialCaseId?: string }) {
  const [caseId, setCaseId] = useState(initialCaseId);
  const [context, setContext] = useState<string>();
  useEffect(() => { setCaseId(initialCaseId); setContext(undefined); }, [initialCaseId]);
  const [credential, setCredential] = useState('');
  const [state, setState] = useState<SecurityState>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function request(path: string, body?: object) {
    const response = await fetch(`/api/v1/security/${path}`, {
      method: body ? 'POST' : 'GET',
      headers: { Authorization: `Bearer ${credential}`, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) throw new Error('Security request refused or unavailable. Check your human credential and request status.');
    return response.json();
  }
  async function loadContext() {
    setBusy(true); setError(''); setContext(undefined);
    try {
      const value: unknown = await request(`investigations/${encodeURIComponent(caseId)}`);
      if (typeof value !== 'object' || value === null || !('case_id' in value) || value.case_id !== caseId) throw new Error('Invalid investigation context');
      setContext(JSON.stringify(value, null, 2));
    } catch (e) { setError(e instanceof Error ? e.message : 'Context unavailable'); }
    finally { setBusy(false); }
  }
  async function refresh() {
    setBusy(true); setError('');
    try { setState(parseDashboard(await request('dashboard'))); }
    catch (e) { setState(undefined); setError(e instanceof Error ? e.message : 'Security service unavailable'); }
    finally { setBusy(false); }
  }
  async function decide(id: string, approved: boolean) {
    setBusy(true); setError('');
    try { await request(`requests/${encodeURIComponent(id)}/approval`, { approved }); setState(parseDashboard(await request('dashboard'))); }
    catch (e) { setError(e instanceof Error ? e.message : 'Approval failed'); }
    finally { setBusy(false); }
  }
  return <main>
    <div className="heading-row"><div><p className="eyebrow">AGENT SECURITY</p><h1>Human approval desk</h1><p>Scoped read tools only. Agents cannot approve requests or access this dashboard.</p></div></div>
    <section className="connection-panel">
      <label>Human approver credential <input type="password" autoComplete="off" value={credential} onChange={e => { setCredential(e.target.value); setState(undefined); setContext(undefined); }} /></label>
      <button disabled={busy || !credential} onClick={() => void refresh()}>{busy ? 'Checking…' : 'Load security activity'}</button>
      <button onClick={() => { setCredential(''); setState(undefined); setContext(undefined); setError(''); }}>Clear session</button>
      <p>Credentials stay in this page’s memory. This isolated development service uses separately provisioned credentials.</p>
    </section>
    <section className="connection-panel">
      <h2>Investigation context</h2>
      <label>Authorized case ID <input value={caseId} onChange={e => { setCaseId(e.target.value); setContext(undefined); }} /></label>
      <button disabled={busy || !credential || !/^[A-Za-z0-9_-]{1,64}$/.test(caseId)} onClick={() => void loadContext()}>Load case findings and provenance</button>
      <p>Review stored assessments, evidence sources, account relationships and report fingerprints before approving access. Agent tools are read-only.</p>
      {context && <pre data-testid="security-case-context" style={{whiteSpace:'pre-wrap', overflowWrap:'anywhere'}}>{context}</pre>}
    </section>
    <InvestigationEngine key={`${credential}:${caseId}`} caseId={caseId} credential={credential} />
    {error && <div className="notice error" role="alert">{error}</div>}
    {state && <>
      <section className="transactions-panel"><h2>Agent permissions</h2><ul>{state.permissions.map(p => <li key={p.agent_id}><strong>{p.agent_id}</strong> · {p.role} · Cases: {p.cases.join(', ')} · Tools: {p.tools.join(', ')}</li>)}</ul></section>
      <section className="transactions-panel"><h2>Approval requests</h2>{!state.requests.length && <p>No requests in your investigation scope.</p>}{state.requests.filter(r => !caseId || r.action.case_id === caseId).map(r => <article key={r.request_id}>
        <h3>{r.action.operation} · {r.action.case_id}</h3><p>{r.agent_id} · {r.status} · Request {r.request_id}</p>
        {r.status === 'pending' && <><button disabled={busy} onClick={() => void decide(r.request_id, true)}>Approve exact request</button><button disabled={busy} onClick={() => void decide(r.request_id, false)}>Reject</button></>}
      </article>)}</section>
      <section className="transactions-panel"><h2>Security audit history</h2>{state.events.map((e, i) => <p key={i}>{new Date(e.timestamp * 1000).toLocaleString()} · {e.actor} · {e.decision} · {e.reason}</p>)}</section>
    </>}
  </main>;
}
