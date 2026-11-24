import { useState } from 'react';

type Run = {
  run_id: string; case_id: string; provider_mode: string; state: string; version: number;
  busy: boolean; pending_request_id: string | null; error: string | null;
  interrupted?: boolean; resumable?: boolean; created_at?: number;
  provider_identity?: {provider:string;model:string;transport:string} | null;
  plan: { operation: string }[];
  steps: { operation: string; decision: string; status: string; request_id: string }[];
  report: null | Record<string, unknown> & { fingerprint: string; human_review_status: string };
};

function parseRun(value: unknown, caseId: string): Run {
  const record = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
  if (!record(value) || value.case_id !== caseId || typeof value.run_id !== 'string'
    || typeof value.provider_mode !== 'string' || typeof value.state !== 'string'
    || !['created', 'planning', 'ready', 'investigating', 'awaiting_approval', 'paused', 'completed', 'failed', 'cancelled'].includes(value.state)
    || !Number.isSafeInteger(value.version) || typeof value.busy !== 'boolean'
    || !(value.provider_identity === undefined || value.provider_identity === null || (record(value.provider_identity) && ['openai','gemini'].includes(String(value.provider_identity.provider)) && typeof value.provider_identity.model === 'string' && ['live_http','mock_http'].includes(String(value.provider_identity.transport))))
    || !Array.isArray(value.plan) || !value.plan.every(p => record(p) && typeof p.operation === 'string')
    || !Array.isArray(value.steps) || !value.steps.every(s => record(s) && ['operation', 'decision', 'status', 'request_id'].every(k => typeof s[k] === 'string'))
    || !(value.report === null || (record(value.report) && typeof value.report.fingerprint === 'string' && typeof value.report.human_review_status === 'string'))) {
    throw new Error('Invalid investigation response; controls disabled.');
  }
  return value as unknown as Run;
}

export default function InvestigationEngine({ caseId, credential }: { caseId: string; credential: string }) {
  const [run, setRun] = useState<Run>();
  const [mode, setMode] = useState('deterministic');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<{run_id:string; state:string; created_at:number}[]>();
  const [notes, setNotes] = useState('');
  const [provider, setProvider] = useState<{configured:boolean;provider:string;model:string|null;transport:string;last_outcome:string}>();
  async function checkProvider() {
    setBusy(true); setError('');
    try {
      const response = await fetch(`/api/v1/security/provider?case_id=${encodeURIComponent(caseId)}`, {headers:{Authorization:`Bearer ${credential}`}});
      if (!response.ok) throw new Error('Provider configuration unavailable or access refused.');
      const value = await response.json();
      if (typeof value.configured !== 'boolean' || !['openai','gemini','none'].includes(value.provider) || !['live_http','mock_http','none'].includes(value.transport) || typeof value.last_outcome !== 'string' || !(value.model === null || typeof value.model === 'string')) throw new Error('Invalid provider status.');
      setProvider(value);
    } catch(e) { setProvider(undefined); setError(e instanceof Error ? e.message : 'Provider status unavailable'); }
    finally { setBusy(false); }
  }
  async function loadHistory() {
    setBusy(true); setError('');
    try {
      const response = await fetch(`/api/v1/security/runs?case_id=${encodeURIComponent(caseId)}`, {headers:{Authorization:`Bearer ${credential}`}});
      if (!response.ok) throw new Error('Investigation history unavailable or access refused.');
      const value = await response.json();
      if (!Array.isArray(value.runs) || !value.runs.every((r: Record<string, unknown>) => r && typeof r.run_id === 'string' && r.case_id === caseId && typeof r.state === 'string' && typeof r.created_at === 'number' && Number.isFinite(new Date(r.created_at*1000).getTime()))) throw new Error('Invalid investigation history response.');
      setHistory(value.runs);
    } catch (e) { setHistory(undefined); setError(e instanceof Error ? e.message : 'History unavailable'); }
    finally { setBusy(false); }
  }
  async function call(path: string, body?: object) {
    setBusy(true); setError('');
    try {
      const response = await fetch(`/api/v1/security/runs${path}`, {
        method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${credential}`, 'Content-Type': 'application/json' },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) throw new Error(response.status === 409 ? 'Run changed. Reload its status before continuing.' : 'Investigation unavailable or access refused.');
      setRun(parseRun(await response.json(), caseId));
      setNotes('');
    } catch (e) { setError(e instanceof Error ? e.message : 'Investigation unavailable'); }
    finally { setBusy(false); }
  }
  const terminal = run && ['completed', 'failed', 'cancelled'].includes(run.state);
  return <section className="transactions-panel" aria-label="Investigation engine">
    <h2>Investigation engine</h2>
    <p>Bounded case reads through the security firewall. Deterministic mode does not use an LLM. Provider mode sends authorized case projections to the configured service; facts are checked against that snapshot; inferences remain unverified and require human review.</p>
    <button disabled={busy || !credential || !/^[A-Za-z0-9_-]{1,64}$/.test(caseId)} onClick={() => void checkProvider()}>Check AI configuration</button>
    <p data-testid="provider-status">{provider ? (!provider.configured ? `Real provider unavailable: configuration or credentials missing. ${provider.provider} / ${provider.model ?? 'none'}. Last outcome: ${provider.last_outcome}.` : `${provider.transport === 'mock_http' ? 'Mocked HTTP test adapter' : 'Real provider configured'}: ${provider.provider} / ${provider.model}. Last outcome: ${provider.last_outcome}. Configuration alone does not verify live access.`) : 'Provider status not checked. No connectivity claim is made.'}</p>
    <p>Investigations and reviews are saved. After refreshing or returning, enter your credential and load this case’s history. Interrupted tool execution is never retried automatically.</p>
    <button disabled={busy || !credential || !/^[A-Za-z0-9_-]{1,64}$/.test(caseId)} onClick={() => void loadHistory()}>Load investigation history</button>
    {history && <div data-testid="engine-history"><h3>Investigation history</h3>{history.length === 0 && <p>No saved investigations for this case.</p>}
      <ul>{history.map(item => <li key={item.run_id}>{new Date(item.created_at*1000).toLocaleString()} · {item.state} <button disabled={busy} onClick={() => void call(`/${item.run_id}`)}>Open investigation {item.run_id}</button></li>)}</ul>
    </div>}
    {!run && <>
      <label>Analysis mode <select value={mode} onChange={e => setMode(e.target.value)}>
        <option value="deterministic">Deterministic development mode (no LLM)</option>
        <option value="provider">AI provider (requires server configuration)</option>
      </select></label>
      <button disabled={busy || !credential || !/^[A-Za-z0-9_-]{1,64}$/.test(caseId)} onClick={() => void call('', {case_id: caseId, mode})}>Start investigation</button>
    </>}
    {error && <p role="alert">{error}</p>}
    {run && <>
      <p data-testid="engine-status">Status: {run.state} · Mode: {run.provider_mode} · {run.steps.filter(s => s.status === 'executed').length}/{run.plan.length} steps completed</p>
      <p>Run {run.run_id}</p>
      {run.provider_identity && <p>Run provider: {run.provider_identity.provider} / {run.provider_identity.model} · {run.provider_identity.transport === 'mock_http' ? 'Mocked HTTP test' : 'Live API transport'}</p>}
      <button disabled={busy} onClick={() => void call(`/${run.run_id}`)}>Reload investigation status</button>
      {!terminal && <>
        {run.state !== 'paused' && <><button disabled={busy || run.busy || !!error} onClick={() => void call(`/${run.run_id}/advance`, {version:run.version})}>Run next bounded step</button>
          <button disabled={busy || run.busy || !!error} onClick={() => void call(`/${run.run_id}/pause`, {version:run.version})}>Pause investigation</button></>}
        {run.state === 'paused' && run.resumable && <button disabled={busy || run.busy || !!error} onClick={() => void call(`/${run.run_id}/resume`, {version:run.version})}>Resume investigation safely</button>}
        <button disabled={busy} onClick={() => void call(`/${run.run_id}/cancel`, {version:run.version})}>Cancel investigation</button>
      </>}
      {run.interrupted && <p>Interrupted investigation. {run.resumable ? 'A saved checkpoint is available; resume requires fresh authorization.' : 'Execution outcome is uncertain. Inspect the firewall audit and reconcile before starting any replacement work. Resume is blocked.'}</p>}
      {run.error && <p role="alert">{run.error}</p>}
      <h3>Investigation plan</h3><ol>{run.plan.map(p => <li key={p.operation}>{p.operation}</li>)}</ol>
      <h3>Tool decisions and progress</h3><ul>{run.steps.map(s => <li key={s.request_id}>{s.operation} · {s.decision} · {s.status} · Request {s.request_id}</li>)}</ul>
      {run.pending_request_id && <p>Human approval is required for request {run.pending_request_id}. This protected read includes scoped amounts, currencies and UTC timestamps for provider analysis. Load security activity below, inspect the case evidence, then approve or reject the exact request. Resume with the next bounded step.</p>}
      {run.report && <>
        <h3>Explainable investigation report</h3>
        <p>{run.report.claim_contract === 'evidence-claims-v1' ? 'Structured facts match the authorized evidence snapshot. Inferences and unknowns are separate; this does not establish fraud or external truth.' : 'Historical report: generated before structured claim validation. Narrative claims have not been verified under the current contract.'}</p>
        <p data-testid="engine-review-status">Human review: {run.report.human_review_status}</p>
        <pre data-testid="engine-report" style={{whiteSpace:'pre-wrap', overflowWrap:'anywhere'}}>{JSON.stringify(run.report, null, 2)}</pre>
        <p>Review the source references and limitations. These controls record review only; they cannot authorize consequential conclusions or external actions.</p>
        {run.report.human_review_status === 'pending' && <>
          <label>Review notes (do not include credentials or personal financial data) <textarea maxLength={1000} value={notes} onChange={e => setNotes(e.target.value)} /></label>
          <button disabled={busy || !!error} onClick={() => void call(`/${run.run_id}/review`, {version:run.version, fingerprint:run.report!.fingerprint, decision:'reviewed_no_determination', notes})}>Record review without fraud determination</button>
          <button disabled={busy || !!error} onClick={() => void call(`/${run.run_id}/review`, {version:run.version, fingerprint:run.report!.fingerprint, decision:'needs_more_evidence', notes})}>Request more evidence</button>
        </>}
      </>}
      {terminal && <button disabled={busy} onClick={() => { setRun(undefined); setError(''); }}>Start another investigation</button>}
    </>}
  </section>;
}
