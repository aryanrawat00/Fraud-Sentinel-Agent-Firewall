import { test, expect, type APIRequestContext } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';

let server: ChildProcess;
let startupError = '';
const auditKey = randomBytes(32).toString('hex');
const agent = randomBytes(32).toString('hex');
const human = randomBytes(32).toString('hex');
const caseId = 'case_agent_workflow';
const dataset = 'browser_' + randomBytes(8).toString('hex');
const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

async function startServer(request: APIRequestContext, mockedLLM: false | 'openai' | 'gemini' = false) {
  startupError = '';
  const root = path.resolve('..');
  server = spawn(path.resolve(root, '../Fraud-Sentinel/.venv/Scripts/python.exe'), mockedLLM ? ['-B', path.join(root, 'tests/support/run_llm_browser.py'), ...(mockedLLM === 'gemini' ? ['--gemini'] : [])] : ['-B', '-m', 'scripts.run_agent_firewall'], {
    cwd: root, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'],
    env: { ...process.env, PYTHONPATH: path.join(root, 'backend'),
      FRAUDSENTINEL_FIREWALL_DATASET: dataset,
      FRAUDSENTINEL_LLM_PROVIDER: 'disabled', FRAUDSENTINEL_LLM_API_KEY: '',
      FRAUDSENTINEL_FIREWALL_PORT: '8004', FRAUDSENTINEL_FIREWALL_SEED_WORKFLOW: '1',
      FRAUDSENTINEL_FIREWALL_AUDIT_KEY: auditKey,
      FRAUDSENTINEL_FIREWALL_CREDENTIALS: JSON.stringify([
        {token:agent,id:'browser_agent',kind:'agent',role:'investigator',owner_id:'user_demo_analyst',cases:[caseId]},
        {token:human,id:'browser_human',kind:'human',role:'approver',owner_id:'user_demo_analyst',cases:[caseId]},
      ]),
    },
  });
  server.once('error', error => { startupError = `Launch failed: ${error.name}`; });
  server.stderr?.on('data', chunk => {
    startupError = (startupError + String(chunk).replaceAll(agent, '[REDACTED]').replaceAll(human, '[REDACTED]').replaceAll(auditKey, '[REDACTED]')).slice(-4000);
  });
  await expect.poll(async () => {
    if (server.exitCode !== null) throw new Error('Isolated server failed: ' + startupError);
    try { return (await request.get('http://127.0.0.1:8004/api/v1/security/dashboard', {headers:auth(human)})).status(); }
    catch { return 0; }
  }, {timeout:45000, message:'Isolated API startup'}).toBe(200).catch(error => { throw new Error(`${error.message}\n${startupError}`); });
}

test.beforeAll(async ({request}) => { test.setTimeout(60000); await startServer(request); });

async function stopServer() {
  if (server && server.exitCode === null) {
    await new Promise<void>(resolve => { server.once('exit', () => resolve()); server.kill(); });
  }
}

test.afterAll(stopServer);

test('real investigation flows through human approval, agent execution and case review', async ({ page, request }) => {
  const proposal = await request.post('/api/v1/security/requests', {headers:auth(agent),data:{operation:'case_report',case_id:caseId}});
  expect(proposal.status()).toBe(200);
  const {request_id: id} = await proposal.json();
  expect((await request.post(`/api/v1/security/requests/${id}/execute`,{headers:auth(agent)})).status()).toBe(403);
  await page.goto(`/#security?case=${caseId}`);
  await page.getByLabel('Human approver credential').fill(human);
  await page.getByRole('button',{name:'Load case findings and provenance'}).click();
  const context = page.getByTestId('security-case-context');
  await expect(context).toContainText('critical');
  await expect(context).toContainText('source_transaction_ids');
  await expect(context).toContainText('report_');
  await page.getByRole('button',{name:'Load security activity'}).click();
  await page.getByRole('button',{name:'Approve exact request'}).click();
  await expect(page.getByText(`browser_agent · approved · Request ${id}`)).toBeVisible();
  const executed = await request.post(`/api/v1/security/requests/${id}/execute`,{headers:auth(agent)});
  expect(executed.status()).toBe(200);
  const result = await executed.json();
  expect(result.evidence.length).toBeGreaterThan(0);
  expect(result.reports.length).toBe(1);
  expect(result.relationships.edges.length).toBeGreaterThan(0);
  expect((await request.post(`/api/v1/security/requests/${id}/execute`,{headers:auth(agent)})).status()).toBe(403);
  await page.getByRole('button',{name:'Load security activity'}).click();
  await expect(page.getByText(/browser_agent · EXECUTED · bounded_read_completed/)).toBeVisible();
  expect((await request.get('/api/v1/security/investigations/'+caseId,{headers:auth(agent)})).status()).toBe(403);
  expect((await request.get('http://127.0.0.1:8004/api/v1/intelligence/dashboard')).status()).toBe(404);
});

test('bounded investigation engine produces a grounded report for human review', async ({page}) => {
  await page.goto(`/#security?case=${caseId}`);
  await page.getByLabel('Human approver credential').fill(human);
  const engine = page.getByRole('region', {name:'Investigation engine'});
  await engine.getByRole('button', {name:'Start investigation', exact:true}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('created');
  await engine.getByRole('button', {name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('ready');
  for (let i = 1; i <= 5; i++) {
    await engine.getByRole('button', {name:'Run next bounded step'}).click();
    await expect(engine.getByTestId('engine-status')).toContainText(`${i}/6 steps completed`);
  }
  await engine.getByRole('button', {name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('awaiting_approval');
  await expect(engine.getByTestId('engine-report')).toHaveCount(0);
  await page.getByRole('button',{name:'Load security activity'}).click();
  await page.getByRole('button',{name:'Approve exact request'}).click();
  await engine.getByRole('button', {name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('completed');
  const report = engine.getByTestId('engine-report');
  await expect(report).toContainText('scenario_high');
  await expect(report).toContainText('source_transactions');
  await expect(report).toContainText('not proof of fraud');
  await expect(report).toContainText('"model_hypotheses": []');
  await expect(engine.getByTestId('engine-review-status')).toContainText('pending');
  await engine.getByRole('button', {name:'Record review without fraud determination'}).click();
  await expect(engine.getByTestId('engine-review-status')).toContainText('reviewed_no_determination');
  await page.getByRole('button',{name:'Clear session'}).click();
  await expect(engine.getByTestId('engine-report')).toHaveCount(0);
  await expect(engine.getByRole('button',{name:'Start investigation',exact:true})).toBeDisabled();
});

test('unconfigured AI provider fails explicitly without mock fallback', async ({page}) => {
  await page.goto(`/#security?case=${caseId}`);
  await page.getByLabel('Human approver credential').fill(human);
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByLabel('Analysis mode').selectOption('provider');
  await engine.getByRole('button',{name:'Start investigation',exact:true}).click();
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('failed');
  await expect(engine.getByRole('alert')).toContainText('no operational AI configured');
  await expect(engine.getByTestId('engine-report')).toHaveCount(0);
});


test('history, review and lifecycle survive browser refresh and actual backend restart', async ({page,request}) => {
  test.setTimeout(60000);
  const headers = auth(human);
  const list = await request.get(`/api/v1/security/runs?case_id=${caseId}`, {headers});
  const saved = (await list.json()).runs.find((r: {state:string}) => r.state === 'completed');
  expect(saved).toBeTruthy();
  await stopServer();
  await startServer(request);
  await page.goto(`/#security?case=${caseId}`);
  await page.getByLabel('Human approver credential').fill(human);
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByRole('button',{name:'Load investigation history'}).click();
  await engine.getByRole('button',{name:`Open investigation ${saved.run_id}`}).click();
  await expect(engine.getByTestId('engine-review-status')).toContainText('reviewed_no_determination');
  await expect(engine.getByTestId('engine-report')).toContainText('scenario_high');
  await engine.getByRole('button',{name:'Start another investigation'}).click();
  await engine.getByRole('button',{name:'Start investigation',exact:true}).click();
  await engine.getByRole('button',{name:'Pause investigation'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('paused');
  const runId = (await engine.getByText(/^Run [a-f0-9]{32}$/).textContent())!.slice(4);
  await page.reload();
  await page.getByLabel('Human approver credential').fill(human);
  await engine.getByRole('button',{name:'Load investigation history'}).click();
  await engine.getByRole('button',{name:`Open investigation ${runId}`}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('paused');
  await engine.getByRole('button',{name:'Resume investigation safely'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('created');
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('ready');
  await engine.getByRole('button',{name:'Cancel investigation'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('cancelled');
  await page.reload();
  await page.getByLabel('Human approver credential').fill(human);
  await engine.getByRole('button',{name:'Load investigation history'}).click();
  await engine.getByRole('button',{name:`Open investigation ${runId}`}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('cancelled');
});


for (const provider of ['openai', 'gemini'] as const) {
test(`${provider} adapter with mocked HTTP preserves approval and shows AI provenance`, async ({page,request}) => {
  test.setTimeout(60000);
  await stopServer();
  await startServer(request,provider);
  await page.goto(`/#security?case=${caseId}`);
  await page.getByLabel('Human approver credential').fill(human);
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByRole('button',{name:'Check AI configuration'}).click();
  await expect(engine.getByTestId('provider-status')).toContainText('Mocked HTTP test adapter');
  await expect(engine.getByTestId('provider-status')).toContainText(provider);
  await expect(engine.getByTestId('provider-status')).toContainText('not_checked');
  await engine.getByLabel('Analysis mode').selectOption('provider');
  await engine.getByRole('button',{name:'Start investigation',exact:true}).click();
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('ready');
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('1/2 steps completed');
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('awaiting_approval');
  await expect(engine.getByTestId('engine-report')).toHaveCount(0);
  await page.getByRole('button',{name:'Load security activity'}).click();
  await page.getByRole('button',{name:'Approve exact request'}).click();
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('completed');
  await expect(engine.getByTestId('engine-report')).toContainText('verified_against_snapshot');
  await expect(engine.getByTestId('engine-report')).toContainText('evidence-claims-v1');
  await expect(engine.getByTestId('engine-report')).toContainText('unknown_in_supplied_evidence');
  await expect(engine.getByTestId('engine-report')).toContainText('unverified');
  await expect(engine.getByTestId('engine-report')).toContainText('mock_http');
  await expect(engine.getByTestId('engine-report')).toContainText('insufficient');
  await engine.getByLabel('Review notes', {exact:false}).fill('Investigate supporting evidence.');
  await engine.getByRole('button',{name:'Request more evidence'}).click();
  await expect(engine.getByTestId('engine-review-status')).toContainText('needs_more_evidence');
  await engine.getByRole('button',{name:'Check AI configuration'}).click();
  await expect(engine.getByTestId('provider-status')).toContainText('successful_response');
});

}
