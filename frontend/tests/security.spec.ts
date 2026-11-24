import { expect, test } from '@playwright/test';
test('human approval desk displays scope and sends only the exact decision', async ({ page }) => {
  let approved = false;
  await page.route('**/api/v1/security/dashboard', route => route.fulfill({ json: {
    permissions: [{agent_id:'agent1',role:'investigator',cases:['case1'],tools:['case_report: human approval']}],
    requests: [{request_id:'request1',agent_id:'agent1',action:{operation:'case_report',case_id:'case1'},status:approved?'approved':'pending',approver:null}],
    events: [{actor:'agent1',decision:'REQUIRE_APPROVAL',reason:'human_review_required',timestamp:1000,request_id:'request1'}],
  }}));
  await page.route('**/api/v1/security/requests/request1/approval', route => {
    expect(route.request().postDataJSON()).toEqual({approved:true});
    expect(route.request().headers().authorization).toBe('Bearer human-test-credential');
    approved=true; return route.fulfill({json:{status:'approved'}});
  });
  await page.goto('/#security');
  await page.getByLabel('Human approver credential').fill('human-test-credential');
  await page.getByRole('button',{name:'Load security activity'}).click();
  await expect(page.getByRole('heading',{name:'case_report · case1'})).toBeVisible();
  await page.getByRole('button',{name:'Approve exact request'}).click();
  await expect(page.getByText('agent1 · approved · Request request1')).toBeVisible();
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('human-test-credential');
  await page.getByRole('button',{name:'Clear session'}).click();
  await expect(page.getByLabel('Human approver credential')).toHaveValue('');
});
test('malformed security response disables approval controls', async ({ page }) => {
  await page.route('**/api/v1/security/dashboard', route => route.fulfill({json:{requests:'unsafe'}}));
  await page.goto('/#security');
  await page.getByLabel('Human approver credential').fill('test');
  await page.getByRole('button',{name:'Load security activity'}).click();
  await expect(page.getByRole('alert')).toContainText('Invalid security response');
  await expect(page.getByRole('button',{name:'Approve exact request'})).toHaveCount(0);
});

test('malformed engine response blocks advancing until a valid reload', async ({page}) => {
  let malformed = false;
  const run = {run_id:'run1',case_id:'case1',provider_mode:'deterministic',state:'created',version:0,busy:false,plan:[],steps:[],report:null,error:null,pending_request_id:null};
  await page.route('**/api/v1/security/runs**', route => route.fulfill({json:malformed ? {case_id:'wrong-case'} : run}));
  await page.goto('/#security?case=case1');
  await page.getByLabel('Human approver credential').fill('human-test-credential');
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByRole('button',{name:'Start investigation',exact:true}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('created');
  malformed = true;
  await engine.getByRole('button',{name:'Run next bounded step'}).click();
  await expect(engine.getByRole('alert')).toContainText('Invalid investigation response');
  await expect(engine.getByRole('button',{name:'Run next bounded step'})).toBeDisabled();
  malformed = false;
  await engine.getByRole('button',{name:'Reload investigation status'}).click();
  await expect(engine.getByRole('button',{name:'Run next bounded step'})).toBeEnabled();
});

test('empty history and interrupted uncertain runs cannot resume', async ({page}) => {
  const run = {run_id:'run1',case_id:'case1',provider_mode:'deterministic',state:'paused',version:2,busy:false,plan:[],steps:[],report:null,error:'uncertain_execution; reconciliation_required',pending_request_id:null,interrupted:true,resumable:false,created_at:1000};
  let empty = true;
  await page.route('**/api/v1/security/runs**', route => route.fulfill({json:route.request().url().includes('?') ? {runs:empty?[]:[run]} : run}));
  await page.goto('/#security?case=case1');
  await page.getByLabel('Human approver credential').fill('human-test-credential');
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByRole('button',{name:'Load investigation history'}).click();
  await expect(engine.getByTestId('engine-history')).toContainText('No saved investigations');
  empty = false;
  await engine.getByRole('button',{name:'Load investigation history'}).click();
  await engine.getByRole('button',{name:'Open investigation run1'}).click();
  await expect(engine.getByText(/Execution outcome is uncertain/)).toBeVisible();
  await expect(engine.getByRole('button',{name:'Resume investigation safely'})).toHaveCount(0);
  await expect(engine.getByRole('button',{name:'Run next bounded step'})).toHaveCount(0);
});

test('provider configuration is not misrepresented as verified availability', async ({page}) => {
  let configured = true;
  await page.route('**/api/v1/security/provider?**', route => route.fulfill({json:{provider:'openai',model:'gpt-6.1-terra',configured,transport:'live_http',last_outcome:'not_checked',availability:'unverified'}}));
  await page.goto('/#security?case=case1');
  await page.getByLabel('Human approver credential').fill('human-test-credential');
  await page.getByRole('button',{name:'Check AI configuration'}).click();
  await expect(page.getByTestId('provider-status')).toContainText('Real provider configured');
  await expect(page.getByTestId('provider-status')).toContainText('does not verify live access');
  configured = false;
  await page.getByRole('button',{name:'Check AI configuration'}).click();
  await expect(page.getByTestId('provider-status')).toContainText('Real provider unavailable');
});

test('Gemini failure displays identity and sanitized error without a successful report', async ({page}) => {
  const identity = {provider:'gemini',model:'gemini-3.5-flash-lite',transport:'mock_http'};
  await page.route('**/api/v1/security/provider?**', route => route.fulfill({json:{...identity,configured:true,last_outcome:'provider_rate_limited',availability:'provider_rate_limited'}}));
  await page.route('**/api/v1/security/runs', route => route.fulfill({json:{
    run_id:'failed_gemini',case_id:'case1',provider_mode:'provider',provider_identity:identity,
    state:'failed',version:1,busy:false,plan:[],steps:[],report:null,
    error:'provider_rate_limited',pending_request_id:null,
  }}));
  await page.goto('/#security?case=case1');
  await page.getByLabel('Human approver credential').fill('synthetic-human-browser-credential');
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByRole('button',{name:'Check AI configuration'}).click();
  await expect(engine.getByTestId('provider-status')).toContainText('gemini / gemini-3.5-flash-lite');
  await expect(engine.getByTestId('provider-status')).toContainText('provider_rate_limited');
  await engine.getByLabel('Analysis mode').selectOption('provider');
  await engine.getByRole('button',{name:'Start investigation',exact:true}).click();
  await expect(engine.getByTestId('engine-status')).toContainText('failed');
  await expect(engine.getByTestId('engine-report')).toHaveCount(0);
  await expect(engine.getByRole('button',{name:'Run next bounded step'})).toHaveCount(0);
  await expect(engine).toContainText('provider_rate_limited');
  await expect(engine).not.toContainText('successful_response');
});

test('historical narrative report is not labeled as validated structured claims', async ({page}) => {
  await page.route('**/api/v1/security/runs', route => route.fulfill({json:{
    run_id:'legacy_run',case_id:'case1',provider_mode:'provider',state:'completed',version:1,
    busy:false,plan:[],steps:[],error:null,pending_request_id:null,
    report:{fingerprint:'legacy-fingerprint',human_review_status:'needs_more_evidence',model_hypotheses:[]},
  }}));
  await page.goto('/#security?case=case1');
  await page.getByLabel('Human approver credential').fill('synthetic-human-browser-credential');
  const engine = page.getByRole('region',{name:'Investigation engine'});
  await engine.getByRole('button',{name:'Start investigation',exact:true}).click();
  await expect(engine).toContainText('Historical report: generated before structured claim validation');
  await expect(engine).not.toContainText('Structured facts match the authorized evidence snapshot');
});
