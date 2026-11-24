> Historical milestone/reference document. Results and limitations below describe the recorded milestone, not fresh verification or the current setup. Use [the current README](../README.md), [offline runbook](demo-runbook.md) and [current readiness results](demo-readiness.md). Machine-specific paths are redacted placeholders; do not execute historical commands as current setup instructions.

# Gemini integration (Milestone 7)

Gemini is an optional reasoning provider in the existing isolated development
snapshot, `<project-root>`. OpenAI remains available. Neither
provider is enabled by default; there is no automatic provider or paid fallback.
Implementation and tests use synthetic data and mocked HTTP only. Live access,
account eligibility and model quality have not been verified with credentials.

Milestone 10 updates the shared analysis contract to `investigation-v2` with
[structured evidence-bound claims](structured-claims.md). The Milestone 7 test
receipt below remains historical.

## Verified API choices

Official Google documentation checked on 2026-11-23:

- [Model](https://aistudio.google.com/docs/models/gemini-3.5-flash-lite):
  default `gemini-3.5-flash-lite`, with structured output support.
- [generateContent](https://aistudio.google.com/api-reference/generate-content/generate-content):
  POST to `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`.
  This supported API fits the existing single-request provider interface; no agent
  sessions, hosted tools or new SDK are needed.
- [API keys](https://aistudio.google.com/docs/api-key): header authentication using
  `x-goog-api-key`. The credential is never placed in a URL or request body.
- [Schema support](https://aistudio.google.com/docs/structured-output) and
  [generation configuration](https://aistudio.google.com/api-reference/generate-content):
  `responseMimeType=application/json`, `responseJsonSchema` and one candidate.
  Server-side Pydantic validation remains authoritative, including constraints
  that Google may ignore during generation.

The configured model must be a bounded `gemini-...` identifier, not a URL or path.
Changing it does not imply that the model exists, supports this schema, or is free.
The provider identity records the requested model, transport and investigation
contract. Existing run bindings reject a provider/model switch during continuation.

## Configuration and private local setup

Create a key privately in [Google AI Studio](https://aistudio.google.com/api-keys)
for the intended project. Confirm that the project uses the free tier and that the
chosen model has available quota. Do not enable billing just to complete this setup.
Some projects require Google's verification. Do not paste keys in chat, source,
shell history or logs. No existing `.env` file needs editing.

| Variable | Meaning |
| --- | --- |
| `FRAUDSENTINEL_LLM_PROVIDER` | `disabled` (default), `openai`, or `gemini` |
| `FRAUDSENTINEL_GEMINI_API_KEY` | Gemini credential; empty means unconfigured |
| `FRAUDSENTINEL_GEMINI_MODEL` | Defaults to `gemini-3.5-flash-lite` |
| `FRAUDSENTINEL_LLM_DEADLINE_SECONDS` | Shared total deadline; default 45, allowed 1–90 |
| `FRAUDSENTINEL_LLM_MAX_OUTPUT_TOKENS` | Shared output cap; default 4096, allowed 1024–8192 |
| `FRAUDSENTINEL_LLM_RETRIES` | Shared retry cap; default 1, allowed 0–1; use 0 initially |

`FRAUDSENTINEL_LLM_MODEL` and `FRAUDSENTINEL_LLM_API_KEY` retain their OpenAI
meaning. Generic `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, reference
example files and `.env` files are not automatically loaded by these adapters.
Set variables in the same shell that starts the process; restart an existing
server after changing them. The shared virtual environment is used read-only;
`PYTHONPATH` selects the isolated snapshot's code.

For a configuration-only check in interactive PowerShell:

```powershell
Set-Location <project-root>
$env:PYTHONPATH = '<project-root>\backend'
$env:FRAUDSENTINEL_LLM_PROVIDER = 'gemini'
$env:FRAUDSENTINEL_GEMINI_MODEL = 'gemini-3.5-flash-lite'
$env:FRAUDSENTINEL_LLM_RETRIES = '0'
& <historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.check_llm_provider --prompt-key
```

The hidden prompt supplies a key only to that checking process. No HTTP request
occurs without `--live`. `configured=true` confirms nonblank input, not accepted
credentials, free quota, connectivity or investigation quality. Hidden input fails
closed if it cannot be secured. This command does not configure a running server.

Only after checking quota and privacy terms, an optional explicit smoke check is:

```powershell
& <historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.check_llm_provider --prompt-key --live
```

This sends a synthetic planning request and may be billed if your project/model
uses paid access. It does not access a database or execute investigation tools.
No such live check was performed during implementation.

To configure the local server, provision the key into the process environment using
a secret manager or a private PowerShell prompt, then start it in that same shell:

```powershell
$geminiSecret = Read-Host 'Gemini API key' -AsSecureString
$geminiPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($geminiSecret)
try {
  $env:FRAUDSENTINEL_GEMINI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($geminiPointer)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($geminiPointer)
  $geminiSecret.Dispose()
}
try {
  & <historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.run_agent_firewall
} finally {
  Remove-Item Env:FRAUDSENTINEL_GEMINI_API_KEY -ErrorAction SilentlyContinue
}
```

First provision the existing firewall identities, audit key and **synthetic**
dataset according to [firewall-integration.md](firewall-integration.md). This
milestone changes no launcher, database, migration or existing dataset. Launching
the server does not contact Gemini; advancing a provider investigation does.

In the Security workspace, authenticate as the authorized human for the synthetic
case, check AI configuration, select provider analysis, and start a **new**
investigation. Advance the bounded steps. Approve the exact protected case-report
request before analysis can run. Review the resulting cited hypotheses as
unverified, alongside the recorded facts, and record the human review. Provider
planning and analysis consume requests; the free tier is not unlimited.

To return to OpenAI, stop the server, set
`$env:FRAUDSENTINEL_LLM_PROVIDER = 'openai'`, provision its existing key/model as
described in [real-llm-integration.md](real-llm-integration.md), restart and create
a new investigation. Existing runs never silently adopt the replacement provider.

## Reliability and security

The adapter uses existing `httpx`, fixed origin, no redirects or environment proxy
inheritance, a total deadline, bounded response/input sizes and at most one retry
for 429 or selected transient server errors. Cancellation propagates. There is no
automatic retry of a failed investigation or fallback to another model/provider.
Errors expose static reason codes, never response bodies, headers or credentials.

Only one completed model text candidate is accepted. Malformed JSON, duplicate
keys, truncated responses, refusals, tools/code/media, unexpected schema fields and
out-of-contract actions are rejected. Thoughts are not returned. Analysis now uses
the same structured claim validation as OpenAI: exact source-field/value checks,
controlled inference and recommendation templates, and explicit unknowns. No
free-form model prose is accepted in new reports. Verification is against the
authorized snapshot, not independent real-world truth; human review remains necessary.

The firewall remains the sole tool executor. Default deny, case ownership,
authorization, exact approval binding, expiry, replay protection and durable audit
logging are unchanged. Gemini has no database, filesystem, shell, browser or
financial-action capability. Persistence/recovery use the existing signed store;
no migration or reset is introduced.

## Free tier, privacy and troubleshooting

Google currently lists free input/output for the default model, with separate
paid pricing. Free access, models, quotas and policies may change. The adapter
cannot inspect or enforce your billing tier. Use only synthetic records; no real
customer or financial information. See [pricing](https://aistudio.google.com/docs/pricing#gemini-3.5-flash-lite).

Limits vary by model and project and include RPM, input TPM and daily requests.
Check your project's actual limits in AI Studio; multiple keys do not create
independent quota. See [rate limits](https://aistudio.google.com/docs/rate-limits).

Unpaid-service inputs and outputs may be used to improve Google products and may
be reviewed by humans. Terms depend on region and service tier. Review the current
[Google terms](https://aistudio.google.com/docs/terms) before sending any data;
this integration does not provide a zero-retention or confidential-data guarantee.

| Symptom | Safe next action |
| --- | --- |
| `configured=false` | Check the Gemini-specific variable in the launching shell, or use the hidden prompt for the check. |
| `provider_authentication_failed` | Check key permissions, project access and restrictions privately in AI Studio (401/403). |
| `provider_rate_limited` | Check model/project quota; wait or reduce usage. No automatic paid fallback. |
| `provider_failed` | Non-success HTTP (including 400/404), exhausted server retries or network failure; check model support and local connectivity. Raw service errors are withheld. |
| `timeout` / `provider_timeout` | The bounded request deadline expired; inspect connectivity and output limits. |
| `provider_incomplete` | Output did not finish normally, e.g. token limit. No partial investigation output is accepted. |
| `provider_refused` | Google blocked or refused the response. Do not bypass safety filtering. |
| `provider_invalid_output` | Output failed strict envelope/schema checks. No result is promoted to verified facts. |
| Provider configuration changed | Restore the original provider configuration to continue that run or create a new investigation. |

Provider status reports the selected model and last in-process outcome; restart
returns availability to unverified. Persisted investigation errors and identities
remain available through the authorized investigation history.

## Local verification receipt

2026-11-23, synthetic data and mocked provider transports:

- Backend: **324 passed, 6 skipped, 0 failed** (36.54 seconds).
  Includes 48 new Gemini cases and existing OpenAI, configuration, firewall,
  investigation and persistence regressions. Five PostgreSQL tests and one
  separately hosted sandbox concurrency test remain opt-in and were not run.
- Browser: **29 passed, 0 failed**: security/provider workflows 11 (24.8 seconds),
  foundation/investigation workflows 18 (19.3 seconds). Both provider adapters run
  through actual approval and review using mocked HTTP. Browser fixtures use
  isolated synthetic SQLite, including the older test with PostgreSQL in its name.
- TypeScript and production build passed. Ruff lint passed; 77 Python files passed
  formatting checks. The project has no separate frontend lint/format script.
- One existing Starlette TestClient deprecation warning remains. The first broad
  pytest invocation collected archived test copies under `tmp`; specifying the
  active directories resolved those duplicate-module collection errors without
  changing source or archives.

Reproduce backend checks from the snapshot root with `PYTHONPATH` as above and
`RUN_POSTGRES_TESTS`, `RUN_POSTGRES_READONLY_TESTS`, `RUN_PHASE2_POSTGRES_TESTS`,
and `RUN_SANDBOX_HTTP_TESTS` all set to `0`:

```powershell
& <historical-checkout-root>\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider -c backend/pyproject.toml tests/unit tests/integration tests/security -q
& <historical-checkout-root>\.venv\Scripts\ruff.exe check --config backend/pyproject.toml --no-cache backend tests
& <historical-checkout-root>\.venv\Scripts\ruff.exe format --config backend/pyproject.toml --no-cache --check backend tests
```

From `frontend`, using the already-installed local dependencies and browsers:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = '<historical-checkout-root>\tmp\playwright'
npm run typecheck
npm run build
npm run test:e2e -- --config playwright.security.config.ts --reporter=list
npm run test:e2e -- --config playwright.regression.config.ts
```

Source hashes confirm the firewall, engine, store, report validation, investigation
contracts and launcher are unchanged. No migration, Git operation or live provider
request was performed. Credentialed live verification remains a separate user step.
