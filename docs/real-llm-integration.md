> Historical milestone/reference document. Results and limitations below describe the recorded milestone, not fresh verification or the current setup. Use [the current README](../README.md), [offline runbook](demo-runbook.md) and [current readiness results](demo-readiness.md). Machine-specific paths are redacted placeholders; do not execute historical commands as current setup instructions.

# Milestone 5: real LLM integration

The isolated snapshot now has an operational HTTP adapter for OpenAI's Responses API.
It can send actual requests when explicitly configured with a valid key. Automated
verification uses mocked HTTP; no live inference or paid API call was made during this
implementation. Account permissions, billing and live model availability remain unverified.

## Provider contract and compatibility

Milestone 10 uses `investigation-v2` with [structured evidence-bound claims](structured-claims.md).
Historical v1 reports remain readable; they are not retroactively verified.


`OpenAIProvider` implements the existing async `plan`/`analyze` interface. It posts to
the fixed HTTPS origin `https://api.openai.com/v1/responses`, with strict JSON Schema
output, `store=false`, low reasoning effort, and no provider-hosted tools. Redirects
and environment-derived proxies are disabled. The existing `httpx` dependency is now
declared as a runtime dependency; no OpenAI SDK or new installed package was needed.

The allowlisted models are `gpt-6.1-terra` (default) and `gpt-6.2-sol`. Their Responses
API and structured-output support were checked against the current official model
documentation on 2026-11-22. Older candidate models were not selected because their
current documentation marks them deprecated. Unknown models/providers are rejected.
API account access still requires a successful credentialed request; documentation
compatibility is not a live availability guarantee.

Official references:

- [Developer quickstart](https://developers.openai.com/api/docs/quickstart)
- [Structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [GPT-6.1 Terra](https://developers.openai.com/api/docs/models/gpt-6.1-terra)
- [GPT-6.2 Sol](https://developers.openai.com/api/docs/models/gpt-6.2-sol)

## Secure configuration and running locally

Gemini is also available as an explicitly selected provider. See
[Gemini setup, free-tier limits and privacy](gemini-integration.md). The OpenAI
configuration and Responses API behavior below remain unchanged.

The isolated launcher reads process environment through `LLMSettings`, following the
existing Pydantic settings conventions. It does not load or modify `.env`. The table
below lists the supported environment variables and their defaults.

`configured=false` for the OpenAI provider means its effective API key is missing or
blank; the provider and model may still be correctly selected. Only
`FRAUDSENTINEL_LLM_API_KEY` is read, not the SDK convention `OPENAI_API_KEY`.
Set process variables in the **same PowerShell session** that launches the command.
Another terminal (including a Codex tool process) does not inherit changes made in
that session. An already-running server must be restarted to load new configuration.
The shared virtual environment is supported, but `PYTHONPATH` must point at this
isolated checkout as shown below so its modules are selected.

| Environment variable | Default / allowed values |
| --- | --- |
| `FRAUDSENTINEL_LLM_PROVIDER` | `disabled`; select `openai` or `gemini` explicitly |
| `FRAUDSENTINEL_LLM_MODEL` | `gpt-6.1-terra`; also `gpt-6.2-sol` |
| `FRAUDSENTINEL_LLM_API_KEY` | Empty; provision out of band |
| `FRAUDSENTINEL_LLM_DEADLINE_SECONDS` | 45; range 1–90 |
| `FRAUDSENTINEL_LLM_MAX_OUTPUT_TOKENS` | 4096; range 1024–8192 |
| `FRAUDSENTINEL_LLM_RETRIES` | 1; range 0–1 |

Use a secret manager or a hidden local prompt, not a key literal in a script or shell
history. For an interactive PowerShell session:

```powershell
Set-Location <project-root>
$env:PYTHONPATH = '<project-root>\backend'
$env:FRAUDSENTINEL_LLM_PROVIDER = 'openai'
$env:FRAUDSENTINEL_LLM_MODEL = 'gpt-6.1-terra'
$llmSecureKey = Read-Host 'OpenAI API key' -AsSecureString
$llmKeyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($llmSecureKey)
try {
  $env:FRAUDSENTINEL_LLM_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($llmKeyPointer)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($llmKeyPointer)
  $llmSecureKey.Dispose()
}
<historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.check_llm_provider
```

The command above reports safe configuration metadata only; it makes no API call.
Alternatively, after setting `PYTHONPATH`, provider and model as above, use hidden
entry directly in the checking process to avoid shell credential propagation:

```powershell
<historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.check_llm_provider --prompt-key
```

This key is used only by that invocation; it is not written to the environment or a
file and does not configure the server. Hidden entry fails closed if unavailable.
`configured=true` confirms a nonblank key was detected, not that OpenAI accepted it.
The script refuses `--live` before planning if configuration is missing.
To explicitly make one potentially billed synthetic planning request, without reading
any financial database or executing tools:

```powershell
<historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.check_llm_provider --live
```

Add `--prompt-key` to that live command to enter the key again for that invocation
instead of using the process environment. Prompting alone never enables API calls.

That live command was supplied but **not executed** during this milestone. After
configuration, use the existing isolated launcher and separately provisioned firewall
identities/audit key described in [firewall-integration.md](firewall-integration.md):

```powershell
<historical-checkout-root>\.venv\Scripts\python.exe -B -m scripts.run_agent_firewall
```

Use the existing synthetic workflow dataset. In the security workspace, check AI
configuration, select provider mode, and start a new investigation. Advance bounded
steps and approve the exact `case_report` request before analysis. After stopping the
server, remove the process key with `Remove-Item Env:FRAUDSENTINEL_LLM_API_KEY`.

## Execution, grounding and oversight

The model proposes a two-to-six-step plan using the existing six read operations.
Plans must start with case context and end with an approved report read. The server
alone binds case/identity/arguments and calls `Firewall.submit` and `Firewall.execute`.
No SQL, shell, Python, filesystem, URL, policy change or approval capability is exposed
to the model. Case data is supplied as untrusted JSON separate from server instructions.
Attempts to add tools, scope arguments or permission fields fail schema validation.

Planning sends only the existing case ID and investigation objective. Analysis sends
the bounded, firewall-approved case projection: source registry, recorded transaction
facts, assessments, evidence, relationship patterns, objective/context and existing
report references. Only the protected, human-approved case report includes amounts,
currencies and UTC transaction timestamps. Stored prose, customer identity and device
information remain withheld. Secrets/credentials are never part of the projection.

Analysis contains typed facts, constrained inferences, explicit unknowns and coded
recommendations. The backend independently matches fact values and types to the cited
fields in the final authorized snapshot. It derives connections/counts from scoped
transactions and generates all explanatory text from controlled templates. Unsupported
claims fail the investigation rather than becoming a successful report. Inferences
remain unverified; snapshot verification is not a guarantee of external truth.

Every actual tool execution remains permission-checked. Human review remains
fingerprint-bound; no financial actions or final fraud determinations are implemented.
Historical narrative reports retain their original limitations and carry a UI warning.

The request uses `store=false`, but this is **not** a guarantee of zero provider retention.
Account-level abuse-monitoring/data controls still apply. Review the official
[data-controls documentation](https://developers.openai.com/api/docs/guides/your-data)
before using anything beyond authorized synthetic development data.

## Reliability, persistence and truthful status

Requests have a total deadline and per-request timeout. At most one retry occurs for
429/500/502/503/504; retries are stateless inference requests only, never tool execution
or investigation creation. Other failures, malformed/incomplete output, refusals,
oversized responses, unauthorized plans and missing credentials fail closed. There is
no silent deterministic fallback. Inputs are capped at 256 KiB, HTTP responses at
256 KiB, and structured model output at 32 KiB. Reasoning tokens may exhaust the output
budget; incomplete responses fail rather than produce a partial report.

Cancellation cancels the active async provider request and discards late output.
Cancellation cannot guarantee that a provider has stopped processing or billing an
already-sent request. Exception bodies/headers and raw provider diagnostics are not
returned or persisted. Reports record provider/model/transport provenance, not keys or
raw API responses. The model never receives hidden provider credentials or tool secrets.

New provider runs persist an immutable provider/model/transport/contract binding. Resume
refuses a changed binding rather than silently switching models. Prior signed records
remain readable: the sole optional additive field is `provider_identity`; other missing
metadata still fails validation. Legacy provider runs cannot silently adopt the new
real adapter. No SQLite schema or financial database migration was necessary.

`GET /api/v1/security/provider?case_id=...` requires current human case authorization
and makes no external request. It reports configured state and the most recent in-process
response outcome. Restart resets that diagnostic outcome. `configured` does not mean
live credentials/model access were verified. A report's provenance, not a global status
label, identifies its actual analysis origin. Injected HTTP test transports are always
labelled `mock_http`; deterministic reports remain labelled local/deterministic.

## Offline verification and remaining work

All automated tests use synthetic fixtures and mocked HTTP, never paid calls. Browser
fixtures explicitly disable inherited live configuration. The dedicated test launcher
`tests/support/run_llm_browser.py` uses the real adapter with `httpx.MockTransport` and
advertises that fact; production launchers contain no mock fallback switch.

Run the complete backend and both browser suites with the existing commands in
[firewall-integration.md](firewall-integration.md), keeping all PostgreSQL opt-ins disabled.
Additional provider tests are in `tests/integration/test_real_llm.py`. Exact final counts,
changed-file hashes and preservation checks are recorded in `real-llm-results.json`.

This is not production readiness. Remaining work includes a user-run credentialed smoke
check, evaluated evidence-grounding quality, cost/usage controls and adversarial review.
Existing local SQLite ownership, retention and audit limitations still apply. The next
recommended milestone is a synthetic-case evaluation harness and supervised pilot with
measured citation accuracy, failure rates, latency and spend before broader deployment.

No main-checkout activation, database modification, migration 0003, `.env` edit, existing
backup/result replacement, commit or push is part of this milestone. The snapshot has
no `.git`; its existing files were inventoried and preserved under `tmp/before-real-llm`.
