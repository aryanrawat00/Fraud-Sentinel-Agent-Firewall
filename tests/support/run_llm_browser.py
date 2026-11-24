"""Browser fixture ONLY: real adapters with offline HTTP transport, never a live API."""

import argparse
import json

import httpx
from pydantic import SecretStr

from app.services.gemini_provider import GeminiProvider, GeminiSettings
from app.services.openai_provider import LLMSettings, OpenAIProvider
from scripts import run_agent_firewall


def respond(request):
    body = json.loads(request.content)
    gemini = request.url.host == "generativelanguage.googleapis.com"
    payload = json.loads(
        body["contents"][0]["parts"][0]["text"] if gemini else body["input"][0]["content"]
    )
    if payload["task"] == "plan":
        output = {"steps": [{"operation": "case_summary"}, {"operation": "case_report"}]}
    else:
        sources = payload["untrusted_case_data"]["data_sources"]
        ref = next(k for k, value in sources.items() if value["kind"] == "assessment")
        account = next(k for k, value in sources.items() if value["kind"] == "account")
        transaction = next(k for k, value in sources.items() if value["kind"] == "transaction")
        output = {
            "claims": [
                {
                    "claim_type": "fact",
                    "source": transaction,
                    "field": "amount",
                    "value": sources[transaction]["fields"]["amount"],
                },
                {"claim_type": "inference", "source": ref, "field": "risk_review", "value": None},
                {"claim_type": "unknown", "source": account, "field": "ownership", "value": None},
            ],
            "recommendations": [{"action": "seek_independent_evidence", "sources": [ref]}],
            "evidence_sufficiency": "insufficient",
        }
    if gemini:
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {"role": "model", "parts": [{"text": json.dumps(output)}]},
                    }
                ]
            },
        )
    return httpx.Response(
        200,
        json={
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": json.dumps(output)}],
                }
            ],
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gemini", action="store_true")
    args = parser.parse_args()
    provider = (
        GeminiProvider(
            GeminiSettings(api_key=SecretStr("offline-test-key")),
            limits=LLMSettings(provider="gemini"),
            transport=httpx.MockTransport(respond),
        )
        if args.gemini
        else OpenAIProvider(
            LLMSettings(provider="openai", api_key=SecretStr("offline-test-key")),
            transport=httpx.MockTransport(respond),
        )
    )
    run_agent_firewall.configured_provider = lambda: provider
    run_agent_firewall.main()  # Existing snapshot-only launcher guards still apply.
