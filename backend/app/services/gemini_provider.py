"""Bounded Gemini generateContent adapter; no SDK tools, files, or database access."""

import asyncio
import json

import httpx
from pydantic import Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.services.investigation_provider import (
    Analysis,
    Plan,
    ProviderRateLimited,
    ProviderUnavailable,
)
from app.services.openai_provider import (
    GEMINI_MODEL_PATTERN,
    INSTRUCTIONS,
    LLMSettings,
    ProviderFailure,
    strict_schema,
)

DEFAULT_MODEL = "gemini-3.5-flash-lite"
BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/"


class GeminiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FRAUDSENTINEL_GEMINI_", env_file=None, extra="ignore", hide_input_in_errors=True
    )
    api_key: SecretStr = SecretStr("")
    model: str = Field(default=DEFAULT_MODEL, pattern="^" + GEMINI_MODEL_PATTERN + "$")


class GeminiProvider:
    def __init__(self, settings: GeminiSettings, *, limits: LLMSettings, transport=None):
        self.settings = settings
        self.limits = limits
        self.transport = transport
        self.deadline = limits.deadline_seconds
        self.last_outcome = "not_checked"

    def identity(self):
        return {
            "provider": "gemini",
            "model": self.settings.model,
            "transport": "mock_http" if self.transport is not None else "live_http",
            "contract": "investigation-v2",
        }

    def status(self):
        return {
            **self.identity(),
            "configured": bool(self.settings.api_key.get_secret_value().strip()),
            "last_outcome": self.last_outcome,
            "availability": "unverified"
            if self.last_outcome == "not_checked"
            else self.last_outcome,
        }

    async def plan(self, context):
        return await self.request("plan", context, Plan)

    async def analyze(self, sources):
        return await self.request("analysis", sources, Analysis)

    async def request(self, task, data, model):
        key = self.settings.api_key.get_secret_value().strip()
        if not key:
            self.last_outcome = "unavailable"
            raise ProviderUnavailable
        try:
            payload = json.dumps({"task": task, "untrusted_case_data": data}, allow_nan=False)
            if len(payload.encode()) > 262144 or key in payload:
                raise ProviderFailure("provider_input_bound_exceeded")
            body = {
                "systemInstruction": {"parts": [{"text": INSTRUCTIONS}]},
                "contents": [{"role": "user", "parts": [{"text": payload}]}],
                "generationConfig": {
                    "candidateCount": 1,
                    "maxOutputTokens": self.limits.max_output_tokens,
                    "responseMimeType": "application/json",
                    "responseJsonSchema": strict_schema(model),
                },
            }
            async with asyncio.timeout(self.deadline):
                async with httpx.AsyncClient(
                    transport=self.transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(min(15, self.deadline)),
                ) as client:
                    for attempt in range(self.limits.retries + 1):
                        async with client.stream(
                            "POST",
                            BASE_URL + self.settings.model + ":generateContent",
                            headers={"x-goog-api-key": key},
                            json=body,
                        ) as response:
                            if response.status_code in {429, 500, 502, 503, 504}:
                                if attempt < self.limits.retries:
                                    await asyncio.sleep(0.25 * (attempt + 1))
                                    continue
                                if response.status_code == 429:
                                    raise ProviderRateLimited
                                raise ProviderFailure("provider_failed")
                            if response.status_code in {401, 403}:
                                raise ProviderFailure("provider_authentication_failed")
                            if response.status_code != 200:
                                raise ProviderFailure("provider_failed")
                            chunks = bytearray()
                            async for chunk in response.aiter_bytes():
                                chunks.extend(chunk)
                                if len(chunks) > 262144:
                                    raise ProviderFailure("provider_invalid_output")
                        result = self.parse(bytes(chunks), model, key)
                        self.last_outcome = "successful_response"
                        return result
        except asyncio.CancelledError:
            self.last_outcome = "cancelled"
            raise
        except (TimeoutError, httpx.TimeoutException):
            self.last_outcome = "timeout"
            raise TimeoutError("Provider deadline exceeded") from None
        except ProviderFailure as error:
            self.last_outcome = error.code
            raise
        except ProviderRateLimited:
            self.last_outcome = "provider_rate_limited"
            raise
        except Exception:
            self.last_outcome = "provider_failed"
            raise ProviderFailure("provider_failed") from None

    @staticmethod
    def parse(raw, model, key):
        def unique(pairs):
            value = {}
            for name, item in pairs:
                if name in value:
                    raise ValueError("Duplicate JSON key")
                value[name] = item
            return value

        try:
            envelope = json.loads(raw, object_pairs_hook=unique)
            if envelope.get("promptFeedback", {}).get("blockReason"):
                raise ProviderFailure("provider_refused")
            candidates = envelope["candidates"]
            if not isinstance(candidates, list) or len(candidates) != 1:
                raise ProviderFailure("provider_invalid_output")
            candidate = candidates[0]
            finish = candidate.get("finishReason")
            if finish in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"}:
                raise ProviderFailure("provider_refused")
            if finish != "STOP":
                raise ProviderFailure("provider_incomplete")
            content = candidate["content"]
            if content.get("role") != "model":
                raise ProviderFailure("provider_invalid_output")
            texts = []
            for part in content["parts"]:
                # Never expose thoughts or accept function/code/media parts, even alongside text.
                if set(part) - {"text", "thought", "thoughtSignature"}:
                    raise ProviderFailure("provider_invalid_output")
                if part.get("thought") is True:
                    continue
                if part.get("thought", False) is not False:
                    raise ProviderFailure("provider_invalid_output")
                texts.append(part["text"])
            if len(texts) != 1 or len(texts[0].encode()) > 32768 or key in texts[0]:
                raise ProviderFailure("provider_invalid_output")
            return model.model_validate(json.loads(texts[0], object_pairs_hook=unique)).model_dump()
        except ProviderFailure:
            raise
        except (ValueError, KeyError, TypeError, AttributeError, ValidationError):
            raise ProviderFailure("provider_invalid_output") from None
