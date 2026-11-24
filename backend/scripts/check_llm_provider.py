"""Configuration check by default; --live explicitly sends one synthetic planning request."""

import argparse
import asyncio
import getpass
import json
import warnings

from pydantic import SecretStr

from app.services.openai_provider import LLMSettings, configured_provider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prompt-key",
        action="store_true",
        help="Read a hidden API key for this check only; does not enable a live request",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Make one potentially billed API planning request, no database access",
    )
    args = parser.parse_args()
    settings = LLMSettings()
    provider = configured_provider(settings)
    if args.prompt_key:
        if settings.provider not in {"openai", "gemini"}:
            parser.error(
                "Set FRAUDSENTINEL_LLM_PROVIDER=openai or gemini before prompting for a key"
            )
        try:
            with warnings.catch_warnings():
                # Never fall back to an echoed stdin prompt when a terminal is unavailable.
                warnings.simplefilter("error", getpass.GetPassWarning)
                provider.settings.api_key = SecretStr(
                    getpass.getpass(f"{settings.provider} API key (hidden): ")
                )
        except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
            raise SystemExit("Hidden key entry unavailable or cancelled; no request sent") from None
    status = getattr(provider, "status", lambda: {"configured": False, "provider": "none"})()
    print(json.dumps(status))  # Only allowlisted configuration metadata, never credentials.
    if not args.live:
        return
    if not status["configured"]:
        key_name = (
            "FRAUDSENTINEL_GEMINI_API_KEY"
            if settings.provider == "gemini"
            else "FRAUDSENTINEL_LLM_API_KEY"
        )
        raise SystemExit(
            "Live check not started: select openai or gemini with FRAUDSENTINEL_LLM_PROVIDER "
            f"and set a nonblank {key_name} in this shell, or use --prompt-key. "
            "Generic SDK key variables and .env files are not read. No request sent."
        )
    try:
        asyncio.run(
            provider.plan(
                {
                    "case_id": "synthetic_configuration_check",
                    "objective": "Plan a synthetic read-only case review",
                }
            )
        )
    except Exception:
        raise SystemExit(
            "Live provider verification failed; no response body or secret disclosed"
        ) from None
    print("Live structured planning response validated. No case data or tools were accessed.")


if __name__ == "__main__":
    main()
