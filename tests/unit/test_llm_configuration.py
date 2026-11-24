"""Credential detection and smoke-check preflight; external HTTP is forbidden."""

import json
import os
import sys
import warnings
from unittest.mock import AsyncMock

import pytest

from app.services.openai_provider import LLMSettings, OpenAIProvider, configured_provider
from scripts import check_llm_provider

KEY = "synthetic-configuration-test-not-a-real-key"


@pytest.fixture(autouse=True)
def isolated_configuration(monkeypatch):
    for name in list(os.environ):
        if name.upper().startswith("FRAUDSENTINEL_LLM_") or name.upper() == "OPENAI_API_KEY":
            monkeypatch.delenv(name)
    monkeypatch.setenv("FRAUDSENTINEL_LLM_PROVIDER", "openai")

    def forbid_http(*args, **kwargs):
        pytest.fail("Configuration checks must not construct an HTTP client")

    monkeypatch.setattr("httpx.AsyncClient", forbid_http)


@pytest.mark.parametrize("key", [None, "", " \t "])
def test_missing_or_blank_key_is_not_configured(monkeypatch, key):
    if key is not None:
        monkeypatch.setenv("FRAUDSENTINEL_LLM_API_KEY", key)
    assert configured_provider().status()["configured"] is False


def test_prefixed_key_detected_without_exposing_it(monkeypatch):
    monkeypatch.setenv("FRAUDSENTINEL_LLM_API_KEY", KEY)
    settings = LLMSettings()
    assert settings.api_key.get_secret_value() == KEY
    assert configured_provider(settings).status()["configured"] is True
    assert KEY not in repr(settings)
    assert KEY not in json.dumps(configured_provider(settings).status())


def test_generic_openai_key_is_not_silently_adopted(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    assert configured_provider().status()["configured"] is False


@pytest.mark.parametrize("present", [False, True])
def test_default_script_reports_configuration_without_request(monkeypatch, capsys, present):
    if present:
        monkeypatch.setenv("FRAUDSENTINEL_LLM_API_KEY", KEY)
    monkeypatch.setattr(sys, "argv", ["check_llm_provider"])
    check_llm_provider.main()
    output = capsys.readouterr()
    assert json.loads(output.out)["configured"] is present
    assert KEY not in output.out + output.err


def test_live_missing_key_stops_before_provider_plan(monkeypatch):
    plan = AsyncMock(side_effect=AssertionError("Preflight must prevent planning"))
    monkeypatch.setattr(OpenAIProvider, "plan", plan)
    monkeypatch.setattr(sys, "argv", ["check_llm_provider", "--live"])
    with pytest.raises(SystemExit, match="FRAUDSENTINEL_LLM_API_KEY"):
        check_llm_provider.main()
    plan.assert_not_called()


def test_hidden_prompt_configures_only_this_check(monkeypatch, capsys):
    monkeypatch.setattr(check_llm_provider.getpass, "getpass", lambda prompt: KEY)
    monkeypatch.setattr(sys, "argv", ["check_llm_provider", "--prompt-key"])
    check_llm_provider.main()
    output = capsys.readouterr()
    status = json.loads(output.out)
    assert status["configured"] is True
    assert status["last_outcome"] == "not_checked"
    assert KEY not in output.out + output.err
    assert "FRAUDSENTINEL_LLM_API_KEY" not in os.environ
    assert configured_provider().status()["configured"] is False


def test_blank_prompt_does_not_fall_back_to_environment_key(monkeypatch):
    monkeypatch.setenv("FRAUDSENTINEL_LLM_API_KEY", KEY)
    monkeypatch.setattr(check_llm_provider.getpass, "getpass", lambda prompt: " ")
    monkeypatch.setattr(sys, "argv", ["check_llm_provider", "--prompt-key", "--live"])
    with pytest.raises(SystemExit, match="No request sent"):
        check_llm_provider.main()
    assert os.environ["FRAUDSENTINEL_LLM_API_KEY"] == KEY


def test_prompt_refuses_echo_fallback(monkeypatch):
    def unsafe_prompt(prompt):
        warnings.warn("Cannot hide input", check_llm_provider.getpass.GetPassWarning)
        pytest.fail("Echoed input must never be read")

    monkeypatch.setattr(check_llm_provider.getpass, "getpass", unsafe_prompt)
    monkeypatch.setattr(sys, "argv", ["check_llm_provider", "--prompt-key", "--live"])
    with pytest.raises(SystemExit, match="Hidden key entry unavailable"):
        check_llm_provider.main()


def test_prompt_does_not_enable_disabled_provider(monkeypatch):
    monkeypatch.setenv("FRAUDSENTINEL_LLM_PROVIDER", "disabled")
    monkeypatch.setattr(sys, "argv", ["check_llm_provider", "--prompt-key"])
    with pytest.raises(SystemExit) as error:
        check_llm_provider.main()
    assert error.value.code == 2


def test_prompt_key_reaches_mocked_live_plan_only_with_live_flag(monkeypatch, capsys):
    seen = []

    async def plan(provider, context):
        seen.append(provider.settings.api_key.get_secret_value() == KEY)
        assert context["case_id"] == "synthetic_configuration_check"
        return {"steps": [{"operation": "case_summary"}, {"operation": "case_report"}]}

    monkeypatch.setattr(OpenAIProvider, "plan", plan)
    monkeypatch.setattr(check_llm_provider.getpass, "getpass", lambda prompt: KEY)
    monkeypatch.setattr(sys, "argv", ["check_llm_provider", "--prompt-key", "--live"])
    check_llm_provider.main()
    assert seen == [True]
    output = capsys.readouterr()
    assert KEY not in output.out + output.err
