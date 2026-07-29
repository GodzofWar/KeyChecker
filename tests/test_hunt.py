"""Offline tests for the secret-hunting logic (no network)."""

from keychecker.cli import _normalize_argv
from keychecker.hunt import default_dorks, extract_secrets


def test_default_dorks_cover_all_services():
    dorks = default_dorks()
    assert "shodan" in dorks
    assert "SHODAN_API_KEY" in dorks["shodan"]
    # Multi-env service exposes both variable names.
    assert set(dorks["censys"]) == {"CENSYS_API_ID", "CENSYS_API_SECRET"}


def test_default_dorks_only_filter():
    dorks = default_dorks(only=["shodan", "fofa"])
    assert set(dorks) == {"shodan", "fofa"}


def test_extract_secret_from_assignment():
    text = 'SHODAN_API_KEY = "abcd1234efgh5678ijkl9012mnop3456"'
    found = extract_secrets(text, "SHODAN_API_KEY")
    assert found == ["abcd1234efgh5678ijkl9012mnop3456"]


def test_extract_secret_json_style():
    text = '"VT_API_KEY": "0123456789abcdef0123456789abcdef"'
    found = extract_secrets(text, "VT_API_KEY")
    assert found == ["0123456789abcdef0123456789abcdef"]


def test_extract_ignores_placeholders():
    for placeholder in (
        'SHODAN_API_KEY = "YOUR_SHODAN_KEY_HERE"',
        'SHODAN_API_KEY = "xxxxxxxxxxxxxxxxxxxx"',
        'SHODAN_API_KEY = "your_api_key_example"',
    ):
        assert extract_secrets(placeholder, "SHODAN_API_KEY") == []


def test_extract_requires_minimum_length():
    # Too short to be a real key.
    assert extract_secrets('SHODAN_API_KEY = "short"', "SHODAN_API_KEY") == []


def test_normalize_argv_defaults_to_check():
    assert _normalize_argv([]) == ["check"]
    assert _normalize_argv(["--shodan", "KEY"]) == ["check", "--shodan", "KEY"]
    assert _normalize_argv(["--list"]) == ["check", "--list"]


def test_normalize_argv_keeps_subcommands():
    assert _normalize_argv(["check", "--list"]) == ["check", "--list"]
    assert _normalize_argv(["hunt", "--org", "acme"]) == ["hunt", "--org", "acme"]
    assert _normalize_argv(["--help"]) == ["--help"]
