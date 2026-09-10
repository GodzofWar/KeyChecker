"""Offline tests for the secret-hunting logic (no network)."""

from keychecker.cli import _normalize_argv
from keychecker.hunt import (
    _extract,
    build_probes,
    default_dorks,
    extract_secrets,
)

# A realistic-shaped (but fake) Shodan key: 32 alphanumerics.
FAKE_SHODAN_KEY = "AbCd1234EfGh5678IjKl9012MnOp3456"


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


def _shodan_probe():
    (probe,) = build_probes(only=["shodan"])
    return probe


def test_shodan_probe_includes_service_specific_queries():
    probe = _shodan_probe()
    assert "SHODAN_API_KEY" in probe.queries
    assert "api.shodan.io" in probe.queries
    assert "shodan.Shodan" in probe.queries
    assert probe.shape is not None


def test_default_dorks_include_hunt_queries():
    dorks = default_dorks(only=["shodan"])
    assert "api.shodan.io" in dorks["shodan"]


def test_shodan_key_extracted_from_api_url():
    probe = _shodan_probe()
    text = f'requests.get("https://api.shodan.io/shodan/host/search?key={FAKE_SHODAN_KEY}&query=apache")'
    assert _extract(text, probe.patterns, probe.shape) == [FAKE_SHODAN_KEY]


def test_shodan_key_extracted_from_sdk_call():
    probe = _shodan_probe()
    text = f"api = shodan.Shodan('{FAKE_SHODAN_KEY}')"
    assert _extract(text, probe.patterns, probe.shape) == [FAKE_SHODAN_KEY]


def test_shodan_key_extracted_from_alternate_var_name():
    probe = _shodan_probe()
    text = f'shodan_key = "{FAKE_SHODAN_KEY}"'
    assert _extract(text, probe.patterns, probe.shape) == [FAKE_SHODAN_KEY]


def test_shodan_shape_rejects_wrong_length():
    probe = _shodan_probe()
    # 40-char value assigned to SHODAN_API_KEY: matches the generic pattern
    # but not Shodan's 32-char shape, so it is filtered out.
    text = 'SHODAN_API_KEY = "0123456789012345678901234567890123456789"'
    assert _extract(text, probe.patterns, probe.shape) == []


def test_normalize_argv_defaults_to_check():
    assert _normalize_argv([]) == ["check"]
    assert _normalize_argv(["--shodan", "KEY"]) == ["check", "--shodan", "KEY"]
    assert _normalize_argv(["--list"]) == ["check", "--list"]


def test_normalize_argv_keeps_subcommands():
    assert _normalize_argv(["check", "--list"]) == ["check", "--list"]
    assert _normalize_argv(["hunt", "--org", "acme"]) == ["hunt", "--org", "acme"]
    assert _normalize_argv(["--help"]) == ["--help"]
