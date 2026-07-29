"""Tests for the registry and config/credential handling (no network)."""

import os

import pytest

from keychecker.checkers import REGISTRY, all_names
from keychecker.config import _label, _mask, _normalize, gather_jobs, load_from_env


def test_registry_is_populated():
    assert "shodan" in REGISTRY
    assert "censys" in REGISTRY
    assert "fofa" in REGISTRY
    assert len(all_names()) >= 9


def test_every_checker_declares_metadata():
    for name, cls in REGISTRY.items():
        assert cls.name == name
        assert cls.fields, f"{name} must declare credential fields"
        assert set(cls.env_vars) == set(cls.fields), (
            f"{name} env_vars must cover every field"
        )


def test_mask_hides_all_but_last_four():
    assert _mask("abcdefgh") == "****efgh"
    assert _mask("abc") == "***"
    assert _mask("") == "<empty>"


def test_normalize_colon_shorthand_for_multifield():
    creds = _normalize("censys", "myid:mysecret")
    assert creds == [{"id": "myid", "secret": "mysecret"}]


def test_normalize_list_of_dicts():
    creds = _normalize("shodan", [{"key": "a"}, {"key": "b"}])
    assert creds == [{"key": "a"}, {"key": "b"}]


def test_normalize_missing_field_raises():
    with pytest.raises(ValueError):
        _normalize("censys", {"id": "only-id"})


def test_label_prefers_non_secret_identifier():
    label = _label("fofa", {"email": "me@example.com", "key": "supersecretkey"})
    assert label.startswith("me@example.com")
    assert "supersecretkey" not in label


def test_load_from_env(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "envkey123456")
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    jobs = load_from_env()
    services = {j.service for j in jobs}
    assert "shodan" in services
    # Censys needs two fields; only one absent -> not included.
    assert "censys" not in services


def test_gather_jobs_only_filter():
    jobs = gather_jobs(
        config_path=None,
        cli_values={"shodan": "abc", "hunter": "def"},
        use_env=False,
        only=["shodan"],
    )
    assert [j.service for j in jobs] == ["shodan"]
