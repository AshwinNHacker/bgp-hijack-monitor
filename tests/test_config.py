import pytest

from bgp_hijack_monitor.config import Config, ConfigError


def test_load_valid_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
org_name: "Test Org"
prefixes:
  - prefix: "203.0.113.0/24"
    expected_origin_asns: [64512]
    description: "test block"
alerting:
  console: true
  min_severity: "medium"
"""
    )
    config = Config.load(cfg_file)
    assert config.org_name == "Test Org"
    assert len(config.prefixes) == 1
    assert config.prefixes[0].expected_origin_asns == [64512]
    assert config.alerting.min_severity == "medium"


def test_missing_file_raises():
    with pytest.raises(ConfigError):
        Config.load("/nonexistent/path/config.yaml")


def test_missing_org_name_raises(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
prefixes:
  - prefix: "203.0.113.0/24"
    expected_origin_asns: [64512]
"""
    )
    with pytest.raises(ConfigError):
        Config.load(cfg_file)


def test_missing_prefixes_raises(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text('org_name: "Test Org"\n')
    with pytest.raises(ConfigError):
        Config.load(cfg_file)


def test_prefix_without_expected_asns_raises(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
org_name: "Test Org"
prefixes:
  - prefix: "203.0.113.0/24"
    expected_origin_asns: []
"""
    )
    with pytest.raises(ConfigError):
        Config.load(cfg_file)


def test_invalid_prefix_raises(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
org_name: "Test Org"
prefixes:
  - prefix: "not-a-prefix"
    expected_origin_asns: [64512]
"""
    )
    with pytest.raises(ConfigError):
        Config.load(cfg_file)


def test_env_var_password_not_stored_in_file(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
org_name: "Test Org"
prefixes:
  - prefix: "203.0.113.0/24"
    expected_origin_asns: [64512]
alerting:
  email:
    enabled: true
    password_env_var: "MY_SECRET_PW"
"""
    )
    monkeypatch.setenv("MY_SECRET_PW", "hunter2")
    config = Config.load(cfg_file)
    assert config.alerting.email.password == "hunter2"
