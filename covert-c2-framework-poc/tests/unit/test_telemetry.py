import time
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.modules.telemetry import TelemetryCollector


@pytest.fixture
def collector():
    return TelemetryCollector()


def test_system_info_collection(collector):
    info = collector.collect_system_info()
    assert isinstance(info, dict)
    expected_keys = ["hostname", "os", "arch", "username", "ip_address", "timestamp"]
    for key in expected_keys:
        assert key in info, "Missing key: {}".format(key)
    assert info["hostname"] != ""
    assert info["os"] != ""


def test_system_info_types(collector):
    info = collector.collect_system_info()
    assert isinstance(info["hostname"], str)
    assert isinstance(info["os"], str)
    assert isinstance(info["arch"], str)
    assert isinstance(info["timestamp"], float)


def test_beacon_formatting(collector):
    info = collector.collect_system_info()
    beacon = collector.format_beacon(info)
    assert beacon["type"] == "telemetry"
    assert "data" in beacon
    assert "timestamp" in beacon
    assert beacon["data"]["hostname"] == info["hostname"]


def test_jitter_bounds_lower(collector):
    base = 60
    jitter = 0.3
    for _ in range(100):
        result = collector.calculate_beacon_jitter(base, jitter)
        assert result >= base * (1 - jitter) - 0.01
        assert result <= base * (1 + jitter) + 0.01


def test_jitter_bounds_upper(collector):
    base = 120
    jitter = 0.5
    for _ in range(100):
        result = collector.calculate_beacon_jitter(base, jitter)
        assert result >= base * (1 - jitter) - 0.01
        assert result <= base * (1 + jitter) + 0.01


def test_jitter_minimum_is_positive(collector):
    result = collector.calculate_beacon_jitter(1, 0.9)
    assert result >= 1.0


def test_network_connections_returns_list(collector):
    connections = collector.collect_network_connections()
    assert isinstance(connections, list)


def test_network_connection_format(collector):
    connections = collector.collect_network_connections()
    for conn in connections:
        if isinstance(conn, dict):
            assert "local_addr" in conn
            assert "status" in conn


def test_beacon_jitter_zero(collector):
    base = 60
    result = collector.calculate_beacon_jitter(base, 0.0)
    assert result == base
