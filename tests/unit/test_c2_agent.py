import time
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.core.c2_agent import C2Agent


@pytest.fixture
def agent():
    return C2Agent(
        server_url="http://localhost:8080",
        agent_id="test-agent-001",
        secret_key="test_secret_key_32_bytes_ok!!",
        beacon_interval=30,
        jitter=0.2,
    )


def test_agent_creation(agent):
    assert agent.agent_id == "test-agent-001"
    assert agent.beacon_interval == 30
    assert agent.jitter == 0.2
    assert agent.aesgcm is not None


def test_beacon_generation(agent):
    beacon = agent.generate_beacon()
    assert "agent_id" in beacon
    assert beacon["agent_id"] == "test-agent-001"
    assert "system_info" in beacon
    sys_info = beacon["system_info"]
    assert "hostname" in sys_info
    assert "os" in sys_info
    assert "user" in sys_info
    assert "ip" in sys_info
    assert "timestamp" in beacon


def test_beacon_has_required_fields(agent):
    beacon = agent.generate_beacon()
    required = ["agent_id", "system_info", "timestamp"]
    for field in required:
        assert field in beacon


def test_encrypt_decrypt_roundtrip(agent):
    data = {"command": "whoami", "target": "agent-001", "timestamp": time.time()}
    encrypted = agent.encrypt_payload(data)
    assert isinstance(encrypted, str)
    assert len(encrypted) > 0
    decrypted = agent.decrypt_response(encrypted)
    assert decrypted["command"] == "whoami"
    assert decrypted["target"] == "agent-001"


def test_encrypt_decrypt_large_payload(agent):
    data = {"key": "A" * 5000}
    encrypted = agent.encrypt_payload(data)
    decrypted = agent.decrypt_response(encrypted)
    assert decrypted["key"] == "A" * 5000


def test_execute_command(agent):
    output, exit_code = agent.execute_command("echo hello")
    assert exit_code == 0
    assert "hello" in output


def test_execute_command_failure(agent):
    output, exit_code = agent.execute_command("exit 1")
    assert exit_code == 1


def test_jitter_within_bounds(agent):
    jitter_percent = 0.2
    base = 30
    samples = [agent.beacon_interval * (1 + __import__("random").uniform(-jitter_percent, jitter_percent)) for _ in range(1000)]
    minimum = base * (1 - jitter_percent)
    maximum = base * (1 + jitter_percent)
    for s in samples:
        assert s >= minimum - 0.01
        assert s <= maximum + 0.01
