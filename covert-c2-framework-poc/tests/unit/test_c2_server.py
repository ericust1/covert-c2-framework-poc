import json
import time
import pytest
import base64
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.core.c2_server import C2Server


@pytest.fixture
def server():
    srv = C2Server(host="127.0.0.1", port=0, secret_key="test_secret_key_32_bytes_ok!!")
    srv.app.config["TESTING"] = True
    return srv


@pytest.fixture
def client_and_server(server):
    client = server.app.test_client()
    return client, server


def test_server_creation(server):
    assert server.host == "127.0.0.1"
    assert server.secret_key is not None
    assert server.agents == {}


def test_agent_registration(server):
    system_info = {"hostname": "testhost", "os": "linux"}
    result = server.handle_checkin("agent-001", system_info)
    assert result is True
    assert "agent-001" in server.agents
    assert server.agents["agent-001"]["system_info"]["hostname"] == "testhost"


def test_command_dispatch(server):
    server.handle_checkin("agent-001", {"hostname": "test"})
    cmd_id = server.dispatch_command("agent-001", "whoami")
    assert cmd_id is not False
    assert "agent-001" in server.command_queues
    assert len(server.command_queues["agent-001"]) == 1
    assert server.command_queues["agent-001"][0]["command"] == "whoami"


def test_dispatch_to_unknown_agent(server):
    cmd_id = server.dispatch_command("agent-999", "whoami")
    assert cmd_id is False


def test_command_retrieval(server):
    server.handle_checkin("agent-001", {"hostname": "test"})
    server.dispatch_command("agent-001", "ls -la")
    server.dispatch_command("agent-001", "id")
    commands = server.command_queues.get("agent-001", [])
    assert len(commands) == 2
    assert commands[0]["command"] == "ls -la"
    assert commands[1]["command"] == "id"


def test_get_results(server):
    server.store_result("agent-001", "cmd-abc", "root", 0)
    results = server.get_results("agent-001")
    assert len(results) == 1
    assert results[0]["cmd_id"] == "cmd-abc"
    assert results[0]["output"] == "root"


def test_encrypted_beacon_handling(client_and_server):
    client, server = client_and_server
    beacon_data = {
        "agent_id": "agent-enc-001",
        "system_info": {"hostname": "enc-host", "os": "linux"},
        "timestamp": time.time(),
    }
    encrypted = server.encrypt_payload(beacon_data)
    response = client.post(
        "/api/v1/beacon",
        json={"payload": encrypted},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "payload" in body
    decrypted = server.decrypt_payload(body["payload"])
    assert decrypted["status"] == "ack"


def test_encrypted_beacon_registers_agent(client_and_server):
    client, server = client_and_server
    encrypted = server.encrypt_payload({
        "agent_id": "agent-reg-001",
        "system_info": {"hostname": "reg-host"},
        "timestamp": time.time(),
    })
    response = client.post("/api/v1/beacon", json={"payload": encrypted})
    assert response.status_code == 200
    assert "agent-reg-001" in server.agents


def test_beacon_returns_commands(client_and_server):
    client, server = client_and_server
    server.handle_checkin("agent-cmd-001", {"hostname": "cmdhost"})
    server.dispatch_command("agent-cmd-001", "uname -a")

    encrypted = server.encrypt_payload({
        "agent_id": "agent-cmd-001",
        "system_info": {"hostname": "cmdhost"},
        "timestamp": time.time(),
    })
    response = client.post("/api/v1/beacon", json={"payload": encrypted})
    body = response.get_json()
    decrypted = server.decrypt_payload(body["payload"])
    assert len(decrypted["commands"]) == 1
    assert decrypted["commands"][0]["command"] == "uname -a"


def test_missing_payload_returns_error(client_and_server):
    client, server = client_and_server
    response = client.post("/api/v1/beacon", json={})
    assert response.status_code == 400


def test_list_agents(client_and_server):
    client, server = client_and_server
    server.handle_checkin("agent-list-001", {"os": "linux"})
    response = client.get("/api/v1/agents")
    assert response.status_code == 200
    body = response.get_json()
    assert len(body["agents"]) == 1
