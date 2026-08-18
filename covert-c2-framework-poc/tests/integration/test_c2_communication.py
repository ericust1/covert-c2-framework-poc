import time
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.core.c2_server import C2Server
from src.core.c2_agent import C2Agent


def test_full_c2_communication_flow():
    secret_key = "integration_test_key_32_byte!!"
    server = C2Server(host="127.0.0.1", port=0, secret_key=secret_key)
    server.app.config["TESTING"] = True
    client = server.app.test_client()

    agent = C2Agent(
        server_url="http://127.0.0.1:0",
        agent_id="integ-agent-001",
        secret_key=secret_key,
        beacon_interval=60,
        jitter=0.1,
    )

    beacon_data = agent.generate_beacon()
    encrypted_payload = agent.encrypt_payload(beacon_data)

    response = client.post(
        "/api/v1/beacon",
        json={"payload": encrypted_payload},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "payload" in body

    decrypted_response = agent.decrypt_response(body["payload"])
    assert decrypted_response["status"] == "ack"
    assert "agent-integ-agent-001" not in server.agents
    assert "integ-agent-001" in server.agents
    assert server.agents["integ-agent-001"]["system_info"]["os"] == beacon_data["system_info"]["os"]


def test_command_dispatch_and_retrieval():
    secret_key = "integ_cmd_test_key_32_bytes!!"
    server = C2Server(host="127.0.0.1", port=0, secret_key=secret_key)
    server.app.config["TESTING"] = True
    client = server.app.test_client()

    agent = C2Agent(
        server_url="http://127.0.0.1:0",
        agent_id="integ-cmd-agent",
        secret_key=secret_key,
    )

    encrypted = agent.encrypt_payload({
        "agent_id": "integ-cmd-agent",
        "system_info": {"hostname": "test"},
        "timestamp": time.time(),
    })
    client.post("/api/v1/beacon", json={"payload": encrypted})

    cmd_resp = client.post(
        "/api/v1/command",
        json={"agent_id": "integ-cmd-agent", "command": "echo hello"},
    )
    assert cmd_resp.status_code == 200
    cmd_body = cmd_resp.get_json()
    assert cmd_body["status"] == "queued"

    beacon2_enc = agent.encrypt_payload({
        "agent_id": "integ-cmd-agent",
        "system_info": {"hostname": "test"},
        "timestamp": time.time(),
    })
    beacon2_resp = client.post("/api/v1/beacon", json={"payload": beacon2_enc})
    beacon2_body = beacon2_resp.get_json()
    decrypted = agent.decrypt_response(beacon2_body["payload"])
    commands = decrypted["commands"]
    assert len(commands) == 1
    assert commands[0]["command"] == "echo hello"


def test_agent_sends_results():
    secret_key = "integ_results_test_key_32b!!"
    server = C2Server(host="127.0.0.1", port=0, secret_key=secret_key)
    server.app.config["TESTING"] = True
    client = server.app.test_client()

    agent = C2Agent(
        server_url="http://127.0.0.1:0",
        agent_id="integ-res-agent",
        secret_key=secret_key,
    )

    encrypted = agent.encrypt_payload({
        "agent_id": "integ-res-agent",
        "system_info": {"hostname": "test"},
        "timestamp": time.time(),
    })
    client.post("/api/v1/beacon", json={"payload": encrypted})

    result_data = {
        "agent_id": "integ-res-agent",
        "cmd_id": "test-cmd-id",
        "output": "hello world",
        "exit_code": 0,
        "timestamp": time.time(),
    }
    encrypted_result = agent.encrypt_payload(result_data)
    result_resp = client.post("/api/v1/beacon", json={"payload": encrypted_result})
    assert result_resp.status_code == 200

    server.handle_checkin("integ-res-agent", {"hostname": "test"})
    server.store_result("integ-res-agent", "test-cmd-id", "hello world", 0)

    results = server.get_results("integ-res-agent")
    assert len(results) >= 1
    found = any(r["cmd_id"] == "test-cmd-id" and r["output"] == "hello world" for r in results)
    assert found


def test_unknown_agent_returns_error():
    secret_key = "integ_unknown_test_key_32b!!"
    server = C2Server(host="127.0.0.1", port=0, secret_key=secret_key)
    server.app.config["TESTING"] = True
    client = server.app.test_client()

    resp = client.post(
        "/api/v1/command",
        json={"agent_id": "nonexistent", "command": "whoami"},
    )
    assert resp.status_code == 404


def test_results_endpoint():
    secret_key = "integ_results_ep_test_key!!"
    server = C2Server(host="127.0.0.1", port=0, secret_key=secret_key)
    server.app.config["TESTING"] = True
    client = server.app.test_client()

    server.handle_checkin("integ-res-ep", {"hostname": "test"})
    server.store_result("integ-res-ep", "cmd-1", "output-1", 0)

    resp = client.get("/api/v1/results/integ-res-ep")
    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body["results"]) == 1
    assert body["results"][0]["output"] == "output-1"
