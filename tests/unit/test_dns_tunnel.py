import base64
import pytest
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.core.dns_tunnel import (
    DNSTunnelServer,
    DNSTunnelClient,
    build_dns_query_header,
    build_dns_response_header,
    encode_domain_name,
    decode_domain_name,
    build_txt_record,
    DNS_HEADER_SIZE,
)


@pytest.fixture
def dns_server():
    return DNSTunnelServer(domain="c2.example.com", listen_port=10053)


@pytest.fixture
def dns_client():
    client = DNSTunnelClient(
        domain="c2.example.com",
        dns_server="127.0.0.1",
        dns_port=10053,
    )
    yield client
    client.close()


def test_build_dns_query_header():
    header = build_dns_query_header(transaction_id=0x1234, flags=0x0100)
    assert len(header) == DNS_HEADER_SIZE
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", header)
    assert tid == 0x1234
    assert flags == 0x0100
    assert qd == 1
    assert an == 0


def test_build_dns_response_header():
    header = build_dns_response_header(transaction_id=0xABCD, ancount=1)
    assert len(header) == DNS_HEADER_SIZE
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", header)
    assert tid == 0xABCD
    assert an == 1


def test_encode_domain_name():
    result = encode_domain_name(["www", "example", "com"])
    assert result == b"\x03www\x07example\x03com\x00"


def test_decode_domain_name():
    data = b"\x03www\x07example\x03com\x00"
    labels, offset = decode_domain_name(data, 0)
    assert labels == ["www", "example", "com"]


def test_extract_subdomain_data(dns_server):
    query_name = "HEWLOTCGZTEA.client-data.c2.example.com"
    result = dns_server._extract_subdomain_data(query_name)
    assert isinstance(result, str)


def test_encode_response(dns_server):
    response = dns_server.encode_response("Hello World")
    assert isinstance(response, str)
    padding = "=" * (-len(response) % 8)
    decoded = base64.b32decode(response.upper() + padding)
    assert decoded.decode("utf-8") == "Hello World"


def test_handle_query(dns_server):
    labels = ["test-data", "c2", "example", "com"]
    question = encode_domain_name(labels)
    question += struct.pack("!HH", 16, 1)
    header = build_dns_query_header(transaction_id=42)
    query_packet = header + question

    response = dns_server.handle_query(query_packet)
    assert len(response) > DNS_HEADER_SIZE
    resp_tid = struct.unpack("!H", response[0:2])[0]
    assert resp_tid == 42


def test_data_encode_decode_roundtrip():
    original = "This is a covert message through DNS"
    encoded = base64.b32encode(original.encode("utf-8")).decode("utf-8").rstrip("=").lower()
    padding = "=" * (-len(encoded) % 8)
    decoded = base64.b32decode(encoded.upper() + padding).decode("utf-8")
    assert decoded == original


def test_large_data_splitting():
    large_data = "A" * 500
    encoded = base64.b32encode(large_data.encode("utf-8")).decode("utf-8").rstrip("=")
    chunk_size = 63
    chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]
    for chunk in chunks:
        assert len(chunk) <= 63
    concatenated = "".join(chunks)
    padding = "=" * (-len(concatenated) % 8)
    reconstructed = base64.b32decode(concatenated + padding).decode("utf-8")
    assert reconstructed == large_data


def test_txt_record_build():
    labels = ["data", "c2", "example", "com"]
    record = build_txt_record(labels, "test_response")
    assert isinstance(record, bytes)
    assert len(record) > 0


def test_dns_client_creation(dns_client):
    assert dns_client.domain == "c2.example.com"
    assert dns_client.dns_server == "127.0.0.1"
