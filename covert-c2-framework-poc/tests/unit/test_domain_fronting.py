import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.core.domain_fronting import DomainFrontingClient


@pytest.fixture
def df_client():
    return DomainFrontingClient(
        cdn_domain="cdn.example.com",
        front_domain="front.example.com",
        c2_host="c2.real-server.com",
    )


def test_client_creation(df_client):
    assert df_client.cdn_domain == "cdn.example.com"
    assert df_client.front_domain == "front.example.com"
    assert df_client.c2_host == "c2.real-server.com"


def test_build_request(df_client):
    req = df_client.build_request("/api/v1/beacon", data={"test": True})
    assert "https://cdn.example.com/api/v1/beacon" == req["url"]
    assert req["headers"]["Host"] == "front.example.com"
    assert req["data"] == {"test": True}
    assert req["headers"]["Content-Type"] == "application/json"


def test_build_request_no_data(df_client):
    req = df_client.build_request("/api/v1/health")
    assert "https://cdn.example.com/api/v1/health" == req["url"]
    assert req["headers"]["Host"] == "front.example.com"
    assert req["data"] is None
    assert "Content-Type" not in req["headers"]


def test_build_request_has_user_agent(df_client):
    req = df_client.build_request("/api/v1/test")
    assert "User-Agent" in req["headers"]


def test_parse_response_json():
    client = DomainFrontingClient("cdn.example.com", "front.example.com", "c2.host")

    class MockResp:
        status_code = 200

        def json(self):
            return {"status": "ok", "commands": []}

    result = client.parse_response(MockResp())
    assert result["status"] == "ok"


def test_parse_response_none():
    client = DomainFrontingClient("cdn.example.com", "front.example.com", "c2.host")
    result = client.parse_response(None)
    assert result is None


def test_parse_response_non_json():
    client = DomainFrontingClient("cdn.example.com", "front.example.com", "c2.host")

    class MockResp:
        status_code = 200
        text = "plain text response"

        def json(self):
            raise ValueError("not json")

    result = client.parse_response(MockResp())
    assert result["status_code"] == 200
    assert result["body"] == "plain text response"


def test_sni_mismatch(df_client):
    req = df_client.build_request("/api/v1/beacon")
    url = req["url"]
    assert url.startswith("https://cdn.example.com")
    host_header = req["headers"]["Host"]
    assert host_header == "front.example.com"
    assert "cdn.example.com" not in host_header
