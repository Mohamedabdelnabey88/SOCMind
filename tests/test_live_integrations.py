import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from socmind.integrations import ElasticClient, WazuhClient, integration_check
from socmind.ioc import IOC
from socmind.threat_intel_live import MISPProvider, OpenCTIClient


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self):
        if self.path.startswith("/security/user/authenticate"):
            data = b"jwt-demo-token"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            self.close_connection = True
        elif self.path.endswith("/_search"):
            self._json({"hits": {"hits": [{"_source": {"@timestamp": "2026-09-28T00:00:00Z", "host": {"name": "WS-01"}}}]}})
        elif self.path == "/attributes/restSearch":
            self._json({"response": {"Attribute": [{"value": "203.0.113.77", "Tag": [{"name": "tlp:amber"}]}]}})
        elif self.path == "/graphql":
            self._json({"data": {"about": {"version": "demo"}}})
        else:
            self._json({}, 404)

    def do_GET(self):
        if self.path.startswith("/agents"):
            self._json({"data": {"affected_items": [{"id": "001", "name": "endpoint-1"}]}})
        elif self.path.startswith("/?"):
            self._json({"data": {"affected_items": [{"version": "4.x"}]}})
        elif self.path == "/":
            self._json({"version": {"number": "9.x"}})
        else:
            self._json({}, 404)


def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def test_wazuh_auth_and_agents():
    httpd = server()
    try:
        url = f"http://127.0.0.1:{httpd.server_port}"
        client = WazuhClient(url, username="analyst", password="secret")
        assert client.authenticate() == "jwt-demo-token"
        assert client.agents()["data"]["affected_items"][0]["id"] == "001"
        assert integration_check("wazuh", client).ok
    finally:
        httpd.shutdown()


def test_elastic_search_and_export(tmp_path):
    httpd = server()
    try:
        url = f"http://127.0.0.1:{httpd.server_port}"
        client = ElasticClient(url, api_key="demo")
        out = tmp_path / "events.ndjson"
        assert client.export_ndjson("logs-*", out, size=10) == 1
        assert json.loads(out.read_text().strip())["_source"]["host"]["name"] == "WS-01"
        assert integration_check("elastic", client).ok
    finally:
        httpd.shutdown()


def test_misp_exact_ioc_enrichment():
    httpd = server()
    try:
        provider = MISPProvider(
            f"http://127.0.0.1:{httpd.server_port}",
            "demo-key",
        )
        result = provider.enrich(IOC("ip", "203.0.113.77", "external"))
        assert result is not None
        assert result.provider == "misp"
        assert "tlp:amber" in result.context
    finally:
        httpd.shutdown()


def test_opencti_graphql_transport():
    httpd = server()
    try:
        client = OpenCTIClient(
            f"http://127.0.0.1:{httpd.server_port}",
            "demo-token",
        )
        data = client.graphql("{ about { version } }")
        assert data["about"]["version"] == "demo"
    finally:
        httpd.shutdown()
