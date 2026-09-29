import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from socmind.integrations import ElasticClient, WazuhClient, integration_check
from socmind.cli import main as cli_main
from socmind.command_center import list_cases
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
            if "wazuh-alerts" in self.path:
                self._json({
                    "hits": {
                        "hits": [{
                            "_id": "wazuh-live-001",
                            "_source": {
                                "timestamp": "2026-09-28T10:00:00Z",
                                "agent": {"name": "WS-01"},
                                "rule": {
                                    "id": "60122",
                                    "level": 12,
                                    "description": "Live Wazuh credential attack",
                                    "mitre": {"id": ["T1110"]},
                                },
                                "data": {
                                    "srcip": "198.51.100.22",
                                    "dstuser": "analyst",
                                },
                            },
                        }]
                    }
                })
            else:
                self._json({
                    "hits": {
                        "hits": [{
                            "_id": "elastic-live-001",
                            "_source": {
                                "@timestamp": "2026-09-28T10:03:00Z",
                                "host": {"name": "WS-01"},
                                "user": {"name": "analyst"},
                                "process": {"name": "powershell.exe"},
                                "source": {"ip": "198.51.100.22"},
                                "destination": {"ip": "203.0.113.77"},
                                "kibana.alert.rule.rule_id": "elastic-live-rule",
                                "kibana.alert.rule.name": "Live Elastic PowerShell",
                                "kibana.alert.severity": "critical",
                                "kibana.alert.risk_score": 90,
                                "kibana.alert.rule.threat": [{
                                    "framework": "MITRE ATT&CK",
                                    "technique": [{"id": "T1059.001"}],
                                }],
                            },
                        }]
                    }
                })
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


def test_alert_live_elastic_cli_creates_case(tmp_path, monkeypatch, capsys):
    httpd = server()
    try:
        db = tmp_path / "elastic-live.db"
        evidence = tmp_path / "evidence"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "socmind",
                "alert-live",
                "elastic",
                f"http://127.0.0.1:{httpd.server_port}",
                ".alerts-security.alerts-default",
                "--database",
                str(db),
                "--evidence-dir",
                str(evidence),
                "--json",
            ],
        )
        cli_main()
        payload = json.loads(capsys.readouterr().out)
        assert payload["provider"] == "elastic"
        assert payload["hits"] == 1
        assert payload["new_cases"] == 1
        assert payload["results"][0]["priority"] == "P1"
        assert len(list_cases(db)) == 1
    finally:
        httpd.shutdown()


def test_alert_live_wazuh_indexer_cli_creates_case(tmp_path, monkeypatch, capsys):
    httpd = server()
    try:
        db = tmp_path / "wazuh-live.db"
        evidence = tmp_path / "evidence"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "socmind",
                "alert-live",
                "wazuh-indexer",
                f"http://127.0.0.1:{httpd.server_port}",
                "wazuh-alerts*",
                "--database",
                str(db),
                "--evidence-dir",
                str(evidence),
                "--json",
            ],
        )
        cli_main()
        payload = json.loads(capsys.readouterr().out)
        assert payload["provider"] == "wazuh-indexer"
        assert payload["hits"] == 1
        assert payload["new_cases"] == 1
        assert payload["results"][0]["priority"] == "P1"
        assert len(list_cases(db)) == 1
    finally:
        httpd.shutdown()
