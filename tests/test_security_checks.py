import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import patch

from scanners.secrets import scan_api_auth_patterns
from scanners.website import _SameOriginRedirects, _require_public_web_host
from engine.change_tracker import annotate_changes
from engine.reporter import save_report


class CustomPortScopeTests(unittest.TestCase):
    def setUp(self):
        self.config = {"authorized_hosts": ["pentest-ground.com"]}

    @patch("scanners.website.socket.getaddrinfo")
    def test_authorized_host_allows_arbitrary_nonstandard_http_port(self, resolver):
        resolver.return_value = [(None, None, None, None, ("178.79.134.182", 0))]
        _require_public_web_host("pentest-ground.com", 4280, self.config)
        _require_public_web_host("pentest-ground.com", 8443, self.config)
        _require_public_web_host("pentest-ground.com", 65535, self.config)
        self.assertEqual(resolver.call_count, 3)

    def test_rejects_nonstandard_port_for_unlisted_host(self):
        with self.assertRaisesRegex(PermissionError, "not authorized"):
            _require_public_web_host("other.example", 8443, self.config)

    @patch("scanners.website.socket.getaddrinfo")
    def test_standard_ports_remain_available_for_public_hosts(self, resolver):
        resolver.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        _require_public_web_host("other.example", 80, self.config)
        _require_public_web_host("other.example", 443, self.config)

    @patch("scanners.website.socket.getaddrinfo")
    def test_rejects_private_resolution_even_for_authorized_host(self, resolver):
        resolver.return_value = [(None, None, None, None, ("127.0.0.1", 0))]
        with self.assertRaisesRegex(PermissionError, "private, local, or reserved"):
            _require_public_web_host("pentest-ground.com", 4280, self.config)

    def test_reads_legacy_041_host_entries(self):
        legacy = {"allowed_host_ports": [{"host": "Pentest-Ground.com", "ports": [4280]}]}
        from scanners.website import _authorized_hosts
        self.assertIn("pentest-ground.com", _authorized_hosts(legacy))


class DashboardHostManagerTests(unittest.TestCase):

    def test_rejects_url_instead_of_hostname(self):
        from engine.scope import normalize_authorized_hostname
        with self.assertRaises(ValueError):
            normalize_authorized_hostname("https://lab.example.com:8443/path")

    def test_rejects_localhost_and_ip_addresses(self):
        from engine.scope import normalize_authorized_hostname
        for value in ("localhost", "127.0.0.1", "192.168.1.10"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_authorized_hostname(value)


class ApiHeuristicTests(unittest.TestCase):
    def test_flags_route_without_auth_and_object_ownership_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.js").write_text(
                "app.get('/item', async (req,res) => db.findUnique({id:req.params.id}));",
                encoding="utf-8",
            )
            titles = [x["title"] for x in scan_api_auth_patterns(root)]
            self.assertTrue(any("authentication guard" in x.lower() for x in titles))
            self.assertTrue(any("object-level authorization" in x.lower() for x in titles))

    def test_flags_disabled_supabase_function_jwt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "supabase").mkdir()
            (root / "supabase" / "config.toml").write_text(
                "[functions.admin]\nverify_jwt = false\n", encoding="utf-8"
            )
            titles = [x["title"] for x in scan_api_auth_patterns(root)]
            self.assertTrue(any("JWT verification disabled" in x for x in titles))

    def test_flags_unverified_jwt_decode_and_wildcard_cors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "routes.py").write_text(
                "@app.get('/data')\ndef data(request):\n    payload = jwt.decode(token)\n    return payload\n" 
                "response.headers['Access-Control-Allow-Origin'] = '*'\n",
                encoding="utf-8",
            )
            titles = [x["title"] for x in scan_api_auth_patterns(root)]
            self.assertTrue(any("JWT decode" in x for x in titles))
            self.assertTrue(any("Wildcard CORS" in x for x in titles))

    def test_flags_sql_tables_without_visible_rls_and_broad_grants(self):
        from scanners.secrets import scan_supabase_sql
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "migration.sql").write_text(
                "create table public.customer_records (id uuid);\n"
                "grant all on all tables in schema public to anon;\n",
                encoding="utf-8",
            )
            titles = [x["title"] for x in scan_supabase_sql(root)]
            self.assertTrue(any("RLS enable statement not found" in x for x in titles))
            self.assertTrue(any("Broad table privileges" in x for x in titles))


class SafetyAndReportingTests(unittest.TestCase):

    def test_open_scope_accepts_public_origin_without_network_io(self):
        from unittest.mock import patch
        from scanners.website import scan_website
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps({"allow_any_public_origin": True, "allowed_origins": []}), encoding="utf-8")
            fake_record = (None, None, None, None, ("93.184.216.34", 443))
            with patch("scanners.website.socket.getaddrinfo", return_value=[fake_record]), \
                 patch("scanners.website._get", return_value=(200, {"content-security-policy": "default-src 'self'"}, b"ok")):
                result = scan_website("https://example.com", scope)
            self.assertEqual(result["target"], "https://example.com/")


    def test_accepts_route_path_and_checks_requested_page(self):
        from unittest.mock import patch
        from scanners.website import scan_website
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps({"allow_any_public_origin": True, "allowed_origins": []}), encoding="utf-8")
            fake_record = (None, None, None, None, ("93.184.216.34", 443))
            calls = []
            def fake_get(url, origin):
                calls.append(url)
                return (200, {"content-security-policy": "default-src 'self'"}, b"ok") if url.endswith("/guestbook") else (404, {}, b"")
            with patch("scanners.website.socket.getaddrinfo", return_value=[fake_record]), \
                 patch("scanners.website._get", side_effect=fake_get):
                result = scan_website("example.com/guestbook", scope)
            self.assertEqual(result["target"], "https://example.com/guestbook")
            self.assertEqual(calls[0], "https://example.com/guestbook")
            self.assertIn("https://example.com/.env", calls)
            self.assertIn("https://example.com/guestbook/.env", calls)

    def test_rejects_query_string_and_fragment(self):
        from scanners.website import _normalize_target
        with self.assertRaises(ValueError):
            _normalize_target("https://example.com/rsvp?token=abc")
        with self.assertRaises(ValueError):
            _normalize_target("https://example.com/rsvp#section")

    def test_open_scope_blocks_private_address_resolution(self):
        from unittest.mock import patch
        from scanners.website import scan_website
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps({"allow_any_public_origin": True, "allowed_origins": []}), encoding="utf-8")
            fake_record = (None, None, None, None, ("192.168.1.10", 443))
            with patch("scanners.website.socket.getaddrinfo", return_value=[fake_record]):
                with self.assertRaises(PermissionError):
                    scan_website("https://private.example", scope)

    def test_open_scope_blocks_nonstandard_ports(self):
        from scanners.website import scan_website
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps({"allow_any_public_origin": True, "allowed_origins": []}), encoding="utf-8")
            with self.assertRaises(PermissionError):
                scan_website("https://example.com:8443", scope)

    def test_blocks_cross_origin_redirects(self):
        handler = _SameOriginRedirects("https://owned.example")
        with self.assertRaises(URLError):
            handler.redirect_request(None, None, 302, "Found", {}, "https://other.example/path")

    def test_change_tracker_records_new_and_resolved_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            baseline = {"target": "repo", "scan_type": "repository", "findings": [
                {"severity": "low", "category": "a", "title": "old", "file": "x", "line": 1, "evidence": "e", "recommendation": "review"}
            ]}
            save_report(baseline, reports)
            current = {"target": "repo", "scan_type": "repository", "findings": [
                {"severity": "low", "category": "a", "title": "new", "file": "y", "line": 1, "evidence": "f", "recommendation": "review"}
            ]}
            result = annotate_changes(current, reports)
            self.assertEqual(result["change_summary"]["new"], 1)
            self.assertEqual(result["change_summary"]["resolved"], 1)

    def test_markdown_report_contains_real_line_breaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, md = save_report({"scan_type": "test", "target": "local", "findings": [], "notes": ["safe"]}, Path(tmp))
            content = md.read_text(encoding="utf-8")
            self.assertIn("\n- **Target:**", content)
            self.assertNotIn("\\n- **Target:**", content)


if __name__ == "__main__":
    unittest.main()
