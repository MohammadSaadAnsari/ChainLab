"""Tests for the decisions and traffic generator used in the live demo."""

from io import BytesIO
import unittest

from demo_http_server import DemoHandler
from sfc_policy import PolicyState
from vnf_configs.ids.signature import is_attack


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.policy = PolicyState(clock=lambda: self.now[0])

    def test_trusted_bypass_untrusted_chain_and_live_policy_change(self):
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 8080), "direct")
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 80), "chain")
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 23), "chain")
        self.policy.set_tcp_policy(80, "direct")
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 80), "direct")
        self.policy.set_tcp_policy(80, "chain")
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 80), "chain")

    def test_ids_quarantine_expires_and_allows_reclassification(self):
        self.policy.quarantine("10.0.0.1", 60)
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 8080), "drop")
        self.now[0] += 61
        self.assertEqual(self.policy.classify_tcp("10.0.0.1", 8080), "direct")
        self.assertEqual(self.policy.snapshot()["quarantined"], {})

    def test_invalid_policy_is_rejected(self):
        for port in (True, 0, 65536, "80"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.policy.set_tcp_policy(port, "direct")
        with self.assertRaises(ValueError):
            self.policy.set_tcp_policy(80, "unknown")


class SignatureTests(unittest.TestCase):
    def test_only_demo_attack_requests_raise_alert(self):
        self.assertTrue(is_attack(b"GET /attack HTTP/1.1\r\nHost: h2\r\n\r\n"))
        self.assertTrue(is_attack(b"GET / HTTP/1.1\r\nX-SFC-Attack: 1\r\n\r\n"))
        self.assertFalse(is_attack(b"GET / HTTP/1.1\r\nHost: h2\r\n\r\n"))
        self.assertFalse(is_attack(b"GET /attacker HTTP/1.1\r\n\r\n"))


class DemoServerTests(unittest.TestCase):
    def request(self, method, path, body=None):
        # Drive the handler directly because CI/sandbox environments may
        # prohibit even loopback sockets.
        handler = DemoHandler.__new__(DemoHandler)
        handler.path = path
        handler.headers = {"Content-Length": str(len(body or b""))}
        handler.rfile = BytesIO(body or b"")
        handler.wfile = BytesIO()
        result = {}
        handler.send_response = lambda status: result.update(status=status)
        handler.send_header = lambda *_: None
        handler.end_headers = lambda: None
        getattr(handler, f"do_{method}")()
        return result["status"], handler.wfile.getvalue()

    def test_get_attack_and_bulk_upload(self):
        status, body = self.request("GET", "/attack")
        self.assertEqual(status, 200)
        self.assertIn(b"signature", body)
        status, body = self.request("POST", "/upload", b"x" * 65536)
        self.assertEqual(status, 200)
        self.assertIn(b"65536", body)


if __name__ == "__main__":
    unittest.main()
