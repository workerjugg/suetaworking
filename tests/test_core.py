import base64
import json
import tempfile
import unittest
from pathlib import Path

from guardian import engine, generators, validate
from guardian.parsers import parse_line, parse_text
from guardian.pipeline import publish

U = "11111111-2222-3333-4444-555555555555"
VLESS_REALITY = f"vless://{U}@203.0.113.10:443?security=reality&sni=example.org&pbk=FAKEKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#a"
VLESS_SAME = f"vless://{U}@203.0.113.10:443?security=reality&sni=example.org&pbk=FAKEKEY#other-name"
TROJAN = "trojan://fakepass@203.0.113.11:443?sni=example.org#t"
SS = "ss://" + base64.b64encode(b"aes-256-gcm:fakepass").decode() + "@203.0.113.12:8388#s"
VMESS = "vmess://" + base64.b64encode(json.dumps(
    {"add": "203.0.113.13", "port": "443", "id": U, "net": "ws", "tls": "tls"}).encode()).decode()
INSECURE = f"vless://{U}@203.0.113.14:443?security=tls&allowInsecure=1"


class T(unittest.TestCase):
    def test_parse_all_protocols(self):
        for line, proto in [(VLESS_REALITY, "vless"), (TROJAN, "trojan"), (SS, "ss"), (VMESS, "vmess")]:
            n = parse_line(line)
            self.assertEqual(n.protocol, proto)
            self.assertEqual(validate.check_syntax(n), [])

    def test_corrupt_dropped(self):
        junk = parse_line("vless://%%%garbage")
        if junk is not None:  # парсер мягкий, отбраковку делает проверка синтаксиса
            validate.apply_static_checks(junk)
            self.assertEqual(junk.trust, "BLOCKED")
            self.assertTrue(junk.reject_reason.startswith("syntax:"))
        self.assertIsNone(parse_line("vmess://!!!"))
        self.assertIsNone(parse_line("http://x"))
        n = parse_line("vless://not-a-uuid@host.example:443")
        self.assertIn("bad_uuid", validate.check_syntax(n))

    def test_dedup_merges_sources(self):
        a, b = parse_line(VLESS_REALITY), parse_line(VLESS_SAME)
        a.sources, b.sources = {"s1"}, {"s2"}
        out = engine.deduplicate([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].sources, {"s1", "s2"})

    def test_suspicious_excluded(self):
        n = parse_line(INSECURE)
        validate.apply_static_checks(n)
        self.assertEqual(n.trust, "SUSPICIOUS")
        n.attempts = n.successes = 3
        n.latency_ms = 50
        self.assertEqual(engine.build_profiles([n])["all"], [])

    def test_private_address_rejected(self):
        n = parse_line(f"vless://{U}@127.0.0.1:443?security=tls&sni=x.example")
        validate.tcp_probe(n)
        self.assertEqual(n.trust, "BLOCKED")

    def test_base64_list(self):
        blob = base64.b64encode(f"{VLESS_REALITY}\n{TROJAN}\n".encode()).decode()
        self.assertEqual(len(parse_text(blob)), 2)

    def test_generators(self):
        nodes = [parse_line(VLESS_REALITY), parse_line(TROJAN), parse_line(SS)]
        dec = base64.b64decode(generators.uri_subscription(nodes)).decode().splitlines()
        self.assertEqual(len(dec), 3)
        cfg = json.loads(generators.singbox_config(nodes))
        types = {o["type"] for o in cfg["outbounds"]}
        self.assertTrue({"vless", "trojan", "shadowsocks", "urltest"} <= types)

    def test_failed_update_keeps_previous(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "subs"
            self.assertTrue(publish(out, {"best": "GOOD"}, 1, alive=5))
            self.assertFalse(publish(out, {"best": ""}, 1, alive=0))
            self.assertEqual((out / "best").read_text(), "GOOD")

    def test_public_dict_has_no_secrets(self):
        n = parse_line(VLESS_REALITY)
        blob = json.dumps(n.public_dict())
        self.assertNotIn(U, blob)
        self.assertNotIn("FAKEKEY", blob)


if __name__ == "__main__":
    unittest.main()
