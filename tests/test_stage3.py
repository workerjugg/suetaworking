import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from guardian import engine, failover, generators, geo, history, notify, pipeline, tunnel, validate
from guardian.failover import Candidate, Failover
from guardian.parsers import parse_line, parse_text
from guardian.regions import region_of

U = "11111111-2222-3333-4444-555555555555"
V = f"vless://{U}@203.0.113.10:443?security=reality&sni=example.org&pbk=FAKEKEY&sid=ab&flow=xtls-rprx-vision#a"
T = "trojan://fakepass@203.0.113.11:443?sni=example.org#t"
VM = "vmess://" + base64.b64encode(json.dumps(
    {"add": "203.0.113.13", "port": "443", "id": U, "net": "ws", "tls": "tls", "path": "/x", "host": "h.example"}).encode()).decode()


def good(line, cc="DE", lat=50.0, trust="PUBLIC", **kw):
    n = parse_line(line)
    n.attempts, n.successes, n.latency_ms, n.jitter_ms = 3, 3, lat, 1.0
    n.country, n.region, n.trust = cc, region_of(cc), trust
    for k, v in kw.items():
        setattr(n, k, v)
    return n


class Regions(unittest.TestCase):
    def test_regions(self):
        self.assertEqual([region_of(c) for c in ("DE", "JP", "US", "RU", "ZZ")],
                         ["europe", "asia", "america", "russia", "other"])


class Geo(unittest.TestCase):
    def test_annotate_uses_exit_ip_and_survives_failure(self):
        n = good(V, cc="")
        n.exit_ip = "198.51.100.7"
        geo.annotate([n], fetch=lambda ch: [{"status": "success", "query": "198.51.100.7", "countryCode": "JP"}])
        self.assertEqual((n.country, n.region), ("JP", "asia"))
        m = good(T, cc="")
        m.exit_ip = "198.51.100.8"
        geo.annotate([m], fetch=lambda ch: (_ for _ in ()).throw(OSError("down")))
        self.assertEqual(m.country, "")


class Profiles(unittest.TestCase):
    def test_russia_not_in_best_and_region_profiles(self):
        ru = good(V, "RU", 10)
        de = good(T, "DE", 80)
        p = engine.build_profiles([ru, de])
        self.assertEqual([n.country for n in p["best"]], ["DE"])
        self.assertEqual(len(p["russia"]), 1)
        self.assertEqual(len(p["europe"]), 1)
        self.assertEqual(len(p["all"]), 2)

    def test_privacy_only_trusted(self):
        a, b = good(V, trust="TRUSTED"), good(T, trust="PUBLIC")
        self.assertEqual(len(engine.build_profiles([a, b])["privacy"]), 1)

    def test_require_tunnel(self):
        a = good(V)
        self.assertEqual(len(engine.build_profiles([a], require_tunnel=True)["all"]), 0)
        a.tunnel_ok = True
        self.assertEqual(len(engine.build_profiles([a], require_tunnel=True)["all"]), 1)
        a.tunnel_ok = False
        self.assertEqual(len(engine.build_profiles([a])["all"]), 0)

    def test_fast_profile_needs_measured_speed(self):
        a = good(V, speed_mbps=40.0)
        b = good(T)
        self.assertEqual(len(engine.build_profiles([a, b])["fast"]), 1)

    def test_country_cap(self):
        nodes = [good(f"trojan://p{i}@203.0.113.{i + 20}:443?sni=e.org", "DE", 50 + i) for i in range(8)]
        nodes += [good(f"trojan://q{i}@203.0.113.{i + 60}:443?sni=e.org", "JP", 120 + i) for i in range(8)]
        best = engine.build_profiles(nodes)["best"]
        self.assertLessEqual(sum(1 for n in best if n.country == "DE"), 5)


class AllProfile(unittest.TestCase):
    def test_all_is_verified_only_sorted_by_ping(self):
        a = good(V, "DE", 90, tunnel_ok=True)
        b = good(T, "NL", 20, tunnel_ok=True)
        w = good("trojan://w@203.0.113.50:443?sni=e.org", "RU", 5)
        w.tags = {"whitelist"}
        w.tunnel_ok = False          # с раннера не прошёл, но whitelist-узлы сохраняются
        order = [n.country for n in engine.build_profiles([a, b, w])["all"]]
        self.assertEqual(order, ["NL", "DE"])

    def test_strict_mode_drops_half_working_and_slow(self):
        full = good(V, "DE", 50, tunnel_ok=True, tunnel_attempts=2, tunnel_successes=2, speed_mbps=8.0)
        half = good(T, "NL", 40, tunnel_ok=True, tunnel_attempts=2, tunnel_successes=1, speed_mbps=8.0)
        slow = good("trojan://s@203.0.113.60:443?sni=e.org", "FR", 30, tunnel_ok=True,
                    tunnel_attempts=2, tunnel_successes=2, speed_mbps=0.3)
        nospeed = good("trojan://n@203.0.113.61:443?sni=e.org", "SE", 30, tunnel_ok=True,
                       tunnel_attempts=2, tunnel_successes=2)
        flaky = good("trojan://f@203.0.113.62:443?sni=e.org", "ES", 30, tunnel_ok=True,
                     tunnel_attempts=2, tunnel_successes=2, speed_mbps=8.0, hist_ok=1, hist_total=10)
        p = engine.build_profiles([full, half, slow, nospeed, flaky], strict=True, min_speed=1.0)
        self.assertEqual([n.country for n in p["all"]], ["DE"])
        self.assertEqual(len(engine.build_profiles([full, half, slow]).get("all")), 3)  # без strict — как раньше

    def test_all_limit(self):
        nodes = [good(f"trojan://p{i}@203.0.113.{i + 1}:443?sni=e.org", "DE", 10 + i) for i in range(20)]
        self.assertEqual(len(engine.build_profiles(nodes, all_limit=7)["all"]), 7)


class StablePick(unittest.TestCase):
    def _n(self, i, cc, lat, **kw):
        return good(f"trojan://p{i}@203.0.113.{i + 1}:443?sni=e.org", cc, lat,
                    tunnel_ok=True, tunnel_attempts=2, tunnel_successes=2, speed_mbps=5.0, **kw)

    def test_size_country_cap_whitelist_and_kazakhstan(self):
        nodes = [self._n(i, "DE", 30 + i) for i in range(12)]          # много быстрых немецких
        nodes += [self._n(20 + i, "FI", 60 + i) for i in range(5)]
        kz = self._n(40, "KZ", 150)                                     # хуже по пингу, но казахский
        wl = self._n(41, "RU", 200); wl.tags = {"whitelist"}            # whitelist: RU допускается
        plain_ru = self._n(42, "RU", 5)                                 # обычный RU — не берём
        stable = engine.build_profiles(nodes + [kz, wl, plain_ru])["stable"]
        ids = {n.fingerprint for n in stable}
        self.assertIn(kz.fingerprint, ids)
        self.assertIn(wl.fingerprint, ids)
        self.assertNotIn(plain_ru.fingerprint, ids)
        self.assertLessEqual(sum(1 for n in stable if n.country == "DE"), 6)
        self.assertLessEqual(len(stable), 20)

    def test_proximity_and_history_raise_rank(self):
        near = self._n(1, "FI", 80)
        far = self._n(2, "US", 80)
        self.assertGreater(engine.stable_score(near), engine.stable_score(far))
        steady = self._n(3, "US", 80, hist_ok=9, hist_total=10)
        self.assertGreater(engine.stable_score(steady), engine.stable_score(far))

    def test_stable_size_limit(self):
        nodes = [self._n(i, ["DE", "FI", "NL", "SE", "PL", "CZ", "AT", "FR"][i % 8], 30 + i) for i in range(60)]
        self.assertEqual(len(engine.build_profiles(nodes, stable_size=20)["stable"]), 20)


class Generators(unittest.TestCase):
    def test_label_keeps_uri_valid(self):
        n = good(V)
        u = generators.labeled_uri(n)
        n2 = parse_line(u)
        self.assertEqual((n2.host, n2.port, n2.identity), (n.host, n.port, n.identity))
        self.assertIn("PUBLIC", u)
        self.assertEqual(generators.flag("DE"), "\U0001F1E9\U0001F1EA")
        self.assertIn("%F0%9F%87%A9%F0%9F%87%AA", u)   # флаг в имени, закодирован корректно
        v = parse_line(generators.labeled_uri(good(VM)))
        self.assertEqual(v.host, "203.0.113.13")

    def test_vmess_singbox(self):
        o = generators.singbox_outbound(parse_line(VM))
        self.assertEqual(o["type"], "vmess")
        self.assertEqual(o["transport"]["type"], "ws")
        self.assertTrue(o["tls"]["enabled"])

    def test_incy_and_happ(self):
        s = generators.incy_subscription([good(V)], interval_h=6)
        self.assertIn("#profile-update-interval: 6", s)
        self.assertIn("#profile-title: FreeVPN Guardian", s)
        self.assertIn("vless://", s)
        self.assertTrue(generators.happ_subscription([good(V)]).startswith("vless://"))

    def test_tunnel_config(self):
        cfg = tunnel.build_test_config(parse_line(V), 12345)
        self.assertEqual(cfg["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(cfg["outbounds"][0]["tag"], "proxy")
        self.assertEqual(cfg["outbounds"][0]["tls"]["reality"]["public_key"], "FAKEKEY")


class Robustness(unittest.TestCase):
    def test_bad_fingerprint_and_vmess_security_are_normalized(self):
        n = parse_line(f"vless://{U}@203.0.113.10:443?security=tls&sni=e.org&fp=unsafe")
        self.assertEqual(generators.singbox_outbound(n)["tls"]["utls"]["fingerprint"], "chrome")
        n = parse_line(f"vless://{U}@203.0.113.10:443?security=tls&sni=e.org&fp=Firefox")
        self.assertEqual(generators.singbox_outbound(n)["tls"]["utls"]["fingerprint"], "firefox")
        vm = parse_line("vmess://" + base64.b64encode(json.dumps(
            {"add": "203.0.113.13", "port": "443", "id": U, "scy": "None2"}).encode()).decode())
        self.assertEqual(generators.singbox_outbound(vm)["security"], "auto")

    def test_http_403_retries_with_browser_ua(self):
        import urllib.error
        calls = []
        class R:
            def read(s, n): return b"vless://x"
            def __enter__(s): return s
            def __exit__(s, *a): pass
        def fake_open(req, timeout=0):
            calls.append(req.headers.get("User-agent"))
            if len(calls) == 1:
                raise urllib.error.HTTPError(req.full_url, 403, "forbidden", {}, None)
            return R()
        with mock.patch("urllib.request.urlopen", fake_open):
            self.assertEqual(pipeline.fetch_url("https://example.com/x"), "vless://x")
        self.assertEqual(len(calls), 2)
        self.assertIn("Mozilla", calls[1])


class Parsing(unittest.TestCase):
    def test_mixed_plain_and_nested_base64(self):
        inner = base64.b64encode(f"{T}\n".encode()).decode()
        text = f"{V}\n{inner}\n#comment\n"
        self.assertEqual(len(parse_text(text)), 2)


class History(unittest.TestCase):
    def test_update_and_ttl(self):
        h = {}
        n = good(V, tunnel_ok=True)
        now = datetime(2026, 1, 10, tzinfo=timezone.utc)
        history.update(h, [n], now)
        self.assertEqual(h[n.fingerprint]["runs"], [1])
        history.update(h, [], now + timedelta(days=4), ttl_days=3)
        self.assertEqual(h, {})

    def test_stability_blends_history(self):
        n = good(V)
        n.hist_ok, n.hist_total = 1, 10
        self.assertLess(n.stability, 0.6)


class FailoverTests(unittest.TestCase):
    def cands(self, a=100, b=40):
        return [Candidate("A", a, score=1000 / a), Candidate("B", b, score=1000 / b)]

    def test_picks_best_initially(self):
        f = Failover()
        self.assertEqual(f.step(0, True, self.cands()), "B")

    def test_single_failure_is_not_outage(self):
        f = Failover(); f.current = "A"; f.last_switch = -1e9
        self.assertIsNone(f.step(0, False, self.cands()))
        self.assertIsNone(f.step(1, False, self.cands()))
        self.assertEqual(f.step(2, False, self.cands()), "B")  # 3-й подряд

    def test_hysteresis_and_stable_time(self):
        f = Failover(min_stable_s=60, cooldown_s=10); f.current = "A"
        c = self.cands(100, 90)  # B лучше всего на ~11% < 25%
        for t in range(0, 200, 20):
            self.assertIsNone(f.step(t, True, c))
        c = self.cands(100, 40)
        # теперь B лучше в 2.5 раза (> гистерезиса) и текущий стабилен давно -> переключаемся
        self.assertEqual(f.step(1000, True, c), "B")

    def test_cooldown_blocks_flapping(self):
        f = Failover(cooldown_s=300, min_stable_s=0); f.current = "A"
        f.step(0, True, self.cands())          # since_ok=0, переключение на B (40 лучше 100)
        self.assertEqual(f.current, "B")
        for t in (10, 50, 100):
            self.assertIsNone(f.step(t, True, [Candidate("A", 10, score=100), Candidate("B", 40, score=25)]))

    def test_switch_limit_per_hour(self):
        f = Failover(max_switches_per_hour=2, fail_threshold=1, cooldown_s=0); f.current = "A"
        out = [f.step(t, False, self.cands()) for t in (0, 1, 2, 3)]
        self.assertEqual(sum(1 for o in out if o), 2)

    def test_manual_and_privacy(self):
        self.assertIsNone(Failover(mode="MANUAL").step(0, False, self.cands()))
        f = Failover(mode="PRIVACY")
        self.assertIsNone(f.step(0, True, self.cands()))  # нет доверенных


class Notify(unittest.TestCase):
    def test_events(self):
        ev = notify.evaluate({"alive": 100, "published": True}, {"alive": 10, "published": True}, 5)
        self.assertEqual(ev[0]["level"], "warning")          # падение — предупреждение, не «красный» запуск
        ev = notify.evaluate({"alive": 100, "published": True}, {"alive": 0, "published": False}, 5)
        self.assertTrue(any(e["level"] == "critical" for e in ev))
        ev = notify.evaluate({"alive": 0, "published": False}, {"alive": 50, "published": True}, 5)
        self.assertEqual(ev[0]["level"], "info")
        self.assertFalse(notify.send_telegram("x"))  # без токена — no-op


class EndToEnd(unittest.TestCase):
    def _cfg(self, src):
        return {"limits": {"min_alive": 1, "source_delay": 0},
                "sources": [{"name": "fake", "type": "file", "location": str(src)}]}

    def test_run_publish_and_keep_last_good(self):
        def fake_probe(n, **kw):
            n.attempts, n.successes, n.latency_ms, n.jitter_ms = 3, 3, 60.0, 1.0
        with tempfile.TemporaryDirectory() as d, mock.patch.object(validate, "tcp_probe", fake_probe):
            d = Path(d)
            src = d / "s.txt"
            src.write_text(f"{V}\n{T}\n{VM}\n")
            out = d / "subs"
            geo_fetch = lambda ch: [{"status": "success", "query": q, "countryCode": "DE"} for q in ch]
            st = pipeline.run(self._cfg(src), out, data_dir=d / "data", use_tunnel=False, geo_fetch=geo_fetch)
            self.assertTrue(st["published"])
            self.assertEqual(st["alive"], 3)
            for name in ("all", "best", "europe", "happ", "incy", "singbox", "v2rayn", "stats.json", "compat.json"):
                self.assertTrue((out / name).exists(), name)
            servers = (out / "servers.json").read_text()
            self.assertNotIn(U, servers)
            self.assertNotIn("FAKEKEY", servers)
            self.assertEqual(json.loads(servers)[0]["country"], "DE")
            good_best = (out / "best").read_text()
            # источник «упал»: прежняя подписка должна остаться
            src.write_text("garbage")
            st2 = pipeline.run(self._cfg(src), out, data_dir=d / "data", use_tunnel=False, geo_fetch=geo_fetch)
            self.assertFalse(st2["published"])
            self.assertTrue(st2["critical"])
            self.assertEqual((out / "best").read_text(), good_best)


class Whitelist(unittest.TestCase):
    def test_whitelist_profile_ignores_runner_tunnel_failure(self):
        n = good(V, "RU", 40)
        n.tags = {"whitelist"}
        n.tunnel_ok = False
        p = engine.build_profiles([n])
        self.assertEqual(len(p["whitelist"]), 1)
        self.assertEqual(len(p["verified"]), 0)
        self.assertEqual(len(p["all"]), 0)     # в `all` только проверенные; whitelist без проверки — отдельно

    def test_whitelist_excludes_suspicious(self):
        n = good(V, "RU", 40, trust="SUSPICIOUS")
        n.tags = {"whitelist"}
        self.assertEqual(engine.build_profiles([n])["whitelist"], [])

    def test_dedup_merges_tags(self):
        a, b = parse_line(V), parse_line(V)
        a.tags, b.tags = {"x"}, {"whitelist"}
        self.assertEqual(engine.deduplicate([a, b])[0].tags, {"x", "whitelist"})

    def test_plain_list_with_hash_headers_is_not_mistaken_for_base64(self):
        head = "\n".join(["# profile-title: WHITE LISTS", "# profile-update-interval: 1",
                          "# Date/Time: 2026-09-08 / 23:30 (Moscow)", "# Количество: 2",
                          "# For more info - visit: www.github.com/igareck/vpn-configs-for-russia", ""])
        self.assertEqual(len(parse_text(head + V + "\n" + T + "\n")), 2)
        base = "#profile-title: base64:AAAA\n#support-url: https://github.com/x/y\n"
        self.assertEqual(len(parse_text(base + V + "\n")), 1)

    def test_oversized_source_is_truncated_not_dropped(self):
        big = (V + "\n") * 10
        class R:
            def __init__(s, d): s.d = d
            def read(s, n): return s.d[:n]
            def __enter__(s): return s
            def __exit__(s, *a): pass
        with mock.patch.object(pipeline, "MAX_BYTES", len(V) * 3), \
             mock.patch("urllib.request.urlopen", lambda *a, **k: R(big.encode())):
            txt = pipeline.fetch_url("https://example.com/x")
        self.assertTrue(txt.startswith("vless://"))
        self.assertLessEqual(len(txt.splitlines()), 3)

    def test_max_probe_limit(self):
        def fake_probe(n, **kw):
            n.attempts, n.successes, n.latency_ms, n.jitter_ms = 3, 3, 50.0, 1.0
        lines = [f"trojan://p{i}@203.0.113.{i % 250 + 1}:{1000 + i}?sni=e.org" for i in range(30)]
        with tempfile.TemporaryDirectory() as d, mock.patch.object(validate, "tcp_probe", fake_probe):
            d = Path(d); (d / "s.txt").write_text("\n".join(lines))
            cfg = {"limits": {"min_alive": 1, "source_delay": 0, "max_probe": 10},
                   "sources": [{"name": "s", "type": "file", "location": str(d / "s.txt"), "tags": ["whitelist"]}]}
            st = pipeline.run(cfg, d / "subs", data_dir=d / "data", use_tunnel=False, use_geo=False)
        self.assertEqual(st["alive"], 10)
        self.assertEqual(st["not_probed"], 20)
        self.assertEqual(st["profiles"]["whitelist"], 10)


if __name__ == "__main__":
    unittest.main()
