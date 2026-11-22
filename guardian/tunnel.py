"""Уровни 3-5: реальное подключение через sing-box и проверка через туннель.

Для каждого узла поднимается локальный sing-box с mixed-inbound на 127.0.0.1,
через него делаются HTTPS-запросы. Узел считается рабочим, только если:
  1) generate_204 вернул 204 (HTTPS через туннель работает),
  2) получен валидный внешний IP, и он ОТЛИЧАЕТ­СЯ от прямого IP раннера
     (значит, трафик действительно вышел через узел).
Скорость и задержка измеряются с раннера GitHub, а не из вашей сети.
Бинарник sing-box берётся только из официального релиза (см. workflow).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import generators
from .models import Node

TEST_URLS = ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"]
IP_URLS = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=2000000"


def find_singbox() -> str | None:
    return os.environ.get("SINGBOX_BIN") or shutil.which("sing-box")


def build_test_config(n: Node, port: int) -> dict | None:
    ob = generators.singbox_outbound(n)
    if not ob:
        return None
    ob["tag"] = "proxy"
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [ob],
        "route": {"final": "proxy"},
    }


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str, proxy_port: int | None, timeout: float, max_bytes: int = 4096):
    handlers = []
    if proxy_port:
        p = f"http://127.0.0.1:{proxy_port}"
        handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    t0 = time.perf_counter()
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "FreeVPN-Guardian"}),
                     timeout=timeout) as r:
        data = r.read(max_bytes)
        return r.status, data, time.perf_counter() - t0


def _fetch_ip(port: int | None, timeout: float) -> str:
    for u in IP_URLS:
        try:
            _, data, _ = _get(u, port, timeout)
            ip = data.decode().strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    return ""


def direct_ip(timeout: float = 10) -> str:
    return _fetch_ip(None, timeout)


def _wait_port(port: int, proc, deadline: float) -> bool:
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


DIAG: Counter = Counter()      # причины отказов тестов через туннель (для лога и stats.json)


def _first_err(path: Path) -> str:
    try:
        txt = path.read_text(errors="replace").strip().splitlines()[0]
    except Exception:
        return "no_stderr"
    return re.sub(r"[0-9a-fA-F\-]{8,}|\d+", "N", txt)[:140]


def test_node(n: Node, binary: str, my_ip: str, with_speed: bool = False,
              tries: int = 2, timeout: float = 8) -> None:
    port = _free_port()
    cfg = build_test_config(n, port)
    if cfg is None:
        n.reject_reason = n.reject_reason or "unsupported_for_tunnel_test"
        DIAG["unsupported_for_tunnel_test"] += 1
        return
    n.tunnel_attempts = tries
    n.tunnel_successes = 0
    with tempfile.TemporaryDirectory() as d:
        path, errp = Path(d) / "c.json", Path(d) / "err.txt"
        path.write_text(json.dumps(cfg))
        with open(errp, "wb") as errf:
            proc = subprocess.Popen([binary, "run", "-c", str(path)],
                                    stdout=subprocess.DEVNULL, stderr=errf)
            try:
                if not _wait_port(port, proc, time.time() + 6):
                    n.tunnel_ok = False
                    n.reject_reason = "singbox_start_failed"
                    DIAG["start_failed: " + _first_err(errp)] += 1
                    return
                lat = []
                for _ in range(tries):
                    try:
                        st, dt, last = None, 0.0, ""
                        for url in TEST_URLS:
                            try:
                                st, _, dt = _get(url, port, timeout)
                                if st == 204:
                                    break
                            except Exception as e:
                                last = type(e).__name__
                        if st != 204:
                            DIAG["no_204: " + (last or str(st))] += 1
                            continue
                        ip = _fetch_ip(port, timeout)   # вторично: геолокация и проверка «утечки»
                        if ip and ip == my_ip:
                            DIAG["ip_leak"] += 1
                            continue
                        n.tunnel_successes += 1
                        DIAG["ok"] += 1
                        if ip:
                            n.exit_ip = ip
                        lat.append(dt * 1000)
                    except Exception as e:
                        DIAG["error: " + type(e).__name__] += 1
                        continue
                n.tunnel_ok = n.tunnel_successes >= 1
                if lat:
                    n.tunnel_ms = round(min(lat), 1)
                else:
                    n.reject_reason = "tunnel_failed"
                if n.tunnel_ok and with_speed:
                    try:
                        t0 = time.perf_counter()
                        _, data, _ = _get(SPEED_URL, port, 20, max_bytes=2_000_000)
                        dt = time.perf_counter() - t0
                        if len(data) > 100_000 and dt > 0:
                            n.speed_mbps = round(len(data) * 8 / dt / 1e6, 1)
                    except Exception:
                        pass
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()


def run_tunnel_tests(nodes: list[Node], binary: str, budget: int = 300, workers: int = 8,
                     speed_top: int = 30, max_seconds: int = 1500) -> dict:
    """Тестирует до `budget` самых быстрых по TCP узлов. Остальные остаются
    с tunnel_ok=None (не проверялись) и в подписки не попадают."""
    my_ip = direct_ip()
    if not my_ip:
        return {"ran": False, "reason": "no_direct_ip"}
    cands = sorted((n for n in nodes if n.alive), key=lambda n: n.latency_ms or 1e9)[:budget]
    deadline = time.time() + max_seconds

    def job(args):
        i, n = args
        if time.time() > deadline:
            return
        test_node(n, binary, my_ip, with_speed=i < speed_top)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(job, enumerate(cands)))
    ok = sum(1 for n in cands if n.tunnel_ok)
    return {"ran": True, "tested": len(cands), "passed": ok, "diag": dict(DIAG.most_common(10))}
