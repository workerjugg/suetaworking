"""Уровни 1 (синтаксис), 2 (TCP-доступность), 6 (флаги безопасности)."""
from __future__ import annotations

import ipaddress
import re
import socket
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

from .models import Node

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$")


def is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_global


def check_syntax(n: Node) -> list[str]:
    errs = []
    if not (1 <= n.port <= 65535):
        errs.append("bad_port")
    if not n.host:
        errs.append("no_host")
    else:
        try:
            ipaddress.ip_address(n.host)
        except ValueError:
            if not HOST_RE.match(n.host):
                errs.append("bad_host")
    if not n.identity:
        errs.append("no_identity")
    p = n.params
    if n.protocol in ("vless", "vmess") and not UUID_RE.match(n.identity):
        errs.append("bad_uuid")
    if n.protocol == "vless" and p.get("security") == "reality":
        if not p.get("pbk"):
            errs.append("reality_no_pbk")
        if not p.get("sni"):
            errs.append("reality_no_sni")
    if n.protocol == "ss" and not p.get("method"):
        errs.append("ss_no_method")
    return errs


def check_security(n: Node) -> list[str]:
    flags = []
    p = n.params
    if p.get("allowInsecure") in ("1", "true") or p.get("insecure") in ("1", "true"):
        flags.append("tls_verify_disabled")
    if p.get("plugin"):
        flags.append("ss_plugin")
    if n.protocol == "vless" and p.get("security", "none") == "none":
        flags.append("no_encryption_transport")
    if n.protocol == "ss" and p.get("method", "").lower() in ("rc4", "rc4-md5", "none", "table"):
        flags.append("weak_cipher")
    if n.protocol == "trojan" and p.get("security") == "none":
        flags.append("no_tls")
    return flags


def apply_static_checks(n: Node, trusted: bool = False) -> None:
    n.errors = check_syntax(n)
    n.flags = check_security(n)
    if n.errors:
        n.trust, n.reject_reason = "BLOCKED", "syntax:" + ",".join(n.errors)
    elif n.flags:
        n.trust, n.reject_reason = "SUSPICIOUS", "security:" + ",".join(n.flags)
    elif trusted:
        n.trust = "TRUSTED"
    else:
        n.trust = "PUBLIC"


def tcp_probe(n: Node, attempts: int = 3, timeout: float = 4.0) -> None:
    """Несколько попыток TCP-connect. НЕ доказывает работу прокси —
    только доступность порта. Адреса из закрытых диапазонов отвергаются."""
    try:
        infos = socket.getaddrinfo(n.host, n.port, type=socket.SOCK_STREAM)
    except OSError:
        n.attempts, n.successes, n.reject_reason = attempts, 0, "dns_fail"
        return
    addrs = [i[4][0] for i in infos]
    if not addrs or not all(is_public_ip(a) for a in addrs):
        n.trust, n.reject_reason = "BLOCKED", "non_public_address"
        return
    target = infos[0][4]
    times = []
    n.attempts = attempts
    for _ in range(attempts):
        t0 = time.perf_counter()
        try:
            with socket.socket(infos[0][0], socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(target)
            times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
    n.successes = len(times)
    if times:
        n.latency_ms = round(statistics.median(times), 1)
        n.jitter_ms = round(statistics.pstdev(times), 1) if len(times) > 1 else 0.0
    else:
        n.reject_reason = "unreachable"


def probe_all(nodes: list[Node], workers: int = 64, **kw) -> None:
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda n: tcp_probe(n, **kw), nodes))
