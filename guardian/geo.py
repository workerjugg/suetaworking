"""Геолокация по IP выхода (если есть туннельный тест) либо по IP сервера.

Используется бесплатный ip-api.com (batch, без ключа, только http, лимит
15 batch-запросов в минуту). Если сервис недоступен — страна остаётся пустой
(ZZ), а не угадывается по названию сервера.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.request

from .models import Node
from .regions import region_of

API = "http://ip-api.com/batch?fields=status,countryCode,query"


def _resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def lookup(ips: list[str], pause: float = 4.5, fetch=None) -> dict[str, str]:
    """ip -> country code. `fetch` подменяется в тестах."""
    fetch = fetch or _fetch_batch
    out: dict[str, str] = {}
    uniq = sorted(set(i for i in ips if i))
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        try:
            for row in fetch(chunk):
                if row.get("status") == "success":
                    out[row["query"]] = row.get("countryCode", "")
        except Exception:
            pass
        if i + 100 < len(uniq):
            time.sleep(pause)
    return out


def _fetch_batch(chunk: list[str]) -> list[dict]:
    req = urllib.request.Request(API, data=json.dumps(chunk).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read(2_000_000))


def annotate(nodes: list[Node], fetch=None, pause: float = 4.5) -> None:
    ip_of = {}
    for n in nodes:
        ip_of[n.fingerprint] = n.exit_ip or _resolve(n.host)
    mapping = lookup(list(ip_of.values()), pause=pause, fetch=fetch)
    for n in nodes:
        cc = mapping.get(ip_of[n.fingerprint], "")
        n.country, n.region = cc, region_of(cc) if cc else ""
