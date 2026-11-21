"""Генераторы форматов.

Подтверждено официальной документацией (прочитано при разработке):
  * Happ: стандартная подписка = URL на текстовый список; протоколы VLESS, VMess,
    Shadowsocks, Socks5, Trojan, Hysteria2 (happ.su/main/dev-docs).
  * Incy: тело подписки — base64 или обычный текст, по ссылке на строку; метаданные
    в теле через `#profile-title`, `#profile-update-interval: <часы>` и т.п.
    (incy.gitbook.io/docs/docs-en/subscription-format).
Остальные клиенты получают base64-список URI — общепринятый формат; это
знание о формате, а НЕ результат теста в приложениях (см. clients.COMPAT).
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote

from .models import Node
from .parsers import b64decode_loose

TRUST_TAG = {"TRUSTED": "TRUSTED", "VERIFIED": "VERIFIED", "PUBLIC": "PUBLIC"}


def label(n: Node) -> str:
    lat = n.best_latency
    parts = [n.country or "ZZ", TRUST_TAG.get(n.trust, n.trust),
             f"{int(lat)}ms" if lat is not None else "?ms"]
    if n.speed_mbps:
        parts.append(f"{n.speed_mbps:g}Mbps")
    return " | ".join(parts)


def labeled_uri(n: Node) -> str:
    """Тот же URI, но с понятным именем: страна | уровень доверия | задержка."""
    lb = label(n)
    if n.protocol == "vmess":
        try:
            d = json.loads(b64decode_loose(n.raw[len("vmess://"):]))
            d["ps"] = lb
            return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()
        except Exception:
            return n.raw
    base = n.raw.split("#", 1)[0]
    return f"{base}#{quote(lb)}"


def uri_text(nodes: list[Node]) -> str:
    return "\n".join(labeled_uri(n) for n in nodes)


def uri_subscription(nodes: list[Node]) -> str:
    return base64.b64encode(uri_text(nodes).encode()).decode()


def happ_subscription(nodes: list[Node]) -> str:
    """Happ: обычный текстовый список URI (формат из документации Happ)."""
    return uri_text(nodes) + "\n"


def incy_subscription(nodes: list[Node], title: str = "FreeVPN Guardian",
                      interval_h: int = 6) -> str:
    """Incy: текст со ссылками + метаданные в теле (по документации Incy)."""
    head = [
        f"#profile-title: {title[:25]}",
        f"#profile-update-interval: {interval_h}",
        "#announce: Публичные узлы неизвестных владельцев. Не для банков и почты.",
    ]
    return "\n".join(head) + "\n" + uri_text(nodes) + "\n"


def _tls_block(p: dict) -> dict | None:
    sec = p.get("security", "none")
    if sec == "none":
        return None
    tls = {"enabled": True, "server_name": p.get("sni", ""),
           "utls": {"enabled": True, "fingerprint": p.get("fp") or "chrome"}}
    if sec == "reality":
        tls["reality"] = {"enabled": True, "public_key": p.get("pbk", ""),
                          "short_id": p.get("sid", "")}
    return tls


def _transport(net: str, p: dict) -> tuple[bool, dict | None]:
    """(поддерживается, блок transport)."""
    if net in ("", "tcp"):
        return True, None
    if net == "ws":
        t = {"type": "ws", "path": p.get("path", "/")}
        if p.get("host"):
            t["headers"] = {"Host": p["host"]}
        return True, t
    if net == "grpc":
        return True, {"type": "grpc", "service_name": p.get("serviceName", p.get("path", ""))}
    return False, None


def singbox_outbound(n: Node) -> dict | None:
    p = n.params
    tag = f"{n.protocol}-{n.fingerprint}"
    base = {"tag": tag, "server": n.host, "server_port": n.port}
    if n.protocol == "vless":
        o = {"type": "vless", "uuid": n.identity, **base}
        if p.get("flow"):
            o["flow"] = p["flow"]
        tls = _tls_block(p)
        if tls:
            o["tls"] = tls
        ok, tr = _transport(p.get("type", "tcp"), p)
        if not ok:
            return None
        if tr:
            o["transport"] = tr
        return o
    if n.protocol == "vmess":
        o = {"type": "vmess", "uuid": n.identity, "security": p.get("scy") or "auto",
             "alter_id": int(p.get("aid") or 0), **base}
        if p.get("tls") == "tls":
            o["tls"] = {"enabled": True, "server_name": p.get("sni") or p.get("host") or n.host,
                        "utls": {"enabled": True, "fingerprint": "chrome"}}
        ok, tr = _transport(p.get("net", "tcp"), p)
        if not ok:
            return None
        if tr:
            o["transport"] = tr
        return o
    if n.protocol == "trojan":
        o = {"type": "trojan", "password": n.identity, **base}
        tls = _tls_block({"security": p.get("security", "tls"), "sni": p.get("sni", n.host),
                          "fp": p.get("fp", "")})
        if tls:
            o["tls"] = tls
        ok, tr = _transport(p.get("type", "tcp"), p)
        if not ok:
            return None
        if tr:
            o["transport"] = tr
        return o
    if n.protocol == "ss" and not p.get("plugin"):
        return {"type": "shadowsocks", "method": p["method"], "password": n.identity, **base}
    return None


def singbox_config(nodes: list[Node]) -> str:
    outs = [o for o in (singbox_outbound(n) for n in nodes) if o]
    tags = [o["tag"] for o in outs]
    cfg = {"outbounds": outs + [
        {"type": "urltest", "tag": "auto", "outbounds": tags,
         "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + tags, "default": "auto"},
    ]} if tags else {"outbounds": []}
    return json.dumps(cfg, ensure_ascii=False, indent=1)
