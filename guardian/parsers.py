"""Безопасный парсинг URI. Вход считается недоверенным: никакого eval/exec."""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .models import Node

MAX_LINE = 4096


def b64decode_loose(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8")


def _query(u) -> dict:
    return {k: v[0] for k, v in parse_qs(u.query).items()}


def _parse_vless_trojan(line: str, proto: str) -> Node:
    u = urlsplit(line)
    return Node(
        protocol=proto,
        host=u.hostname or "",
        port=u.port or 0,
        identity=unquote(u.username or ""),
        raw=line,
        name=unquote(u.fragment),
        params=_query(u),
    )


def _parse_vmess(line: str) -> Node:
    data = json.loads(b64decode_loose(line[len("vmess://"):]))
    if not isinstance(data, dict):
        raise ValueError("vmess payload is not an object")
    return Node(
        protocol="vmess",
        host=str(data.get("add", "")),
        port=int(data.get("port", 0)),
        identity=str(data.get("id", "")),
        raw=line,
        name=str(data.get("ps", "")),
        params={k: str(v) for k, v in data.items() if k in
                ("net", "tls", "sni", "path", "host", "aid", "scy", "type")},
    )


def _parse_ss(line: str) -> Node:
    body = line[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    params = {}
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = b64decode_loose(userinfo)
    else:
        decoded = b64decode_loose(body.split("?", 1)[0])
        userinfo, hostport = decoded.rsplit("@", 1)
    if "?" in hostport:
        hostport, q = hostport.split("?", 1)
        params = {k: v[0] for k, v in parse_qs(q).items()}
    method, password = userinfo.split(":", 1)
    u = urlsplit("//" + hostport.strip("/"))
    params["method"] = method
    return Node(protocol="ss", host=u.hostname or "", port=u.port or 0,
                identity=password, raw=line, name=name, params=params)


def parse_line(line: str) -> Node | None:
    line = line.strip()
    if not line or len(line) > MAX_LINE or "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    try:
        if scheme in ("vless", "trojan"):
            return _parse_vless_trojan(line, scheme)
        if scheme == "vmess":
            return _parse_vmess(line)
        if scheme == "ss":
            return _parse_ss(line)
    except Exception:
        return None
    return None


def parse_text(text: str, max_nodes: int = 20000) -> list[Node]:
    """Принимает список URI построчно или целиком в base64."""
    return _parse(text, max_nodes, depth=0)


_B64_LINE = re.compile(r"^[A-Za-z0-9+/_\-=\s]{24,}$")


def _parse(text: str, max_nodes: int, depth: int) -> list[Node]:
    if "://" not in text[:200]:
        try:
            text = b64decode_loose("".join(text.split()))
        except Exception:
            return []
    nodes: list[Node] = []
    for line in text.splitlines():
        n = parse_line(line)
        if n:
            nodes.append(n)
        elif depth == 0 and "://" not in line and _B64_LINE.match(line.strip()):
            # смешанные источники: отдельные строки могут быть вложенным base64
            try:
                nodes.extend(_parse(line, max_nodes, depth=1))
            except Exception:
                pass
        if len(nodes) >= max_nodes:
            break
    return nodes[:max_nodes]
