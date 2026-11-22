"""Дедупликация, рейтинг, профили."""
from __future__ import annotations

from collections import Counter

from .models import Node

PROTO_PRIORITY = {"vless": 1.0, "trojan": 0.9, "ss": 0.8, "vmess": 0.7}
GOOD_TRUST = ("TRUSTED", "VERIFIED", "PUBLIC")


def deduplicate(nodes: list[Node]) -> list[Node]:
    seen: dict[str, Node] = {}
    for n in nodes:
        fp = n.fingerprint
        if fp in seen:
            seen[fp].sources |= n.sources
            seen[fp].tags |= n.tags
        else:
            seen[fp] = n
    return list(seen.values())


def is_usable(n: Node, require_tunnel: bool = False) -> bool:
    if not n.alive or n.trust not in GOOD_TRUST:
        return False
    if n.tunnel_ok is False:
        return False
    if require_tunnel and n.tunnel_ok is not True:
        return False
    return True


def score(n: Node) -> float:
    lat_ms = n.best_latency
    if not n.alive or lat_ms is None:
        return 0.0
    lat = max(0.0, 100 - lat_ms / 8)                 # 0 мс -> 100, 800 мс -> 0
    jit = max(0.0, 100 - (n.jitter_ms or 0) * 2)
    stab = n.stability * 100
    proto = PROTO_PRIORITY.get(n.protocol, 0.5) * 100
    multi = min(len(n.sources), 3) / 3 * 100
    speed = min((n.speed_mbps or 0) / 50, 1.0) * 100
    s = 0.30 * lat + 0.15 * jit + 0.25 * stab + 0.10 * proto + 0.10 * multi + 0.10 * speed
    if n.trust == "PUBLIC":
        s *= 0.97
    s *= 0.85 + 0.15 * max(0.0, min(1.0, n.source_quality))
    return s


def cap_by(nodes: list[Node], key, share: float, min_cap: int) -> list[Node]:
    cap = max(min_cap, int(len(nodes) * share))
    used: Counter = Counter()
    out = []
    for n in nodes:
        k = key(n)
        if used[k] < cap:
            used[k] += 1
            out.append(n)
    return out


def cap_per_source(nodes: list[Node], share: float = 0.4, min_cap: int = 10) -> list[Node]:
    """Не даём одному источнику занять почти всю подписку."""
    return cap_by(nodes, lambda n: sorted(n.sources)[0] if n.sources else "", share, min_cap)


def build_profiles(nodes: list[Node], limit: int = 100,
                   require_tunnel: bool = False, all_limit: int = 1500) -> dict[str, list[Node]]:
    usable = [n for n in nodes if is_usable(n, require_tunnel)]
    for n in usable:
        n.score = score(n)
    by_score = sorted(usable, key=lambda n: -n.score)
    foreign = [n for n in by_score if n.region != "russia"]   # РФ не вытесняет зарубежные
    best_all = cap_by(cap_per_source(foreign), lambda n: n.country or "ZZ", 0.25, 5)
    best = best_all[:limit]
    best_ids = {n.fingerprint for n in best}
    # Профиль для обхода «белых списков». С раннера GitHub проверить обход нельзя (он не в
    # мобильной сети РФ), поэтому здесь достаточно живого TCP; результат туннельного теста
    # с раннера не отсекает такие узлы (они могут принимать подключения только из РФ).
    wl = [n for n in nodes if "whitelist" in n.tags and n.alive and n.trust in GOOD_TRUST]
    for n in wl:
        n.score = score(n)
    wl.sort(key=lambda n: (n.tunnel_ok is not True, n.best_latency or 1e9))
    stable = [n for n in by_score if n.stability >= 0.9
              and (n.hist_total >= 3 or n.tunnel_attempts or n.attempts)]
    by_ping = sorted(usable, key=lambda n: n.best_latency or 1e9)
    verified_ids = {n.fingerprint for n in by_ping}
    all_list = (by_ping + [n for n in wl if n.fingerprint not in verified_ids])[:all_limit]
    return {
        "all": all_list,
        "verified": by_score,
        "best": best,
        "low-ping": sorted(usable, key=lambda n: n.best_latency or 1e9)[:limit],
        "stable": stable[:limit],
        "fast": sorted((n for n in usable if n.speed_mbps),
                       key=lambda n: -(n.speed_mbps or 0))[:limit],
        "privacy": [n for n in by_score if n.trust == "TRUSTED"][:limit],
        "europe": [n for n in by_score if n.region == "europe"][:limit],
        "asia": [n for n in by_score if n.region == "asia"][:limit],
        "america": [n for n in by_score if n.region == "america"][:limit],
        "russia": [n for n in by_score if n.region == "russia"][:30],
        "backup": [n for n in foreign if n.fingerprint not in best_ids][:limit],
        "whitelist": wl[:limit * 3],
        "vless": [n for n in by_score if n.protocol == "vless"],
        "vmess": [n for n in by_score if n.protocol == "vmess"],
        "trojan": [n for n in by_score if n.protocol == "trojan"],
        "shadowsocks": [n for n in by_score if n.protocol == "ss"],
    }
