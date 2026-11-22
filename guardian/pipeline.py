"""Оркестрация: сбор -> разбор -> дедуп -> проверки (TCP, туннель) -> геолокация ->
история -> рейтинг -> профили -> атомарная публикация -> уведомления."""
from __future__ import annotations

import json
import random
import shutil
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import clients, engine, generators, geo, history, notify, tunnel, validate
from .models import Node
from .parsers import parse_text

MAX_BYTES = 8 * 1024 * 1024


def fetch_url(url: str, timeout: int = 30) -> str:
    """Скачивает https-источник. Слишком большой файл не отбрасывается целиком:
    берётся первые MAX_BYTES без оборванной последней строки."""
    if not url.startswith("https://"):
        raise ValueError("only https sources are allowed")
    def _open(ua):
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(MAX_BYTES + 1)
    try:
        data = _open("FreeVPN-Guardian/0.2")
    except urllib.error.HTTPError as e:
        if e.code not in (403, 429):
            raise
        data = _open("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36")
    if len(data) > MAX_BYTES:
        data = data[:MAX_BYTES].rsplit(b"\n", 1)[0]
    return data.decode("utf-8", errors="replace")


def collect(sources: list[dict], delay: float = 1.0, retries: int = 2) -> tuple[list[Node], dict]:
    nodes, health = [], {}
    for s in sources:
        if not s.get("enabled", True):
            continue
        name = s["name"]
        t0, err = time.time(), None
        for attempt in range(retries if s["type"] == "url" else 1):
            try:
                text = fetch_url(s["location"]) if s["type"] == "url" else \
                    Path(s["location"]).read_text(encoding="utf-8", errors="replace")
                found = parse_text(text)
                for n in found:
                    n.sources.add(name)
                    n.tags |= set(s.get("tags", []))
                    n.params["_trusted_src"] = "1" if s.get("trusted") else ""
                nodes += found
                health[name] = {"ok": True, "parsed": len(found),
                                "fetch_s": round(time.time() - t0, 1)}
                err = None
                break
            except Exception as e:  # источник упал — остальные продолжают работать
                err = type(e).__name__ + (f" {e.code}" if isinstance(e, urllib.error.HTTPError) else "")
                time.sleep(2)
        if err:
            health[name] = {"ok": False, "error": err, "parsed": 0}
        if s["type"] == "url":
            time.sleep(delay)
    return nodes, health


def publish(out_dir: Path, files: dict[str, str], min_files_alive: int, alive: int) -> bool:
    """Атомарная замена. Пустой/провальный результат прежнюю подписку не затирает."""
    if alive < min_files_alive:
        return False
    new, prev = out_dir.with_name(out_dir.name + ".new"), out_dir.with_name(out_dir.name + ".prev")
    shutil.rmtree(new, ignore_errors=True)
    new.mkdir(parents=True)
    for name, content in files.items():
        (new / name).write_text(content, encoding="utf-8")
    # проверка целостности перед заменой
    for name, content in files.items():
        if (new / name).read_text(encoding="utf-8") != content:
            shutil.rmtree(new, ignore_errors=True)
            return False
    shutil.rmtree(prev, ignore_errors=True)
    if out_dir.exists():
        out_dir.rename(prev)
    new.rename(out_dir)
    return True


def source_report(nodes: list[Node], health: dict) -> dict:
    """Качество источников: доля рабочих, дубликаты, доля подозрительных."""
    rep = {}
    for name, h in health.items():
        mine = [n for n in nodes if name in n.sources]
        alive = sum(1 for n in mine if engine.is_usable(n))
        susp = sum(1 for n in mine if n.trust in ("SUSPICIOUS", "BLOCKED"))
        parsed = h.get("parsed", 0)
        rep[name] = {**h, "unique": len(mine), "duplicates": max(0, parsed - len(mine)),
                     "alive": alive, "suspicious_share": round(susp / len(mine), 2) if mine else 0,
                     "alive_ratio": round(alive / len(mine), 3) if mine else 0.0}
    return rep


def run(config: dict, out_dir: Path, probe: bool = True, data_dir: Path | None = None,
        use_tunnel: bool = True, use_geo: bool = True, geo_fetch=None) -> dict:
    limits = config.get("limits", {})
    data_dir = data_dir or out_dir.parent / "data"
    now = datetime.now(timezone.utc)

    raw_nodes, health = collect(config.get("sources", []), limits.get("source_delay", 1.0))
    raw_nodes = raw_nodes[: limits.get("max_nodes", 20000)]
    for n in raw_nodes:
        trusted = bool(n.params.pop("_trusted_src", ""))
        validate.apply_static_checks(n, trusted)
    nodes = engine.deduplicate(raw_nodes)
    candidates = [n for n in nodes if n.trust in ("TRUSTED", "PUBLIC")]
    # Лимит проверок за запуск (чтобы уложиться во время Actions). Сначала узлы для белых
    # списков и найденные в нескольких источниках, остальные — случайная выборка.
    max_probe = limits.get("max_probe", 4000)
    if len(candidates) > max_probe:
        random.shuffle(candidates)
        candidates.sort(key=lambda n: (-("whitelist" in n.tags), -len(n.sources)))
        skipped = len(candidates) - max_probe
        for n in candidates[max_probe:]:
            n.reject_reason = "not_probed_limit"
        candidates = candidates[:max_probe]
    else:
        skipped = 0

    hist_path = data_dir / "history.json"
    hist = history.load(hist_path)
    tunnel_info = {"ran": False, "reason": "disabled"}
    require_tunnel = False
    if probe:
        validate.probe_all(candidates, workers=limits.get("workers", 128), attempts=3, timeout=3.0)
        binary = tunnel.find_singbox() if use_tunnel else None
        if binary:
            tc = config.get("tunnel", {})
            tunnel_info = tunnel.run_tunnel_tests(
                candidates, binary, budget=tc.get("budget", 300), workers=tc.get("workers", 8),
                speed_top=tc.get("speed_top", 30), max_seconds=tc.get("max_seconds", 1500))
            require_tunnel = bool(tunnel_info.get("ran"))
        elif use_tunnel:
            tunnel_info = {"ran": False, "reason": "sing-box not found"}
    for n in candidates:
        if n.tunnel_ok and n.trust == "PUBLIC":
            n.trust = "VERIFIED"      # технически подтверждён, но НЕ «доверенный»

    history.apply_to_nodes(hist, candidates)
    rep = source_report(nodes, health)
    for n in candidates:
        qs = [min(1.0, rep[s]["alive_ratio"] / 0.2) for s in n.sources if s in rep]
        n.source_quality = max(qs) if qs else 1.0
    usable_now = [n for n in candidates if engine.is_usable(n, require_tunnel)
                  or ("whitelist" in n.tags and n.alive)]
    if use_geo and probe:
        geo.annotate(usable_now[: limits.get("geo_max", 1500)], fetch=geo_fetch)
    history.update(hist, candidates, now, ttl_days=limits.get("ttl_days", 3))

    profiles = engine.build_profiles(candidates, limits.get("profile_size", 100), require_tunnel,
                                     all_limit=limits.get("all_limit", 300),
                                     strict=require_tunnel, min_speed=limits.get("min_speed_mbps", 1.0))
    alive = len(profiles["verified"])          # «рабочие» = прошли проверку; от этого зависит публикация
    alive_ids = {n.fingerprint for n in profiles["all"]}
    lats = [n.best_latency for n in profiles["all"] if n.best_latency is not None]

    stats = {
        "updated": now.isoformat(timespec="seconds"),
        "found_raw": len(raw_nodes), "unique": len(nodes), "alive": alive,
        "excluded_total": len(nodes) - alive,
        "not_probed": skipped,
        "excluded": dict(Counter((n.reject_reason.split(":")[0] or "dead")
                                 for n in nodes if n.fingerprint not in alive_ids)),
        "protocols": dict(Counter(n.protocol for n in profiles["all"])),
        "countries": dict(Counter(n.country or "ZZ" for n in profiles["all"])),
        "regions": dict(Counter(n.region or "other" for n in profiles["all"])),
        "trust": dict(Counter(n.trust for n in profiles["all"])),
        "avg_latency_ms": round(sum(lats) / len(lats), 1) if lats else None,
        "profiles": {k: len(v) for k, v in profiles.items()},
        "sources": rep,
        "tunnel": tunnel_info,
        "check_level": ("tunnel_via_singbox_from_runner" if require_tunnel
                        else "tcp_connect_from_runner (не проверка туннеля)"),
        "warning": "Публичные узлы неизвестных владельцев: возможен перехват трафика. "
                   "Не используйте для банков и почты.",
    }

    best = profiles["best"]
    files = {name: generators.uri_subscription(lst) for name, lst in profiles.items()}
    for c in clients.BASE64_CLIENTS:
        files[c] = files["best"]
    # ЕДИНАЯ ссылка для Happ: обычный текстовый список (формат из документации Happ).
    files["all"] = generators.happ_subscription(profiles["all"])
    files["all-b64"] = generators.uri_subscription(profiles["all"])
    files["happ"] = generators.happ_subscription(best)
    files["incy"] = generators.incy_subscription(best, interval_h=limits.get("client_update_hours", 6))
    files["singbox"] = generators.singbox_config(best)
    files["compat.json"] = json.dumps(clients.COMPAT, ensure_ascii=False, indent=1)
    files["servers.json"] = json.dumps([n.public_dict() for n in profiles["all"]],
                                       ensure_ascii=False)

    prev_stats = None
    try:
        prev_stats = json.loads((data_dir / "last_run.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    log_path = data_dir / "changelog.json"
    try:
        log = json.loads(log_path.read_text(encoding="utf-8"))
    except Exception:
        log = []
    log = (log + [{"t": stats["updated"], "unique": len(nodes), "alive": alive}])[-100:]
    files["changelog.json"] = json.dumps(log)
    files["stats.json"] = json.dumps(stats, ensure_ascii=False, indent=1)

    stats["published"] = publish(out_dir, files, limits.get("min_alive", 1), alive)
    events = notify.evaluate(prev_stats, stats, limits.get("min_alive", 1))
    stats["events"] = events
    stats["critical"] = any(e["level"] == "critical" for e in events)
    for e in events:
        notify.send_telegram(("🚨 " if e["level"] == "critical" else "ℹ️ ") + e["text"])

    data_dir.mkdir(parents=True, exist_ok=True)
    history.save(hist_path, hist)
    if stats["published"]:
        log_path.write_text(json.dumps(log), encoding="utf-8")
    (data_dir / "last_run.json").write_text(json.dumps(
        {k: stats[k] for k in ("updated", "alive", "unique", "published", "critical", "events")},
        ensure_ascii=False), encoding="utf-8")
    return stats
