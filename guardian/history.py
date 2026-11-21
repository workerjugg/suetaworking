"""Ограниченная история серверов между запусками (JSON, хранится в кеше Actions)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

KEEP = 20


def load(path: Path) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save(path: Path, hist: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(hist, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def apply_to_nodes(hist: dict, nodes) -> None:
    for n in nodes:
        h = hist.get(n.fingerprint)
        if h:
            runs = h.get("runs", [])[-KEEP:]
            n.hist_ok, n.hist_total = sum(runs), len(runs)


def update(hist: dict, nodes, now: datetime | None = None, ttl_days: int = 3) -> dict:
    """Записывает результат текущей проверки; удаляет записи старше TTL."""
    now = now or datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    for n in nodes:
        checked = n.attempts > 0
        if not checked:
            continue
        ok = n.tunnel_ok if n.tunnel_ok is not None else n.alive
        h = hist.setdefault(n.fingerprint, {"first_seen": stamp, "runs": [], "last_ok": None})
        h["last_seen"] = stamp
        h["runs"] = (h.get("runs", []) + [1 if ok else 0])[-KEEP:]
        if ok:
            h["last_ok"] = stamp
        lat = n.best_latency
        if lat is not None:
            h["lat"] = (h.get("lat", []) + [lat])[-KEEP:]
    cutoff = now - timedelta(days=ttl_days)
    for fp in list(hist):
        ref = hist[fp].get("last_ok") or hist[fp].get("first_seen")
        try:
            if datetime.fromisoformat(ref) < cutoff:
                del hist[fp]
        except Exception:
            del hist[fp]
    return hist
