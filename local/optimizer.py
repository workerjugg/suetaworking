"""Локальный оптимизатор: измеряет серверы из ВАШЕЙ сети (например, МегаФон в Самаре).

Запускается вручную, когда нужно; компьютер не обязан работать постоянно.
Ничего не отправляет в интернет, кроме загрузки вашей подписки и TCP-соединений
к самим серверам. Телеметрии нет вообще. Настройки Windows не меняет.

  python local/optimizer.py --sub https://USER.github.io/REPO/subscriptions/all
  python local/optimizer.py --sub URL --watch --mode LOW_PING

Результат: local/out/local_ranking.json и local/out/local_best (base64-подписка,
её можно импортировать в клиент как файл/текст). Локальные измерения имеют
приоритет над глобальными: рейтинг строится только по ним.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardian.failover import Candidate, Failover  # noqa: E402
from guardian.generators import uri_text  # noqa: E402,F401
from guardian.parsers import parse_text  # noqa: E402
from guardian.validate import tcp_probe  # noqa: E402
from concurrent.futures import ThreadPoolExecutor  # noqa: E402


def fetch(url: str) -> str:
    if not url.startswith("https://"):
        raise SystemExit("Нужна https-ссылка на подписку")
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read(8_000_000).decode("utf-8", "replace")


def local_score(n) -> float:
    if not n.alive or n.latency_ms is None:
        return 0.0
    loss = 1 - n.successes / n.attempts
    return max(0.0, 100 - n.latency_ms / 8) * 0.45 + max(0.0, 100 - (n.jitter_ms or 0) * 2) * 0.2 \
        + (1 - loss) * 100 * 0.35


def measure(nodes, attempts=5, workers=32):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda n: tcp_probe(n, attempts=attempts, timeout=4.0), nodes))
    for n in nodes:
        n.score = local_score(n)
    return sorted((n for n in nodes if n.score > 0), key=lambda n: -n.score)


def country_of(n) -> str:
    return (n.name.split("|")[0].strip() or "ZZ") if "|" in n.name else "ZZ"


def export(ranked, outdir: Path, top: int):
    outdir.mkdir(parents=True, exist_ok=True)
    rows = [{"country": country_of(n), "protocol": n.protocol, "host": n.host, "port": n.port,
             "tcp_ms": n.latency_ms, "jitter_ms": n.jitter_ms,
             "loss_pct": round(100 * (1 - n.successes / n.attempts), 1),
             "local_score": round(n.score, 1)} for n in ranked]
    (outdir / "local_ranking.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    text = "\n".join(n.raw for n in ranked[:top])
    (outdir / "local_best").write_text(base64.b64encode(text.encode()).decode(), encoding="utf-8")
    (outdir / "local_best.txt").write_text(text, encoding="utf-8")
    return rows


def watch(ranked, mode: str, outdir: Path, interval: int, attempts: int):
    """Следит за текущим сервером, выбирает резервный по правилам failover.
    Только пишет рекомендацию в local/out/current.txt — систему не меняет."""
    fo = Failover(mode=mode)
    pool = ranked[:20]
    print(f"Режим {mode}. Ctrl+C — остановить.")
    while True:
        for n in pool:
            tcp_probe(n, attempts=attempts, timeout=3.0)
            n.score = local_score(n)
        cands = [Candidate(n.fingerprint, n.latency_ms if n.alive else None,
                           n.successes / n.attempts if n.attempts else 0, None,
                           n.trust == "TRUSTED", n.score) for n in pool]
        cur_ok = any(c.id == fo.current and c.latency_ms is not None for c in cands)
        new = fo.step(time.time(), cur_ok, cands)
        if new:
            n = next(x for x in pool if x.fingerprint == new)
            (outdir / "current.txt").write_text(n.raw, encoding="utf-8")
            print(time.strftime("%H:%M:%S"), "рекомендуется:", country_of(n), n.host, n.port)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sub", required=True)
    ap.add_argument("--out", default="local/out")
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--limit", type=int, default=200, help="сколько серверов измерять")
    ap.add_argument("--attempts", type=int, default=5)
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--mode", default="AUTO", choices=["AUTO", "LOW_PING", "STABLE", "PRIVACY", "MANUAL"])
    ap.add_argument("--interval", type=int, default=60)
    a = ap.parse_args()
    nodes = parse_text(fetch(a.sub))[: a.limit]
    print(f"Серверов в подписке: {len(nodes)}. Измеряю из вашей сети...")
    ranked = measure(nodes, a.attempts)
    rows = export(ranked, Path(a.out), a.top)
    print(f"Доступно: {len(ranked)}. Лучшие 5:")
    for r in rows[:5]:
        print(f"  {r['country']:3} {r['host']}:{r['port']}  {r['tcp_ms']} ms  потери {r['loss_pct']}%")
    print(f"Файлы: {a.out}/local_ranking.json, local_best, local_best.txt")
    if a.watch and ranked:
        watch(ranked, a.mode, Path(a.out), a.interval, 3)


if __name__ == "__main__":
    main()
