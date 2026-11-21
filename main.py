"""Запуск: python main.py [--config config/sources.json] [--out subscriptions]
[--data-dir data] [--no-probe] [--no-tunnel] [--no-geo]"""
import argparse
import json
from pathlib import Path

from guardian.pipeline import run


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/sources.json")
    ap.add_argument("--out", default="subscriptions")
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--no-tunnel", action="store_true")
    ap.add_argument("--no-geo", action="store_true")
    a = ap.parse_args()
    cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
    stats = run(cfg, Path(a.out), probe=not a.no_probe, data_dir=Path(a.data_dir),
                use_tunnel=not a.no_tunnel, use_geo=not a.no_geo)
    print(json.dumps({k: stats[k] for k in ("found_raw", "unique", "alive", "published")}))
    for e in stats.get("events", []):
        print(e["level"].upper(), e["text"])
    return 0  # недоступные источники не должны валить workflow; critical проверяет отдельный шаг


if __name__ == "__main__":
    raise SystemExit(main())
