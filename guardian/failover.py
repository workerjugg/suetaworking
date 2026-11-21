"""Логика автоматического переключения (чистая функция состояния, без сети).

Используется локальным агентом (local/optimizer.py --watch). Сами VPN-клиенты
(sing-box urltest, Happ и др.) делают своё переключение внутри приложения —
этот модуль нужен там, где решение принимаем мы. Бесшовность TCP-соединений
НЕ гарантируется: при смене сервера часть соединений оборвётся.
"""
from __future__ import annotations

from dataclasses import dataclass, field

MODES = ("AUTO", "MANUAL", "LOW_PING", "STABLE", "FAST", "PRIVACY")


@dataclass
class Candidate:
    id: str
    latency_ms: float | None
    stability: float = 1.0
    speed_mbps: float | None = None
    trusted: bool = False
    score: float = 0.0


@dataclass
class Failover:
    mode: str = "AUTO"
    fail_threshold: int = 3          # подряд неудачных проверок = отказ (не скачок задержки)
    hysteresis: float = 0.25         # новый сервер должен быть лучше минимум на 25%
    cooldown_s: float = 300          # пауза после любого переключения
    min_stable_s: float = 120        # сколько текущий должен проработать до возврата на «лучший»
    max_switches_per_hour: int = 6
    current: str | None = None
    fails: int = 0
    last_switch: float = -1e9
    since_ok: float | None = None
    switches: list = field(default_factory=list)

    def _metric(self, c: Candidate) -> float:
        """Больше = лучше."""
        if c.latency_ms is None:
            return 0.0
        if self.mode == "LOW_PING":
            return 1000.0 / max(c.latency_ms, 1)
        if self.mode == "STABLE":
            return c.stability * 100 - c.latency_ms / 100
        if self.mode == "FAST":
            return c.speed_mbps or 0.0
        return c.score or (1000.0 / max(c.latency_ms, 1))

    def _pool(self, cands):
        pool = [c for c in cands if c.latency_ms is not None]
        if self.mode == "PRIVACY":
            pool = [c for c in pool if c.trusted]
        return pool

    def step(self, now: float, current_ok: bool, cands: list[Candidate]) -> str | None:
        """Возвращает id сервера для переключения или None (остаёмся)."""
        if self.mode == "MANUAL":
            return None
        if self.current is None:
            best = max(self._pool(cands), key=self._metric, default=None)
            if best:
                return self._switch(now, best.id)
            return None
        if current_ok:
            self.fails = 0
            self.since_ok = self.since_ok if self.since_ok is not None else now
        else:
            self.fails += 1
            self.since_ok = None
        pool = [c for c in self._pool(cands) if c.id != self.current]
        if not pool:
            return None
        best = max(pool, key=self._metric)
        in_cooldown = now - self.last_switch < self.cooldown_s
        recent = [t for t in self.switches if now - t < 3600]
        if len(recent) >= self.max_switches_per_hour:
            return None
        if self.fails >= self.fail_threshold:
            # полный отказ: уходим сразу, даже в cooldown (но не чаще лимита/час)
            return self._switch(now, best.id)
        if in_cooldown or not current_ok:
            return None
        cur = next((c for c in cands if c.id == self.current), None)
        if self.since_ok is None or now - self.since_ok < self.min_stable_s:
            return None
        cur_m = self._metric(cur) if cur else 0.0
        if self._metric(best) > cur_m * (1 + self.hysteresis):
            return self._switch(now, best.id)
        return None

    def _switch(self, now: float, new_id: str) -> str:
        self.current, self.last_switch, self.fails, self.since_ok = new_id, now, 0, None
        self.switches = [t for t in self.switches if now - t < 3600] + [now]
        return new_id
