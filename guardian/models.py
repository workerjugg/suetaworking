from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class Node:
    protocol: str            # vless | vmess | trojan | ss
    host: str
    port: int
    identity: str            # uuid / password
    raw: str                 # исходный URI (недоверенные данные)
    name: str = ""
    params: dict = field(default_factory=dict)
    sources: set = field(default_factory=set)
    tags: set = field(default_factory=set)       # например {"whitelist"} из конфигурации источника
    trust: str = "PUBLIC"    # TRUSTED | VERIFIED | PUBLIC | SUSPICIOUS | BLOCKED
    errors: list = field(default_factory=list)   # синтаксические ошибки
    flags: list = field(default_factory=list)    # замечания безопасности
    # уровень 2: TCP
    attempts: int = 0
    successes: int = 0
    latency_ms: float | None = None
    jitter_ms: float | None = None
    # уровень 3-4: реальный туннель через sing-box (None = не проверялось)
    tunnel_ok: bool | None = None
    tunnel_attempts: int = 0
    tunnel_successes: int = 0
    tunnel_ms: float | None = None
    speed_mbps: float | None = None      # измерено С РАННЕРА, не из вашей сети
    exit_ip: str = ""
    country: str = ""
    region: str = ""
    # история между запусками
    hist_ok: int = 0
    hist_total: int = 0
    source_quality: float = 1.0
    score: float = 0.0
    reject_reason: str = ""

    @property
    def fingerprint(self) -> str:
        key = f"{self.protocol}|{self.host.lower()}|{self.port}|{self.identity}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def alive(self) -> bool:
        return self.attempts > 0 and self.successes >= 2

    @property
    def stability(self) -> float:
        cur = self.successes / self.attempts if self.attempts else 0.0
        if self.tunnel_attempts:
            cur = self.tunnel_successes / self.tunnel_attempts
        if self.hist_total >= 3:
            return 0.5 * cur + 0.5 * (self.hist_ok / self.hist_total)
        return cur

    @property
    def best_latency(self) -> float | None:
        return self.tunnel_ms if self.tunnel_ms is not None else self.latency_ms

    def public_dict(self) -> dict:
        """Без секретов (uuid/пароль/ключи) — для публичного JSON и dashboard."""
        return {
            "id": self.fingerprint,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "country": self.country or "ZZ",
            "region": self.region or "other",
            "trust": self.trust,
            "latency_ms": self.best_latency,
            "tcp_ms": self.latency_ms,
            "jitter_ms": self.jitter_ms,
            "speed_mbps": self.speed_mbps,
            "tunnel_checked": self.tunnel_ok is not None,
            "stability": round(self.stability, 2),
            "score": round(self.score, 1),
            "sources": len(self.sources),
            "flags": self.flags,
        }
