"""Необязательные уведомления. Без секретов TG_BOT_TOKEN / TG_CHAT_ID ничего не делает.
Базовая бесплатная альтернатива: падение workflow -> письмо от GitHub (см. workflow)."""
from __future__ import annotations

import json
import os
import urllib.request


def evaluate(prev: dict | None, cur: dict, min_alive: int) -> list[dict]:
    ev = []
    if not cur.get("published"):
        ev.append({"level": "critical", "text": "Обновление не опубликовано: рабочих серверов "
                   f"{cur.get('alive', 0)} < {min_alive}. Прежняя подписка сохранена."})
    if prev and prev.get("alive") and cur.get("published"):
        if cur["alive"] < prev["alive"] * 0.5:
            ev.append({"level": "critical", "text":
                       f"Число рабочих серверов упало: {prev['alive']} -> {cur['alive']}"})
    if prev and not prev.get("published") and cur.get("published"):
        ev.append({"level": "info", "text": f"Система восстановилась: рабочих серверов {cur['alive']}"})
    return ev


def send_telegram(text: str) -> bool:
    token, chat = os.environ.get("TG_BOT_TOKEN"), os.environ.get("TG_CHAT_ID")
    if not token or not chat:
        return False
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps({"chat_id": chat, "text": text[:3500]}).encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception:
        return False  # токен в лог не пишем
