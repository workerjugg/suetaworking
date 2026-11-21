"""Таблица совместимости. Статусы честные: «docs» = подтверждено официальной
документацией клиента, «third-party» = утверждение стороннего проекта,
«not-tested» = формат стандартный, но в приложении не проверялся.
Ни одно приложение автоматически здесь не тестировалось."""

OK, PART, NO, UNK = "полностью", "частично", "не поддерживается", "не проверено"

COMPAT = {
    "happ": {
        "format": "текстовый список URI (plain)", "protocols": "vless vmess trojan ss socks5 hy2",
        "evidence": "docs (happ.su dev-docs): протоколы и standard-подписка",
        "reality": UNK, "wireguard": UNK, "auto_update": UNK, "status": "формат по документации; в приложении не тестировалось",
    },
    "incy": {
        "format": "plain/base64 + метаданные в теле (#profile-title, #profile-update-interval)",
        "protocols": "vless vmess trojan ss hy2 socks wireguard amneziawg http",
        "evidence": "docs (incy.gitbook.io subscription-format); REALITY в документации не упомянут",
        "reality": UNK, "wireguard": "поддерживает (мы не генерируем)", "auto_update": "по profile-update-interval (docs)",
        "status": "формат по документации; в приложении не тестировалось",
    },
    "singbox": {
        "format": "JSON outbounds (urltest + selector)", "protocols": "vless vmess trojan ss",
        "evidence": "собственный генератор + реальный запуск sing-box в Actions (tunnel.py), но только как outbound",
        "reality": "генерируется", "wireguard": "не генерируется", "auto_update": UNK,
        "status": "outbound'ы проверены реальным запуском sing-box; импорт в мобильное приложение не проверялся",
    },
}
BASE64_CLIENTS = ["v2rayn", "v2rayng", "nekobox", "shadowrocket", "hiddify", "v2box", "foxray", "streisand"]
for c in BASE64_CLIENTS:
    COMPAT[c] = {
        "format": "base64-список URI", "protocols": "vless vmess trojan ss",
        "evidence": ("third-party: проект nodesradar заявляет v2ray.txt для v2rayN, v2rayNG, "
                     "Shadowrocket, NekoBox, Hiddify; для остальных — общий стандарт, не проверено"),
        "reality": UNK, "wireguard": "не генерируется", "auto_update": UNK,
        "status": "не проверено в приложении",
    }
