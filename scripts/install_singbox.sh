#!/usr/bin/env bash
# Устанавливает sing-box из официального релиза SagerNet на раннере Actions.
set -euo pipefail
api=$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN:-}" \
  https://api.github.com/repos/SagerNet/sing-box/releases/latest)
url=$(printf '%s' "$api" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for a in d['assets']:
    n=a['name']
    if n.endswith('linux-amd64.tar.gz') and 'legacy' not in n and 'glibc' not in n and 'musl' not in n:
        print(a['browser_download_url']); break
")
[ -n "$url" ] || { echo "sing-box asset not found"; exit 1; }
mkdir -p "$RUNNER_TEMP/sb" && curl -fsSL "$url" | tar -xz -C "$RUNNER_TEMP/sb" --strip-components=1
echo "SINGBOX_BIN=$RUNNER_TEMP/sb/sing-box" >> "$GITHUB_ENV"
"$RUNNER_TEMP/sb/sing-box" version | head -1
