# Скачивает официальный sing-box для Windows в local\bin (один раз).
$ErrorActionPreference = "Stop"
$dir = Join-Path $PSScriptRoot "bin"
New-Item -ItemType Directory -Force $dir | Out-Null
if (Get-ChildItem $dir -Recurse -Filter sing-box.exe -ErrorAction SilentlyContinue) { Write-Host "sing-box уже есть"; return }
$rel = Invoke-RestMethod "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
$asset = $rel.assets | Where-Object { $_.name -like "*windows-amd64.zip" -and $_.name -notlike "*legacy*" } | Select-Object -First 1
if (-not $asset) { throw "Не нашёл windows-amd64 в релизе sing-box" }
$zip = Join-Path $dir "sb.zip"
Invoke-WebRequest $asset.browser_download_url -OutFile $zip
Expand-Archive $zip -DestinationPath $dir -Force
Remove-Item $zip
Write-Host "Готово: $((Get-ChildItem $dir -Recurse -Filter sing-box.exe | Select-Object -First 1).FullName)"
