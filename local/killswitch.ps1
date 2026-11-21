<#
Firewall Kill Switch для Windows (ОПЦИОНАЛЬНО, только по вашему явному согласию).
Блокирует ВЕСЬ исходящий трафик, кроме: loopback, локальной сети, IP ваших VPN-серверов.
Если VPN упал — интернет не «утекает» мимо туннеля.

Применить:  .\killswitch.ps1 -Apply  -ServerIPs 203.0.113.10,203.0.113.11   (от администратора)
Снять:      .\killswitch.ps1 -Remove
Прежнее состояние сохраняется в %ProgramData%\fvg-killswitch.json.
ВНИМАНИЕ: при смене сервера на новый IP добавьте его в список, иначе клиент не подключится.
Снять блокировку можно всегда командой -Remove (или в «Брандмауэр Защитника Windows»).
#>
param([switch]$Apply, [switch]$Remove, [string[]]$ServerIPs = @())
$ErrorActionPreference = 'Stop'
$state = Join-Path $env:ProgramData 'fvg-killswitch.json'
$prefix = 'FVG-KillSwitch'

if ($Remove) {
  Get-NetFirewallRule -DisplayName "$prefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  $act = 'Allow'
  if (Test-Path $state) { $act = (Get-Content $state | ConvertFrom-Json).DefaultOutboundAction }
  Set-NetFirewallProfile -All -DefaultOutboundAction $act
  Write-Host "Kill Switch снят."; return
}
if (-not $Apply) { Write-Host "Укажите -Apply или -Remove. Прочитайте комментарий в начале файла."; return }
if ($ServerIPs.Count -eq 0) { throw "Нужен -ServerIPs (IP ваших VPN-серверов)." }

Write-Host "Будет заблокирован весь исходящий трафик, кроме loopback, LAN и: $($ServerIPs -join ', ')"
if ((Read-Host "Продолжить? (yes/no)") -ne 'yes') { return }

$cur = (Get-NetFirewallProfile -Profile Public).DefaultOutboundAction.ToString()
@{ DefaultOutboundAction = $cur } | ConvertTo-Json | Set-Content $state
New-NetFirewallRule -DisplayName "$prefix-Servers" -Direction Outbound -Action Allow -RemoteAddress $ServerIPs | Out-Null
New-NetFirewallRule -DisplayName "$prefix-LAN" -Direction Outbound -Action Allow `
  -RemoteAddress 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,127.0.0.0/8,224.0.0.0/4 | Out-Null
Set-NetFirewallProfile -All -DefaultOutboundAction Block
Write-Host "Kill Switch включён. Снять: .\killswitch.ps1 -Remove"
Write-Host "Если VPN-клиент использует туннельный адаптер, трафик внутри туннеля идёт через разрешённый IP сервера."
