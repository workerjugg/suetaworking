@echo off
chcp 65001 >nul
rem 1) Подключитесь к МегаФону (раздача с телефона или модем) и ВЫКЛЮЧИТЕ любой VPN.
rem 2) Замените ссылку на свою подписку all (с вашим токеном).
set SUB=https://workerjugg.github.io/suetaworking/ТОКЕН/subscriptions/all
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_singbox.ps1"
for /r "%~dp0bin" %%f in (sing-box.exe) do set SB=%%f
python "%~dp0optimizer.py" --sub %SUB% --singbox "%SB%" --tunnel-top 400
echo.
echo Готово. Откройте local\out\local_best.txt, скопируйте ВСЁ и в Happ нажмите "Из буфера".
pause
