@echo off
rem Запуск локального оптимизатора. Замените ссылку на свою подписку.
set SUB=https://USER.github.io/REPO/subscriptions/all
python "%~dp0optimizer.py" --sub %SUB%
pause
