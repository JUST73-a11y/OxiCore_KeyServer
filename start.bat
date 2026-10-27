@echo off
title OxiCore Key Server (Local)
cd /d "%~dp0"
echo ===========================================
echo    OxiCore Key Server ishga tushmoqda...
echo    Admin panel: http://localhost:3000/admin/login
echo ===========================================
node server.js
pause
