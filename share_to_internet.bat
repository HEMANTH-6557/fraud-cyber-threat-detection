@echo off
title Autonomous Multi-Agent SOC Framework - Public Internet Tunnel
echo ===============================================================================
echo  Autonomous Multi-Agent Framework for Fraud and Cyber Threat Detection
echo  Public Tunnel Gateway
echo ===============================================================================
echo.

echo [1/2] Verifying local Streamlit dashboard on port 8501...
netstat -ano | findstr 8501 | findstr LISTENING >nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Starting Streamlit in background...
    start /b .venv\Scripts\streamlit.exe run dashboard\app.py --server.port 8501 --server.headless true
    timeout /t 5 /nobreak >nul
) else (
    echo [INFO] Local Streamlit dashboard is active on port 8501.
)

echo.
echo ===============================================================================
echo  SELECT PUBLIC TUNNEL PROVIDER:
echo    [1] Jio-Friendly Tunnel (Works on Reliance Jio, Airtel, Vi, JioFiber)
echo    [2] Cloudflare Edge Tunnel (Cloudflare CDN - requires Private DNS on Jio)
echo ===============================================================================
set /p choice="Enter choice [1 or 2, default is 1]: "
if "%choice%"=="2" goto cloudflare

:pinggy
echo.
echo [2/2] Launching Jio-Compatible Tunnel...
ssh -i .\tools\id_ed25519 -o StrictHostKeyChecking=no -p 443 -R0:127.0.0.1:8501 a.pinggy.io
goto end

:cloudflare
echo.
echo [2/2] Launching Cloudflare Edge Tunnel...
.\tools\cloudflared.exe tunnel --protocol http2 --url http://127.0.0.1:8501

:end
pause
