@echo off
title Autonomous Multi-Agent SOC Framework - Public Internet Tunnel
echo ===============================================================================
echo  Autonomous Multi-Agent Framework for Fraud and Cyber Threat Detection
echo  Launching Live Public HTTPS Tunnel via Cloudflare Edge Network
echo ===============================================================================
echo.

echo [1/2] Verifying local Streamlit dashboard on port 8501...
netstat -ano | findstr 8501 | findstr LISTENING >nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Starting Streamlit in background...
    start /b .venv\Scripts\streamlit.exe run dashboard\app.py
    timeout /t 3 /nobreak >nul
) else (
    echo [INFO] Local Streamlit dashboard is already active on port 8501.
)

echo.
echo [2/2] Opening Cloudflare Secure Public Tunnel to the Internet...
echo.
echo ===============================================================================
echo  A public HTTPS link (https://xxxx.trycloudflare.com) will appear below.
echo  Share this URL with faculty, examiners, and evaluators anywhere in the world!
echo  (Press Ctrl+C to close the public internet tunnel when finished)
echo ===============================================================================
echo.

.\tools\cloudflared.exe tunnel --url http://127.0.0.1:8501
pause
