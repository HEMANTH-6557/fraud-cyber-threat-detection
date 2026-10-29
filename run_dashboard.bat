@echo off
title Autonomous Multi-Agent SOC Framework - Dashboard
cls
echo ===============================================================================
echo  AUTONOMOUS MULTI-AGENT FRAMEWORK FOR FRAUD ^& CYBER THREAT DETECTION
echo  SOC Analyst Dashboard Launcher
echo ===============================================================================
echo.

echo [1/3] Checking port 8501 and freeing any stale sessions...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8501" ^| findstr "LISTENING"') do (
    echo [INFO] Terminating zombie process on port 8501 (PID %%a)...
    taskkill /f /pid %%a >nul 2>&1
)
echo [1/3] Port 8501 is clean and available.
echo.

echo [2/3] Setting up automatic browser redirect to http://localhost:8501...
start /b "" cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:8501"

echo [3/3] Starting Streamlit SOC Dashboard Server...
echo.
echo -------------------------------------------------------------------------------
echo  >> LOCAL DASHBOARD : http://localhost:8501
echo  >> NOTICE          : KEEP THIS TERMINAL WINDOW OPEN while using the dashboard.
echo  >> TO STOP SERVER  : Press Ctrl+C in this window or close this window.
echo -------------------------------------------------------------------------------
echo.

if exist .venv\Scripts\streamlit.exe (
    .venv\Scripts\streamlit.exe run dashboard\app.py --server.port 8501 --server.headless false --browser.serverAddress localhost
) else (
    streamlit run dashboard\app.py --server.port 8501 --server.headless false --browser.serverAddress localhost
)

pause
