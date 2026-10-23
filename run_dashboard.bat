@echo off
title Autonomous Multi-Agent SOC Framework - Dashboard
echo ===============================================================================
echo  Autonomous Multi-Agent Framework for Fraud and Cyber Threat Detection
echo  Starting Interactive SOC Analyst Dashboard on http://localhost:8501
echo ===============================================================================
echo.

if exist .venv\Scripts\streamlit.exe (
    echo [INFO] Using virtual environment (.venv)...
    .venv\Scripts\streamlit.exe run dashboard\app.py
) else (
    echo [INFO] .venv not found, attempting global streamlit...
    streamlit run dashboard\app.py
)

pause
