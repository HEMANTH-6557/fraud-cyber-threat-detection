@echo off
title Autonomous Multi-Agent SOC Framework - Automated Test Suite
echo ===============================================================================
echo  Autonomous Multi-Agent Framework for Fraud and Cyber Threat Detection
echo  Running Comprehensive Automated Verification and Pipeline Tests
echo ===============================================================================
echo.

if exist .venv\Scripts\python.exe (
    set PY_EXE=.venv\Scripts\python.exe
) else (
    set PY_EXE=python
)

echo [TEST 1/5] Running Comprehensive 9-Point Full Pipeline Test Suite...
%PY_EXE% tests\test_full_pipeline.py
if %ERRORLEVEL% NEQ 0 goto failure

echo.
echo [TEST 2/5] Running Tier-1 Fast Anomaly Detection Pipeline...
%PY_EXE% tests\test_tier1.py
if %ERRORLEVEL% NEQ 0 goto failure

echo.
echo [TEST 3/5] Running End-to-End Multi-Agent Collaborative Framework...
%PY_EXE% tests\test_multi_agent.py
if %ERRORLEVEL% NEQ 0 goto failure

echo.
echo [TEST 4/5] Running Private Access PBKDF2 Authentication Verification...
%PY_EXE% tests\test_auth.py
if %ERRORLEVEL% NEQ 0 goto failure

echo.
echo [TEST 5/5] Running Nine Selectable Modules Comprehensive Verification...
%PY_EXE% tests\test_nine_modules.py
if %ERRORLEVEL% NEQ 0 goto failure

echo.
echo ===============================================================================
echo  ALL AUTOMATED SECURITY AND SYSTEM VERIFICATION TESTS PASSED SUCCESSFULLY!
echo ===============================================================================
if "%1"=="/nopause" goto end
pause
:end
exit /b 0

:failure
echo.
echo [ERROR] Test execution failed! Check error details above.
if "%1"=="/nopause" goto endfail
pause
:endfail
exit /b 1
