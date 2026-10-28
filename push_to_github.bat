@echo off
title Push Project to GitHub
echo ===============================================================================
echo  Pushing project to https://github.com/HEMANTH-6557/fraud-cyber-threat-detection
echo ===============================================================================
echo.
echo If a GitHub sign-in window or browser popup appears, please click "Sign in" to authorize.
echo.
git push -u origin main
echo.
echo ===============================================================================
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Code pushed successfully to GitHub!
    echo.
    echo Next step: Go to https://share.streamlit.io to deploy your app for 24/7 access!
) else (
    echo [ERROR] Push failed. If authentication failed, please try again.
)
echo ===============================================================================
pause
