@echo off
title Push Project to GitHub
echo ===============================================================================
echo  Autonomous Multi-Agent SOC Framework - GitHub Synchronizer
echo  Target: https://github.com/HEMANTH-6557/fraud-cyber-threat-detection
echo ===============================================================================
echo.
echo [1/3] Staging modified and new files...
git add .
echo [2/3] Creating deployment commit...
git commit -m "Fix: Streamlit Cloud deployment entrypoint and configuration"
echo.
echo [3/3] Pushing to GitHub main branch...
echo (If a GitHub sign-in window or browser popup appears, please click "Sign in")
echo.
git push -u origin main
echo.
echo ===============================================================================
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Code pushed successfully to GitHub!
    echo.
    echo Streamlit Cloud will automatically detect the push and redeploy.
    echo Check your live dashboard at:
    echo https://fraud-cyber-threat-detection.streamlit.app/
) else (
    echo [ERROR] Push failed. If authentication failed, please try again.
)
echo ===============================================================================
pause
