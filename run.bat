@echo off
title DDoS Detection & Prevention System
echo ============================================================
echo   DDoS Attack Detection and Prevention System
echo   Safe Simulation Mode - College Project
echo ============================================================
echo.

REM 1. Verify Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not detected or not found in system PATH.
    echo Please install Python 3.9+ from https://www.python.org/
    echo Be sure to check the box "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed.
echo.

REM 2. Check if models exist, otherwise run setup.py
if not exist "backend\models\rf_classifier.pkl" (
    echo [INFO] First time setup: Generating synthetic data and training ML models...
    python setup.py
    if %errorlevel% neq 0 (
        echo [ERROR] setup.py encountered an error.
        pause
        exit /b 1
    )
) else (
    echo [OK] Trained ML models found.
)

echo.
echo [INFO] Starting Flask web server at http://localhost:5000 ...
echo [INFO] Opening dashboard in your default browser...
echo [INFO] KEEP THIS TERMINAL WINDOW OPEN while using the dashboard.
echo [INFO] To stop the server, press Ctrl + C.
echo.

REM 3. Open browser after a short delay
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:5000"

REM 4. Launch backend
python backend/app.py

pause

