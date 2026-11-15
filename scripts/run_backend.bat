@echo off
chcp 65001 >nul
title PREVENT-X Backend API
cd /d "%~dp0.."
set "PORT=%1"
if "%PORT%"=="" set "PORT=8002"

echo ==============================================================================
echo                 PREVENT-X BACKEND API SERVER
echo ==============================================================================
echo [*] Working Directory: %CD%
echo [*] Listening on     : http://127.0.0.1:%PORT%
echo [*] OpenAPI Docs     : http://127.0.0.1:%PORT%/api/v1/docs
echo ==============================================================================
echo.

call .venv\Scripts\activate.bat
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port %PORT% --reload

if errorlevel 1 (
    echo.
    echo [ERROR] Backend API exited with error.
    pause
)

