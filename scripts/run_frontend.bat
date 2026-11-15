@echo off
chcp 65001 >nul
title PREVENT-X Frontend UI
cd /d "%~dp0..\frontend"
set "PORT=%1"
if "%PORT%"=="" set "PORT=8002"
set "BACKEND_PORT=%PORT%"
set "VITE_BACKEND_PORT=%PORT%"

echo ==============================================================================
echo                 PREVENT-X FRONTEND WEB UI
echo ==============================================================================
echo [*] Working Directory: %CD%
echo [*] Frontend URL     : http://localhost:5173
echo [*] Proxying API to  : http://localhost:%PORT%
echo ==============================================================================
echo.

call npm run dev

if errorlevel 1 (
    echo.
    echo [ERROR] Frontend dev server exited with error.
    pause
)

