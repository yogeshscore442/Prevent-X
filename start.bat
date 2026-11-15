@echo off
chcp 65001 >nul
title PREVENT-X Platform & Security Lab Launcher
cd /d "%~dp0"

:: ==============================================================================
:: PREVENT-X : AI-Era Virtual Patching Platform & Security Testing Lab
:: Single-Click Master Windows Startup Automation
:: 
:: - Starts all 7 services: PostgreSQL, Redis, Upstream App, Nginx WAF Proxy,
::   Celery Worker, FastAPI Backend, and React Frontend.
:: - Automatically detects Wi-Fi / Local Network IP and displays both Local & Network URLs.
:: - Automatically stops all services cleanly when this window is closed or Enter/Ctrl+C is pressed.
:: ==============================================================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*

exit /b %ERRORLEVEL%
