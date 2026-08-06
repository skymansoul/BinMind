@echo off
rem binmind launcher for Windows
rem Paths with spaces must be quoted

setlocal enabledelayedexpansion
set "g_SCRIPT_DIR=%~dp0"
set "g_PYTHON_BIN=python"

rem Locate Python: venv > python3 > python
if exist "%g_SCRIPT_DIR%.venv\Scripts\python.exe" (
    set "g_PYTHON_BIN=%g_SCRIPT_DIR%.venv\Scripts\python.exe"
    goto :found_python
)

rem Try python3 (common in Git Bash / MSYS2, may not exist in cmd)
where python3 >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "g_PYTHON_BIN=python3"
    goto :found_python
)

rem Fall back to python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+ or create a venv.
    echo   Download: https://www.python.org/downloads/
    exit /b 1
)

:found_python

rem Execute — all arguments forwarded to the Python script
rem Note: paths with spaces in cmd must be quoted
"%g_PYTHON_BIN%" "%g_SCRIPT_DIR%binmind.py" %*
