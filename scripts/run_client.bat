@echo off
setlocal

:: ─────────────────────────────────────────────────────────────────────────────
:: run_client.bat — Start the TamozaKeyGen license validator CLI
:: ─────────────────────────────────────────────────────────────────────────────

:: Resolve the repo root (one level above this scripts\ folder)
set "ROOT=%~dp0.."

:: Prefer the project virtual-env Python if it exists
set "VENV_PY=%ROOT%\.venv\Scripts\python.exe"
if exist "%VENV_PY%" (
    set "PYTHON=%VENV_PY%"
) else (
    :: Fall back to whatever python is on PATH
    set "PYTHON=python"
)

:: Run the client script
"%PYTHON%" "%~dp0client_integration.py"

:: Keep the window open so the user can read the result
echo.
pause
endlocal
