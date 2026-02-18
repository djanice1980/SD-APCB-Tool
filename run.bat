@echo off
:: SD-APCB Tool Launcher for Windows
:: Double-click this file to run the CLI in interactive mode.
:: The window will stay open so you can interact with the tool.

python "%~dp0sd_apcb_tool.py" %*
if errorlevel 1 (
    echo.
    echo   Tool exited with an error.
)
echo.
pause
