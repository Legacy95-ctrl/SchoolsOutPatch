@echo off
setlocal
cd /d "%~dp0"
if not exist "Injector.exe" (
    echo Injector.exe is missing. Extract all five files from the patch ZIP.
    pause
    exit /b 1
)
"%~dp0Injector.exe" --check-install
if errorlevel 1 (
    pause
    exit /b 1
)
set "SCHOOLSOUT_TRACE_QUIT=1"
set "SCHOOLSOUT_SUPPRESS_CHEAT_QUIT=1"
set "SCHOOLSOUT_SUPPRESS_EXIT_STATE=1"
set "SCHOOLSOUT_GAME_ARGS=+forcemode:screen"
start "Injector" "%~dp0Injector.exe" --launch
timeout /t 1 /nobreak >nul
"%~dp0Injector.exe" --wait-ready
if errorlevel 1 (
    pause
    exit /b 1
)
endlocal
