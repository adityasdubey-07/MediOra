@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_EXE="
where python.exe >nul 2>nul
if not errorlevel 1 set "PYTHON_EXE=python.exe"
if not defined PYTHON_EXE (
  for /d %%D in ("C:\Users\Aditya\AppData\Local\strawberry\sandbox\.sandbox-bin\win32-x64\python-runtime-v3-*") do if exist "%%~fD\Scripts\python.exe" set "PYTHON_EXE=%%~fD\Scripts\python.exe"
)
if not defined PYTHON_EXE (
  echo Python was not found. Install Python or ask me to help set up the local preview.
  pause
  exit /b 1
)
start "Connected Care Test Server" /D "%~dp0" "%PYTHON_EXE%" -m http.server 8000 --bind 127.0.0.1
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:8000/index.html"
endlocal
