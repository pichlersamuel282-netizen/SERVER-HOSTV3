@echo off
setlocal EnableExtensions

set "APP_DIR=%~dp0"
if not exist "%APP_DIR%\wembux_host.py" set "APP_DIR=%LOCALAPPDATA%\Wembux"
for %%I in ("%APP_DIR%") do set "APP_DIR=%%~fI"
set "DATA_DIR=%LOCALAPPDATA%\Wembux\data"
set "VENV_DIR=%LOCALAPPDATA%\Wembux\server-venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
if /i "%~1"=="--check" goto check_files

where py >nul 2>nul
if errorlevel 1 goto use_python_command
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto python_missing
if not exist "%VENV_PYTHON%" py -3 -m venv "%VENV_DIR%"
if errorlevel 1 goto python_missing
goto install_dependencies

:use_python_command
where python >nul 2>nul
if errorlevel 1 goto python_missing
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto python_missing
if not exist "%VENV_PYTHON%" python -m venv "%VENV_DIR%"
if errorlevel 1 goto python_missing

:install_dependencies
if not exist "%VENV_PYTHON%" goto python_missing
echo Preparing Wembux server dependencies...
"%VENV_PYTHON%" -m pip install --disable-pip-version-check -r "%APP_DIR%\requirements.txt"
if errorlevel 1 goto dependency_error
	where cloudflared >nul 2>nul
	if errorlevel 1 (
	  where winget >nul 2>nul
	  if errorlevel 1 goto tunnel_missing
	  echo Installing Cloudflare Tunnel for this Windows user...
	  winget install --id Cloudflare.cloudflared -e --scope user --accept-package-agreements --accept-source-agreements
	  if errorlevel 1 goto tunnel_missing
	  set "PATH=%PATH%;%LOCALAPPDATA%\Microsoft\WinGet\Links"
	)

set "WEMBUX_DATA_DIR=%DATA_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
"%VENV_PYTHON%" "%APP_DIR%\wembux_host.py" --data-dir "%DATA_DIR%"
exit /b %errorlevel%

:python_missing
echo Wembux needs Python 3.11 or newer. Install Python from https://www.python.org/downloads/ and run this file again.
pause
exit /b 1

:dependency_error
echo Could not install server dependencies. Check the laptop's internet connection and try again.
pause
exit /b 1

:check_files
for %%F in (wembux_host.py wembux_server.py requirements.txt) do if not exist "%APP_DIR%\%%F" (
	echo Missing required server file: %%F
	exit /b 1
)
echo Wembux host files are present in %APP_DIR%.
exit /b 0
