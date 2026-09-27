@echo off
setlocal

set "STATUS_URL=http://127.0.0.1:8765/account-admin.html"
curl.exe -fsS "http://127.0.0.1:8765/api/health" >nul 2>nul
if errorlevel 1 (
  echo Wembux server is not running. Start Start-Wembux-Server.bat first.
  pause
  exit /b 1
)

for %%I in (
  "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
  "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
  "%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"
  "%ProgramFiles%\Google\Chrome\Application\chrome.exe"
  "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
  "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
) do if exist "%%~I" (
  start "" "%%~I" --new-window --app="%STATUS_URL%"
  exit /b 0
)

start "" "%APP_DIR%\account-admin.html"
