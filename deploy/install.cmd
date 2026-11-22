@echo off
rem FastFlare installer for Windows. Double-click it (it asks for administrator rights).
rem   install.cmd                      run FastFlare on this PC
rem   install.cmd -Client SERVER.IP    make this PC take its time from a FastFlare server
rem   install.cmd -Uninstall           remove FastFlare
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
set "PS1=%~dp0install.ps1"
if not exist "%PS1%" (
  set "PS1=%TEMP%\fastflare-install.ps1"
  powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.ps1' -OutFile '%TEMP%\fastflare-install.ps1'"
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
echo.
pause
