<#
FastFlare installer for Windows.

  Easiest:  right-click deploy\install.cmd -> Run as administrator
  Or, in an ADMINISTRATOR PowerShell:
    irm https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/deploy/install.ps1 | iex

  Server:   install.ps1                                           runs FastFlare on this PC (starts at boot)
  Client:   install.ps1 -Client SERVER.IP                         makes this PC take its time from a FastFlare server
  Remove:   install.ps1 -Uninstall
#>
param(
  [string]$Client,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Join-Path $env:ProgramData 'FastFlare'
$App  = Join-Path $Root 'app'
$Task = 'FastFlare'
function Say($m) { Write-Host ''; Write-Host "==> $m" -ForegroundColor Cyan }

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an administrator PowerShell (or right-click install.cmd and choose Run as administrator).'
}

# ---- Client mode: use a FastFlare server as this PC's time source ------------------------------
if ($Client) {
  Say "Pointing this PC's clock at $Client"
  Set-Service w32time -StartupType Automatic
  w32tm /config /manualpeerlist:"$Client,0x8" /syncfromflags:manual /reliable:no /update | Out-Null
  Restart-Service w32time -Force
  w32tm /resync /force
  Write-Host ''
  w32tm /query /status
  Write-Host ''
  Write-Host "Check the difference to the server with:  w32tm /stripchart /computer:$Client /samples:5 /dataonly"
  return
}

# ---- Uninstall -------------------------------------------------------------------------------------
if ($Uninstall) {
  Say 'Removing FastFlare'
  Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*ProgramData\FastFlare\app*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  Get-NetFirewallRule -DisplayName 'FastFlare*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
  Write-Host 'FastFlare removed.'
  return
}

# ---- Server install ----------------------------------------------------------------------------------
function Get-NodeMajor { try { [int]((node -v) -replace '^v(\d+)\..*', '$1') } catch { 0 } }
function Update-Path { $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User') }

if ((Get-NodeMajor) -lt 20) {
  Say 'Installing Node.js'
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements | Out-Null
  }
  Update-Path
  if ((Get-NodeMajor) -lt 20) {
    $index = (Invoke-WebRequest -UseBasicParsing 'https://nodejs.org/dist/latest-v22.x/').Content
    $msi = [regex]::Match($index, 'node-v22[\d.]+-x64\.msi').Value
    if (-not $msi) { throw 'Could not find the Node.js installer. Install Node 20 or newer from nodejs.org and run this again.' }
    $file = Join-Path $env:TEMP $msi
    Invoke-WebRequest -UseBasicParsing "https://nodejs.org/dist/latest-v22.x/$msi" -OutFile $file
    Start-Process msiexec.exe -ArgumentList "/i `"$file`" /qn /norestart" -Wait
    Update-Path
  }
  if ((Get-NodeMajor) -lt 20) { throw 'Node.js 20 or newer is required but was not found after installing.' }
}
$NodeExe = (Get-Command node).Source

Say 'Downloading FastFlare'
if (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*ProgramData\FastFlare\app*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$zip = Join-Path $env:TEMP 'fastflare.zip'
$tmp = Join-Path $env:TEMP 'fastflare-extract'
Invoke-WebRequest -UseBasicParsing 'https://github.com/ArthWarrior3201/FastFlare/archive/refs/heads/main.zip' -OutFile $zip
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
Expand-Archive -Path $zip -DestinationPath $tmp -Force
if (Test-Path $App) { Remove-Item -Recurse -Force $App }
Move-Item (Join-Path $tmp 'FastFlare-main') $App

$settings = Join-Path $Root 'settings.cmd'
if (-not (Test-Path $settings)) {
  Say 'Creating settings'
  $bytes = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $secret = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
  Set-Content -Path $settings -Encoding ASCII -Value @("set FF_SECRET=$secret")
}
$run = Join-Path $Root 'run.cmd'
Set-Content -Path $run -Encoding ASCII -Value @(
  '@echo off',
  'call "%~dp0settings.cmd"',
  "cd /d `"$App`"",
  "`"$NodeExe`" `"$App\src\server.js`" >> `"$Root\fastflare.log`" 2>&1"
)

Say 'Opening the firewall (UDP 123 for time, TCP 8787 for the web API)'
Get-NetFirewallRule -DisplayName 'FastFlare*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'FastFlare time (UDP 123)' -Direction Inbound -Protocol UDP -LocalPort 123 -Action Allow | Out-Null
New-NetFirewallRule -DisplayName 'FastFlare web (TCP 8787)' -Direction Inbound -Protocol TCP -LocalPort 8787 -Action Allow | Out-Null

Say 'Starting FastFlare (it will also start at every boot)'
$action    = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$run`""
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$taskSet   = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $taskSet -Force | Out-Null
Start-ScheduledTask -TaskName $Task

Say 'Waiting for the first time sync'
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
  try { if ((Invoke-RestMethod 'http://localhost:8787/time/status' -TimeoutSec 2).synced) { $ok = $true; break } } catch { }
  Start-Sleep -Seconds 1
}

$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | ForEach-Object { $_.IPAddress })
$ip = if ($ips.Count) { $ips[0] } else { 'THIS.PC.IP' }
Write-Host ''
if ($ok) { Write-Host 'FastFlare is running and synced.' -ForegroundColor Green }
else { Write-Host "FastFlare is running but has not synced yet. Log: $Root\fastflare.log" -ForegroundColor Yellow }
Write-Host @"

  Web API:     http://${ip}:8787/time?tz=Asia/Kolkata
  Time server: $ip   (UDP 123)

  Other devices on this network can use $ip as their time server.
  Keep this PC on for the server to stay available.
  Remove it later with:  install.ps1 -Uninstall

"@
