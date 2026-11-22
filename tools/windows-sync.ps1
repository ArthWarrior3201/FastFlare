<#
FastFlare Windows time sync (HTTP). Use this when your FastFlare is on a web host that has no UDP 123.

  One-off sync:      powershell -ExecutionPolicy Bypass -File windows-sync.ps1 -Server https://your-app.onrender.com
  Install schedule:  powershell -ExecutionPolicy Bypass -File windows-sync.ps1 -Server https://your-app.onrender.com -Install
  Remove schedule:   powershell -ExecutionPolicy Bypass -File windows-sync.ps1 -Uninstall

Run it in an ADMINISTRATOR PowerShell (setting the clock needs admin).
Takes 5 samples, keeps the one with the shortest round trip, assumes the reply spent half that
round trip travelling back, and only steps the clock if it is more than -ThresholdMs out.
#>
param(
  [string]$Server,
  [int]$Samples = 5,
  [int]$ThresholdMs = 50,
  [int]$EveryMinutes = 15,
  [switch]$Install,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$TaskName = 'FastFlare Time Sync'
$Dir = Join-Path $env:ProgramData 'FastFlare'

function Test-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) { Write-Error 'Run this in an administrator PowerShell.'; exit 1 }

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Removed scheduled task '$TaskName'."
  exit 0
}
if (-not $Server) { Write-Error 'Pass -Server https://your-fastflare-host'; exit 1 }
$Server = $Server.TrimEnd('/')

if ($Install) {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $dest = Join-Path $Dir 'windows-sync.ps1'
  Copy-Item -Force $PSCommandPath $dest
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$dest`" -Server `"$Server`""
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes)
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Write-Host "Installed: syncing from $Server every $EveryMinutes minutes."
}

# Free hosts sleep when idle: the first request can take a while to wake the app.
try { Invoke-RestMethod -Uri "$Server/health" -TimeoutSec 90 | Out-Null } catch { }

$best = $null
for ($i = 0; $i -lt $Samples; $i++) {
  try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-RestMethod -Uri "$Server/time" -TimeoutSec 10
    $sw.Stop()
    $got = [Diagnostics.Stopwatch]::StartNew()   # time since this reply arrived
    $rtt = $sw.Elapsed.TotalMilliseconds
    if (-not $r.synced) { Write-Host 'Server is not synced to its upstream time sources yet.'; continue }
    if ($null -eq $best -or $rtt -lt $best.Rtt) { $best = @{ Rtt = $rtt; UnixMs = [double]$r.unixMs; Got = $got } }
  } catch { Write-Host "sample failed: $($_.Exception.Message)" }
  Start-Sleep -Milliseconds 200
}
if ($null -eq $best) { Write-Error 'No usable reply from the server.'; exit 2 }

$trueNowMs = $best.UnixMs + ($best.Rtt / 2) + $best.Got.Elapsed.TotalMilliseconds
$nowUtc = [DateTimeOffset]::FromUnixTimeMilliseconds([long][math]::Round($trueNowMs)).UtcDateTime
$diffMs = ($nowUtc - [DateTime]::UtcNow).TotalMilliseconds
Write-Host ("Best round trip {0:N0} ms. Local clock is {1:N0} ms {2} true time." -f $best.Rtt, [math]::Abs($diffMs), $(if ($diffMs -gt 0) { 'behind' } else { 'ahead of' }))

if ([math]::Abs($diffMs) -gt $ThresholdMs) {
  Set-Date -Date $nowUtc.ToLocalTime() | Out-Null
  Write-Host 'Clock corrected.'
} else {
  Write-Host "Within $ThresholdMs ms: left alone."
}
