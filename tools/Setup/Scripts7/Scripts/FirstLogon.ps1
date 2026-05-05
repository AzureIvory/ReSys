# Windows 7 compatible PowerShell 2.0 entry script
# Stage: first logon
# Purpose: call FirstLogon.cmd and write a basic log.

$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path -Parent $ScriptPath
$CmdFile = Join-Path $ScriptDir "FirstLogon.cmd"
$Log = Join-Path $ScriptDir "FirstLogon.ps1.log"

"FirstLogon.ps1 started: $(Get-Date)" | Out-File -FilePath $Log -Append -Encoding UTF8

if (Test-Path $CmdFile) {
    "Calling: $CmdFile" | Out-File -FilePath $Log -Append -Encoding UTF8
    $arguments = '/c ""' + $CmdFile + '""'
    $process = Start-Process -FilePath "$env:ComSpec" -ArgumentList $arguments -Wait -PassThru
    "FirstLogon.cmd exit code: $($process.ExitCode)" | Out-File -FilePath $Log -Append -Encoding UTF8
    "FirstLogon.ps1 finished: $(Get-Date)" | Out-File -FilePath $Log -Append -Encoding UTF8
    exit $process.ExitCode
} else {
    "Missing file: $CmdFile" | Out-File -FilePath $Log -Append -Encoding UTF8
    "FirstLogon.ps1 finished with error: $(Get-Date)" | Out-File -FilePath $Log -Append -Encoding UTF8
    exit 1
}
