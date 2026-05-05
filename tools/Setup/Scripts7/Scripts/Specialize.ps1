# Windows 7 compatible PowerShell 2.0 entry script
# Stage: specialize
# Purpose: call Specialize.cmd and write a basic log.

$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path -Parent $ScriptPath
$CmdFile = Join-Path $ScriptDir "Specialize.cmd"
$Log = Join-Path $ScriptDir "Specialize.ps1.log"

"Specialize.ps1 started: $(Get-Date)" | Out-File -FilePath $Log -Append -Encoding UTF8

if (Test-Path $CmdFile) {
    "Calling: $CmdFile" | Out-File -FilePath $Log -Append -Encoding UTF8
    $arguments = '/c ""' + $CmdFile + '""'
    $process = Start-Process -FilePath "$env:ComSpec" -ArgumentList $arguments -Wait -PassThru
    "Specialize.cmd exit code: $($process.ExitCode)" | Out-File -FilePath $Log -Append -Encoding UTF8
    "Specialize.ps1 finished: $(Get-Date)" | Out-File -FilePath $Log -Append -Encoding UTF8
    exit $process.ExitCode
} else {
    "Missing file: $CmdFile" | Out-File -FilePath $Log -Append -Encoding UTF8
    "Specialize.ps1 finished with error: $(Get-Date)" | Out-File -FilePath $Log -Append -Encoding UTF8
    exit 1
}
