@echo off
setlocal

set LOG=%SystemRoot%\Setup\Scripts\Specialize.cmd.log
echo Specialize.cmd started: %date% %time%>>"%LOG%"

REM This runs during the specialize stage, before the normal desktop logon.
REM Put commands that do not require an interactive desktop here.

if exist "C:\drive.exe" (
    echo Running C:\drive.exe>>"%LOG%"
    start "" /wait "C:\drive.exe"
    echo C:\drive.exe finished with exit code %ERRORLEVEL%>>"%LOG%"
) else (
    echo C:\drive.exe not found. Edit Specialize.cmd to run your own command.>>"%LOG%"
)

echo Specialize.cmd finished: %date% %time%>>"%LOG%"
exit /b 0
