@echo off
setlocal

set LOG=%SystemRoot%\Setup\Scripts\FirstLogon.cmd.log
echo FirstLogon.cmd started: %date% %time%>>"%LOG%"

REM This runs after the first logon reaches the user session.
REM Put programs that need desktop/user context here.

if exist "C:\FirstLogon.exe" (
    echo Running C:\FirstLogon.exe>>"%LOG%"
    start "" "C:\FirstLogon.exe"
    echo C:\FirstLogon.exe launched.>>"%LOG%"
) else (
    echo C:\FirstLogon.exe not found. Edit FirstLogon.cmd to run your own command.>>"%LOG%"
)

echo FirstLogon.cmd finished: %date% %time%>>"%LOG%"
exit /b 0
