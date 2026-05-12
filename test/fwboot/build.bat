@echo off
setlocal

cd /d "%~dp0\..\.."
go build -o "test\fwboot\fwboot.exe" ./test/fwboot
if errorlevel 1 (
	echo Build failed.
	exit /b %errorlevel%
)

echo Build OK: test\fwboot\fwboot.exe
exit /b 0
