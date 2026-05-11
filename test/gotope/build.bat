@echo off
setlocal

cd /d "%~dp0\..\.."
go build -o "test\gotope\gotope.exe" ./test/gotope
if errorlevel 1 (
	echo Build failed.
	exit /b %errorlevel%
)

echo Build OK: test\gotope\gotope.exe
exit /b 0
