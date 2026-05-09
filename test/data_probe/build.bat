@echo off
setlocal

cd /d "%~dp0\..\.."
go build -ldflags "-H=windowsgui" -o "test\data_probe\data_probe.exe" ./test/data_probe
if errorlevel 1 (
	echo Build failed.
	exit /b %errorlevel%
)

echo Build OK: test\data_probe\data_probe.exe
exit /b 0
