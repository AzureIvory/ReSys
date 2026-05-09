@echo off
setlocal

cd /d "%~dp0\..\.."
go build -ldflags "-H=windowsgui" -o "test\downloader\downloader.exe" ./test/downloader
if errorlevel 1 (
	echo Build failed.
	exit /b %errorlevel%
)

echo Build OK: test\downloader\downloader.exe
exit /b 0
