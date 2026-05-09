@echo off
setlocal

cd /d "%~dp0\..\.."
go build -ldflags "-H=windowsgui" -o "test\image_finder\image_finder.exe" ./test/image_finder
if errorlevel 1 (
	echo Build failed.
	exit /b %errorlevel%
)

echo Build OK: test\image_finder\image_finder.exe
exit /b 0
