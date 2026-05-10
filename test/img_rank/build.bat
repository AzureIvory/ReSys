@echo off
setlocal

cd /d "%~dp0\..\.."
go build -o "test\img_rank\img_rank.exe" ./test/img_rank
if errorlevel 1 (
	echo Build failed.
	exit /b %errorlevel%
)

echo Build OK: test\img_rank\img_rank.exe
exit /b 0
