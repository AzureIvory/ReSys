@echo off
setlocal

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=386

go run github.com/akavel/rsrc@v0.10.2 -arch %GOARCH% -manifest res\main.manifest -ico res\icon.ico -o rsrc_windows_%GOARCH%.syso
if errorlevel 1 exit /b 1

go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe
if errorlevel 1 exit /b 1
