暂时未完成

需要防杀软
win10_Iot_Ltsc2021_5198_X64 [AEC155F5].esd会被识别成win7
需要更好的方式获取镜像版本

xp系列号：MRX3F-47B9T-2487J-KWKMF-RPWBY
3BHMCUXNJVWZLJBA5I8LHF7YD1OM79EF
set GOOS=windows

set GOARCH=386

set CGO_ENABLED=1

set CC=i686-w64-mingw32-gcc

go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe
