暂时未完成

xp系列号：MRX3F-47B9T-2487J-KWKMF-RPWBY

set GOOS=windows

set GOARCH=386

set CGO_ENABLED=1

set CC=i686-w64-mingw32-gcc

go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe
