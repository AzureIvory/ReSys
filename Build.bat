set GOOS=windows
set GOARCH=386
set CGO_ENABLED=1
set CC=i686-w64-mingw32-gcc
go build -x -v -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe