set CGO_ENABLED=1
set CC=x86_64-w64-mingw32-gcc
go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe
