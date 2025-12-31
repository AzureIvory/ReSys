set GOARCH=amd64
set CGO_ENABLED=1
set CC=C:\mingw64\bin\x86_64-w64-mingw32-gcc.exe
go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe