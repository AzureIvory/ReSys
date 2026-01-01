set CGO_ENABLED=0
set GOARCH=386
go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe