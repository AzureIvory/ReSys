set GOOS=windows
set GOARCH=386
set CGO_ENABLED=1
set "CC=clang --target=i686-w64-windows-gnu"
set "CXX=clang++ --target=i686-w64-windows-gnu"
go clean -cache
go build -trimpath -buildvcs=false ^
  -ldflags "-H=windowsgui -s -w -buildid= -linkmode external -extldflags \"-static -Wl,--gc-sections -Wl,--strip-all\"" ^
  -o ReSys.exe