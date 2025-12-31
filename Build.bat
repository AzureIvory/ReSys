set GOOS=windows
set GOARCH=386
set CGO_ENABLED=1
set "CC=clang --target=i686-w64-windows-gnu"
set "CXX=clang++ --target=i686-w64-windows-gnu"
set "CGO_CFLAGS=-Os -g0 -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables"
set "CGO_CXXFLAGS=%CGO_CFLAGS%"
go clean -cache
go build -trimpath -buildvcs=false ^
  -ldflags "-H=windowsgui -s -w -buildid= -linkmode external -extldflags \"-static -Wl,--gc-sections -Wl,--strip-all\"" ^
  -o ReSys.exe