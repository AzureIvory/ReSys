暂时未完成

需要防杀软
写入进PE后需要单独一个文件存放，安装完系统需要删除
当是Win7且UEFI模式时，自动UEFI修补，非UEFI模式，取消UEFI修补
需要检查是否管理员权限运行，不是就以管理员权限重新启动程序
win10_Iot_Ltsc2021_5198_X64 [AEC155F5].esd会被识别成win7
需要更好的方式获取镜像版本
进度条需要解析curl的进度或者用其他的下载工具（急需更靠谱的下载工具）
ListImageInfos需要淘汰，换为GetNtdllVer实现
参考：https://github.com/NORMAL-EX/LetRecovery/tree/main/%E6%AD%A3%E5%B8%B8%E7%B3%BB%E7%BB%9F%E7%AB%AF/src/core
安装镜像后的处理https://github.com/NORMAL-EX/LetRecovery/blob/main/%E6%AD%A3%E5%B8%B8%E7%B3%BB%E7%BB%9F%E7%AB%AF/src/ui/advanced_options.rs
显卡驱动卸载：https://github.com/Wagnard/display-drivers-uninstaller

xp系列号：MRX3F-47B9T-2487J-KWKMF-RPWBY
3BHMCUXNJVWZLJBA5I8LHF7YD1OM79EF
set GOOS=windows

set GOARCH=386

set CGO_ENABLED=1

set CC=i686-w64-mingw32-gcc

go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -o ReSys.exe
