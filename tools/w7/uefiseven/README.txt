======================================================
              UefiSeven - Win7 UEFI 启动修补
======================================================

此文件夹用于存放 UefiSeven 启动修补文件。
UefiSeven 是一个开源项目，用于让 Windows 7 能够在 UEFI Class 3 系统上正常启动。

项目地址: https://github.com/manatails/uefiseven

【问题背景】
Windows 7 的引导程序不完全支持 UEFI，在某些较新的电脑上可能出现：
- 启动时卡在 "Starting Windows" 界面
- 出现错误代码 0xc000000d
- 黑屏无法启动

【解决方案】
UefiSeven 通过在启动前模拟 Int10h 中断处理程序来解决这个问题。

【文件要求】
请从 UefiSeven 发布页面下载最新版本：
https://github.com/manatails/uefiseven/releases

下载后，将以下文件放入此文件夹：

1. bootx64.efi       - UefiSeven 主程序（必需）
2. UefiSeven.ini     - 配置文件（可选，程序会自动创建默认配置）

【工作原理】
当您选择 Win7 镜像并使用 UEFI 模式安装时，如果勾选了 "Win7 UEFI启动修补" 选项：

1. 程序会在引导修复完成后自动部署 UefiSeven
2. 原始的 bootmgfw.efi 会被备份为 bootmgfw.original.efi
3. UefiSeven 的 bootx64.efi 会替换 bootmgfw.efi

启动流程：
UEFI 固件 -> UefiSeven -> bootmgfw.original.efi -> Windows 7

【配置选项】
UefiSeven.ini 配置文件示例：

[uefiseven]
; 跳过启动时的警告和错误（0=显示，1=跳过）
skiperrors=0
; 详细日志输出（0=关闭，1=开启）
verbose=0
; 输出日志到文件（需要 verbose=1）
log=0

【注意事项】
- 此补丁仅适用于 Win7 + UEFI 模式安装
- 对于 Legacy/BIOS 模式安装，不需要此补丁
- 如果您的电脑能正常 UEFI 启动 Win7，也不需要此补丁
- 建议在遇到 Win7 UEFI 启动问题时才启用此选项

======================================================
                  LetRecovery 系统重装工具
======================================================
