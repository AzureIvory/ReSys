# fwboot

`fwboot` 是一个独立的命令行测试程序，用来直接调用 `src/boot` 包里的 `WimToEFI`。

它的作用是：

- 从 `boot.wim` 中准备出 `Windows` 目录
- 优先用 `DISM/WIMGAPI` 挂载或解包
- 失败后回退到 `wimlib-imagex` 提取 `\Windows`
- 最后执行 `bcdboot <Windows目录> /s <FAT32分区> /f UEFI`

## 用法

```bat
fwboot.exe <wimPath> [index] [espRoot]
```

示例：

```bat
fwboot.exe D:\boot\boot.wim
fwboot.exe D:\boot\boot.wim 2
fwboot.exe D:\boot\boot.wim S:\
fwboot.exe D:\boot\boot.wim 1 S:\
```

说明：

- `wimPath` 是 `boot.wim` 路径
- `index` 默认自动探测第一个包含 `\Windows` 的镜像索引
- `espRoot` 默认留空，此时自动使用 `boot.wim` 所在分区

## 返回结果

程序输出固定 JSON，便于人工查看，也便于脚本或 AI 解析。

成功示例：

```json
{
	"mode": "wim_to_efi",
	"ok": true,
	"wim": "D:\\boot\\boot.wim",
	"index": 1,
	"esp": "D:\\"
}
```

失败示例：

```json
{
	"mode": "wim_to_efi",
	"ok": false,
	"wim": "D:\\boot\\boot.wim",
	"index": 1,
	"esp": "D:\\",
	"error": "错误信息"
}
```

## 注意

- 目标分区必须是 `FAT32`
- 如果不传 `espRoot`，默认使用 `boot.wim` 所在分区
- 输出里的 `index` 是程序最终实际使用的索引，不是固定回显输入值
- 这个工具只负责生成或刷新 UEFI 引导文件，不会设置 `BootNext`

## 编译

双击 `build.bat`，或在命令行执行：

```bat
test\fwboot\build.bat
```

生成文件：

```bat
test\fwboot\fwboot.exe
```
