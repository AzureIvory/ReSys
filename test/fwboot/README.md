# fwboot

`fwboot` 是一个独立的命令行测试程序，用来直接调用 `src/boot/Boot.go` 里的 `SetFwOnce`。

它的作用是：

- 枚举 `bcdedit /enum firmware /v` 的已有 UEFI 固件启动项
- 按你传入的 `PE` 文件路径匹配对应的固件项
- 调用 `bcdedit /set {fwbootmgr} bootsequence {id}` 设置下次一次性启动

## 用法

```bat
fwboot.exe <pePath>
```

示例：

```bat
fwboot.exe S:\WEPE\WEPE64.WIM
```

## 返回结果

程序输出固定 JSON，便于人工查看，也便于脚本或 AI 解析。

成功示例：

```json
{
	"mode": "set_fw_once",
	"ok": true,
	"pe": "S:\\WEPE\\WEPE64.WIM",
	"id": "{12345678-1111-2222-3333-444444444444}"
}
```

失败示例：

```json
{
	"mode": "set_fw_once",
	"ok": false,
	"pe": "S:\\WEPE\\WEPE64.WIM",
	"error": "错误信息"
}
```

## 注意

- 这个工具只负责切换到“已存在”的 UEFI 固件启动项。
- 如果 `bcdedit /enum firmware /v` 里没有能匹配到该分区的固件项，就会失败。
- 它不会自动创建新的 UEFI 固件启动项。

## 编译

双击 `build.bat`，或在命令行执行：

```bat
test\fwboot\build.bat
```

生成文件：

```bat
test\fwboot\fwboot.exe
```
