# fwboot

`fwboot` 是一个独立命令行测试程序，用来直接调用 `src/boot` 包里的 `WimSdiToBCD`。

它的作用是：

- 使用 `wimPath + sdiPath` 写入 RAMDISK 启动项
- 设置一次性 `bootsequence`，让下次启动进入该 PE
- 不改主程序流程，便于手动验证

## 用法

```bat
fwboot.exe <wimPath> <sdiPath>
```

示例：

```bat
fwboot.exe D:\boot\11pex64.wim D:\boot\boot.sdi
```

## 返回结果

成功示例：

```json
{
	"mode": "wim_sdi_to_bcd",
	"ok": true,
	"wim": "D:\\boot\\11pex64.wim",
	"sdi": "D:\\boot\\boot.sdi"
}
```

失败示例：

```json
{
	"mode": "wim_sdi_to_bcd",
	"ok": false,
	"wim": "D:\\boot\\11pex64.wim",
	"sdi": "D:\\boot\\boot.sdi",
	"error": "错误信息"
}
```

## 注意

- `wimPath` 和 `sdiPath` 必须都存在
- 当前实现要求两个文件在同一分区
- 该工具会修改系统 BCD，测试前建议先备份

## 编译

```bat
test\fwboot\build.bat
```

生成文件：

```bat
test\fwboot\fwboot.exe
```
