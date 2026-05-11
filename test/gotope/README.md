# gotope

`gotope` 是一个独立的命令行测试程序，用来直接调用 `src/pe/PE.go` 里的 `GoToPE`。

它适合做两件事：

- 扫描并校验当前机器上可用的 PE 启动文件
- 直接设置下次启动进入指定的 PE

## 用法

```bat
gotope.exe true
gotope.exe false
gotope.exe true sdiPath wimPath
gotope.exe false sdiPath wimPath
```

说明：

- `true` 表示扫描模式
- `false` 表示设置下次启动进入 PE
- 后面再跟 `sdiPath wimPath` 表示使用自定义 SDI/WIM

## 返回结果

程序输出固定 JSON，便于人工查看，也便于脚本或 AI 解析。

扫描成功示例：

```json
{
	"mode": "scan",
	"ok": true,
	"found": true,
	"wim": "D:\\boot\\11pex64.wim",
	"sdi": "D:\\boot\\boot.sdi"
}
```

设置成功示例：

```json
{
	"mode": "set",
	"ok": true
}
```

失败时会返回：

```json
{
	"mode": "scan",
	"ok": false,
	"error": "错误信息"
}
```

## 构建

双击 `build.bat`，或在命令行执行：

```bat
test\gotope\build.bat
```

生成文件：

```bat
test\gotope\gotope.exe
```
