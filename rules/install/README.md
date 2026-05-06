# install JSON 说明

这个目录放的是重装配置 JSON。

- [default.json](/C:/Users/Administrator/Desktop/ReSys/rules/install/default.json)：
  手动重装模板。
- [win7.json](/C:/Users/Administrator/Desktop/ReSys/rules/install/auto/win7.json)：
  自动重装 Windows 7 模板。
- [win10.json](/C:/Users/Administrator/Desktop/ReSys/rules/install/auto/win10.json)：
  自动重装 Windows 10 模板。
- [win11.json](/C:/Users/Administrator/Desktop/ReSys/rules/install/auto/win11.json)：
  自动重装 Windows 11 模板。

程序会忽略不认识的字段，所以你可以保留 `_`、`_method` 这类注释字段。

## 路径规则

- `image_path`、`PEwim`、`file.items[].src`、`win7fix.*`
  支持绝对路径，也支持相对路径。
  相对路径是相对程序所在目录。
- `file.items[].dst`
  是相对新系统根目录的路径。
  例如 `\\Windows\\Panther\\Unattend.xml`。
- `shortcut.items[].dir`
  也是相对新系统根目录的路径。
  例如 `\\Users\\Public\\Desktop`。
- `shortcut.items[].target`
  支持三种写法：
  - `https://...`：网页快捷方式
  - `C:\\xxx.exe`：绝对路径快捷方式
  - `\\xxx.exe`：相对新系统根目录的路径

## 顶层字段

### `mode`

安装模式。

- `manual`：手动重装
- `auto`：自动重装

通常：

- `default.json` 用 `manual`
- `auto/*.json` 用 `auto`

### `target_os`

目标系统版本。

- `win7`
- `win10`
- `win11`

手动模式可以留空。
自动模式建议和文件名保持一致。

### `image_arch`

镜像架构。

- `auto`：自动选择
- `32`
- `64`
- `arm`
- 空：按程序默认逻辑处理

### `pe_arch`

PE 架构。

- `auto`
- `32`
- `64`
- `arm`
- 空：按程序默认逻辑处理

### `image_path`

安装镜像路径。

- 留空：自动重装按程序现有规则找镜像或下载镜像
- 填值：直接使用你指定的镜像

支持 `wim`、`esd`、`iso`。

示例：

```json
"image_path": "images\\install.wim"
```

```json
"image_path": "D:\\ISO\\Win10.iso"
```

### `index`

镜像索引。

- `-1`：自动选择
- `1`、`2`、`3`...：指定镜像索引

如果一个镜像里有多个版本，这个字段用来指定具体要装哪一个。

### `partition`

目标安装分区。

常见写法：

```json
"partition": "C:\\"
```

或留空让程序自动判断：

```json
"partition": ""
```

### `PEwim`

自定义 PE 镜像路径。

- 留空：自动选择或自动获取 PE
- 填值：强制使用指定的 PE WIM

示例：

```json
"PEwim": "tools\\pe\\wepe.wim"
```

### `restart`

是否在准备完成后自动重启进入 PE。

- `true`：自动重启
- `false`：不自动重启

## `boot`

引导修复相关配置。

### `boot.method`

- `AUTO`：自动修复
- `UEFI`：强制按 UEFI 修复
- `BIOS`：强制按 BIOS 修复
- `NONE` 或 `SKIP`：跳过引导修复

### `boot.boot_partition`

- `AUTO`：自动选择引导分区
- `gpt:<DiskUniqueID>:<PartitionGuid>`：手动指定 GPT 分区
- `mbr:<DiskSignature>:<PartitionNumber>`：手动指定 MBR 分区

大多数情况下保持 `AUTO` 即可。

## `unattended`

无人值守配置。

### `unattended.state`

- `true`：启用无人值守
- `false`：禁用无人值守

### `unattended.unattended_file`

- `AUTO`：自动选择无人值守文件
- 其他路径：使用你指定的 XML 文件

`AUTO` 时会按目标系统自动选用内置 XML。

## `backup_driver`

驱动备份与恢复配置。

### `backup_driver.state`

- `true`：安装前备份驱动，安装后离线恢复
- `false`：不处理驱动

### `backup_driver.file`

按文件名规则筛选驱动。

示例：

```json
"file": ["oem*.inf"]
```

### `backup_driver.guid`

按设备类 GUID 筛选驱动。

示例：

```json
"guid": ["{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"]
```

## `format`

格式化目标分区的配置。

### `format.state`

- `true`：安装前格式化目标分区
- `false`：不格式化

### `format.fs`

文件系统。

常用值：

- `NTFS`
- `FAT32`
- `exFAT`

实际是否适合当前分区，由你自己决定。

### `format.quick`

- `true`：快速格式化
- `false`：完整格式化

### `format.letter`

目前只支持：

```json
"letter": "AUTO"
```

### `format.label`

分区卷标。

示例：

```json
"label": "Windows"
```

## `file`

安装完成后复制文件或目录到新系统。

### `file.state`

- `true`：启用复制
- `false`：不复制

### `file.items`

每一项都包含下面字段：

- `src`：源路径
- `dst`：目标路径，相对新系统根目录
- `overwrite`：目标已存在时是否覆盖
- `required`：源不存在时是否报错

示例：

```json
"file": {
	"state": true,
	"items": [
		{
			"src": "tools\\Setup\\win10.xml",
			"dst": "\\Windows\\Panther\\Unattend.xml",
			"overwrite": true,
			"required": false
		}
	]
}
```

## `shortcut`

安装完成后在新系统里创建快捷方式。

### `shortcut.state`

- `true`：启用快捷方式创建
- `false`：不创建

### `shortcut.items`

每一项都包含下面字段：

- `target`：快捷方式目标
- `name`：快捷方式名称
- `dir`：快捷方式放到哪里，相对新系统根目录

示例 1：程序快捷方式

```json
{
	"target": "C:\\drive.exe",
	"name": "驱动",
	"dir": "\\Users\\Public\\Desktop"
}
```

示例 2：网页快捷方式

```json
{
	"target": "https://store.ttraw.com",
	"name": "应用商店",
	"dir": "\\Users\\Public\\Desktop"
}
```

## `win7fix`

Windows 7 专用修复资源。
只有目标系统是 `win7` 时才有意义。

字段：

- `nvme`：NVMe 驱动目录
- `storage_controller`：存储控制器驱动目录
- `usb3`：USB3 驱动目录
- `uefi`：Win7 UEFI 修复资源目录

非 Win7 可以留空。

示例：

```json
"win7fix": {
	"nvme": "tools\\w7\\drivers\\nvme",
	"storage_controller": "tools\\w7\\drivers\\storage_controller",
	"usb3": "tools\\w7\\drivers\\usb3",
	"uefi": "tools\\w7\\uefi"
}
```

## 建议

- 手动重装建议从 `default.json` 改。
- 自动重装建议只改 `auto/win7.json`、`auto/win10.json`、`auto/win11.json` 对应文件。
- 不确定时优先保持：
  - `index = -1`
  - `partition = ""`
  - `PEwim = ""`
  - `boot.boot_partition = "AUTO"`
- 改路径时，优先先用相对路径，方便整套程序一起移动。
