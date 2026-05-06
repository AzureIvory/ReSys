# rules/core JSON 规则说明


## 目录用途

`rules/core` 下面主要有三类规则：

- `image-sources`：系统镜像来源规则。决定“可下载哪些 Windows 镜像”
- `pe-sources`：PE 来源规则。决定“可下载哪些 PE 或 boot.wim”


## 先看最重要的概念

镜像和 PE 来源规则主要有 3 种写法：

1. `items`：你直接把最终下载项写死在 JSON 里
2. `rules`：程序先请求远程 JSON，再按规则把字段取出来
3. `parser = "section_kv_group_v1"`：程序先请求远程文本，再按分段和正则解析

如果你不确定该用哪种，优先按这个顺序判断：

1. 数据本来就是固定的，直接用 `items`
2. 数据在远程 JSON 接口里，使用 `rules`
3. 数据在网页文本或 INI 风格文本里，使用 `section_kv_group_v1`

## 一个规则文件的通用结构

大多数来源规则文件都长这样：

```json
{
  "Source": "win10-zh-cn",
  "Rank": 9,
  "Enabled": true,
  "method": "get",
  "headers": {},
  "data": {},
  "SizeUnit": "GB",
  "timeout": 8000,
  "items": {}
}
```

或者：

```json
{
  "Source": "win10-ms",
  "Rank": 9,
  "Enabled": true,
  "system": "10",
  "url": {
    "url1": "https://example.com/api.json"
  },
  "method": "get",
  "headers": {},
  "data": {},
  "SizeUnit": "B",
  "timeout": 8000,
  "rules": {}
}
```

## 通用字段说明

这些字段在大多数来源规则里都能用。

| 字段 | 是否建议填写 | 作用 |
| --- | --- | --- |
| `Source` | 建议 | 来源名。用于区分这个规则来自哪里 |
| `Rank` | 建议 | 优先级。数字越大越靠前 |
| `Enabled` | 建议 | 是否启用这个规则 |
| `system` | 按需 | 这个规则默认属于哪个系统版本 |
| `url` | 仅远程解析时需要 | 远程地址集合 |
| `method` | 建议 | 请求方式，一般填 `get` |
| `headers` | 可选 | 自定义请求头 |
| `data` | 可选 | `post` 请求时发送的 JSON 数据 |
| `SizeUnit` | 建议 | `Size` 的单位 |
| `timeout` | 建议 | 请求超时，单位毫秒 |
| `items` | `items` 模式必填 | 直接写下载项 |
| `rules` | `rules` 模式必填 | 远程 JSON 字段提取规则 |
| `parser` | 文本解析模式必填 | 指定特殊解析器 |
| `sections` | 文本解析模式按需 | 指定要解析哪些分段 |
| `group` | 文本解析模式按需 | 指定如何把字段分组 |
| `field_map` | 文本解析模式可选 | 自定义字段映射 |
| `extract` | 文本解析模式可选 | 用正则从文本里提取字段 |

### `Source`

这是“来源标识”。

建议：

- 填一个稳定、可读、不会经常变的名字
- 不要把它当注释写得很随意

常见示例：

- `win10-ms`
- `win11-ms`
- `win10-zh-cn`
- `easyrc-PE`

效果：

- 用于区分来源
- 可能影响同优先级时的排序
- 日志里通常会显示这个值

### `Rank`

这是“优先级”。

常见写法：

- `10`
- `9`
- `8`

效果：

- 数值越大，来源越靠前
- 多个来源提供了相同内容时，通常会优先保留更高 `Rank` 的结果

建议：

- 最好显式填写
- 不要只靠文件名或目录位置来表达优先级

### `Enabled`

这是“是否启用”。

可填值：

- `true`
- `false`

效果：

- `true`：参与正常扫描
- `false`：文件还在，但正常聚合时会被跳过

适用场景：

- 临时下线一个来源
- 做规则测试但不想让它正式生效

### `system`

这是“默认系统代号”。

常见值：

- `"7"`
- `"8"`
- `"10"`
- `"11"`

效果：

- 当单个条目没有写 `System` 时，程序会优先使用这里的值

注意：

- `system` 是规则级字段
- `System` 是条目级字段

### `method`

这是 HTTP 请求方式。

常见值：

- `"get"`
- `"post"`

效果：

- `get`：直接请求远程地址
- `post`：附带 `data` 作为 JSON 请求体发送

建议：

- 绝大多数场景填 `get`
- 只有接口明确要求 `POST` 时再填 `post`

### `headers`

这是附加请求头。

示例：

```json
{
  "Referer": "https://example.com/",
  "Origin": "https://example.com"
}
```

适用场景：

- 某些接口需要 `Referer`
- 某些站点要校验 `Origin`
- 某些接口需要鉴权头

如果不需要，直接写空对象：

```json
{}
```

### `data`

这是 `POST` 时发送的 JSON 数据。

示例：

```json
{
  "system": "10",
  "arch": "x64"
}
```

如果你用的是 `get`，通常写空对象即可：

```json
{}
```

### `SizeUnit`

这是当前规则里 `Size` 字段的单位。

常见值：

- `"B"`
- `"KB"`
- `"MB"`
- `"GB"`

效果：

- 决定 `Size` 应该如何理解
- 比如 `Size: "6.49"` 配合 `SizeUnit: "GB"`，表示 6.49 GB

建议：

- 一整个文件里保持同一种单位
- 不要同一个文件一部分写 MB、一部分写 GB

### `timeout`

这是请求超时时间，单位毫秒。

常见值：

- `8000`
- `10000`
- `15000`

效果：

- 值越大，等待远程接口返回的时间越长

建议：

- 普通 JSON 接口一般 `8000` 就够
- 网页文本、慢站点、带校验的站点可以适当加到 `15000`

## 模式一：`items`

这是最容易理解的写法。

含义：

- 你直接把最终可下载项写进 JSON
- 程序不再去远程接口“找数据”
- 程序只负责读取这些条目并展示或下载

适合场景：

- 固定下载地址
- 固定种子或磁力链接
- 你已经手动整理好了镜像清单

### 最小示例

```json
{
  "Source": "win10-zh-cn",
  "Rank": 9,
  "Enabled": true,
  "SizeUnit": "GB",
  "items": {
    "Windows 10 Consumer Editions": {
      "System": "10",
      "Name": "Windows 10 Consumer Editions Version 22H2 64-bit",
      "FileName": "zh-cn_windows_10_consumer_editions_x64.iso",
      "Language": "zh-cn",
      "Arch": "64",
      "Size": "6.49",
      "hash": {
        "SHA1": "A39FCDD7909F0FB83EBD2831526E6691413262A0"
      },
      "link": {
        "type": "url",
        "link1": "https://example.com/win10.iso"
      }
    }
  }
}
```

### `items` 里的每一项代表什么

`items` 是一个对象。

对象里的每个子项都代表“一个最终可下载项”。

例如：

```json
"items": {
  "Windows 10 Consumer Editions": { ... },
  "Windows 10 Business Editions": { ... }
}
```

这里的：

- `Windows 10 Consumer Editions`
- `Windows 10 Business Editions`

是条目的键名。它通常会作为条目 ID 使用。

### 条目字段说明

| 字段 | 是否常用 | 说明 |
| --- | --- | --- |
| `System` | 常用 | 该镜像属于哪个系统版本 |
| `Name` | 常用 | 展示名称 |
| `FileName` | 很常用 | 下载后的建议文件名 |
| `Description` | 可选 | 说明文字 |
| `PublishDate` | 可选 | 发布日期 |
| `Language` | 常用 | 语言代码 |
| `Arch` | 常用 | 架构 |
| `Size` | 常用 | 文件大小，单位看 `SizeUnit` |
| `Edition` | 可选 | 版本或发行类型 |
| `ver` | 可选 | 版本号、构建号或版本标识 |
| `index` | 可选 | 镜像索引，常用于 WIM/ESD |
| `hash` | 建议 | 校验值 |
| `link` | 必填 | 下载地址信息 |
| `offset` | 仅 PE 场景常用 | 从 EXE 中剥离镜像时的偏移范围 |

### `System`

常见值：

- `"7"`
- `"8"`
- `"10"`
- `"11"`

效果：

- 告诉程序这个条目属于哪个目标系统

### `Name`

这是展示给用户看的名称。

建议：

- 写成完整可读的名字
- 让用户一眼看出版本、语言、架构

推荐写法：

- `Windows 10 Enterprise LTSC 2021 64-bit`
- `Windows 7 Ultimate with Service Pack 1 (English)`

### `FileName`

这是下载后的目标文件名。

效果：

- 会影响保存后的文件名
- 也常用于去重和排序

建议：

- 尽量使用真实文件名
- 带上语言、版本、架构信息

### `Language`

常见值：

- `"zh-cn"`
- `"en-us"`
- `"ja-jp"`

效果：

- 用于语言筛选
- 也方便用户辨认镜像内容

建议：

- 尽量使用标准语言代码

### `Arch`

常见值：

- `"32"`
- `"64"`
- `"x86"`
- `"x64"`
- `"arm64"`

建议：

- 优先写 `"32"`、`"64"`、`"arm64"`

效果：

- 程序会按架构做归一化
- 同一来源下混填 `x64` 和 `64` 虽然通常能识别，但不够整齐

### `Size`

这是文件大小。

写法：

- 可以是数字
- 也可以是字符串形式的数字

示例：

```json
"Size": "6.49"
```

配合：

```json
"SizeUnit": "GB"
```

表示 6.49 GB。

### `Edition`

用来说明发行类型、SKU 或渠道。

示例：

- `Consumer Editions`
- `Business Editions`
- `LTSC`
- `Professional`

### `ver`

用来表示版本号或构建标识。

示例：

- `"22H2"`
- `"7601.24214"`
- `"2021"`

效果：

- 有些来源会用它帮助排序或展示

### `index`

当镜像内部有多个可安装映像时，可以用它指定索引。

常见值：

- `-1`
- `1`
- `2`

一般理解：

- `-1`：不指定
- 正整数：指定某个映像索引

### `hash`

这是校验信息。

支持的子字段：

- `SHA1` 或 `Sha1`
- `SHA256` 或 `Sha256`
- `MD5`

示例：

```json
"hash": {
  "SHA1": "A39FCDD7909F0FB83EBD2831526E6691413262A0",
  "MD5": "32FA102F277B242C2E37135014CA1200"
}
```

建议：

- 能填就填
- 新规则尽量统一写法，优先用 `Sha1`、`Sha256`、`MD5`

### `link`

这是下载信息，几乎是最重要的字段。

支持的子字段：

- `type`
- `link1`
- `link2`
- `link3`

常见 `type`：

- `"url"`：普通下载链接
- `"bt"`：磁力或种子类链接

示例 1：普通直链

```json
"link": {
  "type": "url",
  "link1": "https://example.com/win10.iso"
}
```

示例 2：多个镜像站

```json
"link": {
  "type": "url",
  "link1": "https://mirror1.example.com/winpe.exe",
  "link2": "https://mirror2.example.com/winpe.exe"
}
```

示例 3：磁力链接

```json
"link": {
  "type": "bt",
  "link1": "magnet:?xt=urn:btih:..."
}
```

效果：

- `link1` 通常是首选地址
- `link2`、`link3` 可以作为备用地址

### `offset`

这个字段主要给 PE 场景用。

含义：

- 某些 PE 来源提供的是 EXE 安装包
- 程序需要从这个 EXE 里剥离出真正的镜像数据
- `offset` 用来告诉程序镜像数据在 EXE 里的起止位置

格式：

```json
"offset": "0x2071A4 | 0xD3B8DFE"
```

建议：

- 普通 Windows ISO 来源不要填
- 只有你明确知道它是“从 EXE 提取镜像”时再填

## 模式二：`rules`

这个模式适合“远程接口返回 JSON，程序再按字段取值”的场景。

你可以把它理解成：

1. 先请求远程接口
2. 再按你写的路径把字段提取出来
3. 组装成最终镜像条目

### 最小示例

```json
{
  "Source": "win10-ms",
  "Rank": 9,
  "Enabled": true,
  "system": "10",
  "url": {
    "url1": "https://example.com/api/win10"
  },
  "method": "get",
  "headers": {},
  "data": {},
  "SizeUnit": "B",
  "timeout": 8000,
  "rules": {
    "FileName": "$.data[number].FileName",
    "Language": "$.data[number].LanguageCode",
    "Edition": "$.data[number].Edition",
    "Arch": "$.data[number].Architecture",
    "Size": "$.data[number].Size",
    "hash": {
      "Sha1": "$.data[number].Sha1"
    },
    "link": {
      "link1": "$.data[number].FilePath"
    },
    "ver": "$.data[number].VerCode",
    "index": -1
  }
}
```

### `url`

这是“远程地址集合”。

写法：

```json
"url": {
  "url1": "https://example.com/api1",
  "url2": "https://example.com/api2"
}
```

效果：

- 可以配置一个或多个远程接口
- 多个接口都解析成功时，结果会合并

建议：

- 主地址放 `url1`
- 备用地址放 `url2`、`url3`

### `rules` 里能写什么

`rules` 表示“如何从远程 JSON 里取值”。

可用字段通常和 `items` 模式下的条目字段一致：

- `System`
- `Name`
- `FileName`
- `Description`
- `PublishDate`
- `Language`
- `Arch`
- `Size`
- `Edition`
- `ver`
- `index`
- `hash`
- `link`

示例：

```json
"rules": {
  "FileName": "$.data[number].FileName",
  "Language": "$.data[number].LanguageCode",
  "Arch": "$.data[number].Architecture",
  "Size": "$.data[number].Size",
  "hash": {
    "Sha1": "$.data[number].Sha1"
  },
  "link": {
    "link1": "$.data[number].FilePath"
  }
}
```

### 可以直接写固定值吗

可以。

例如：

```json
"rules": {
  "System": "10",
  "Arch": "64",
  "link": {
    "type": "url",
    "link1": "$.data[number].FilePath"
  }
}
```

这里：

- `System` 永远是固定值 `"10"`
- `Arch` 永远是固定值 `"64"`
- `link1` 从远程 JSON 动态读取

### 路径语法怎么写

`rules` 模式里，路径不是标准 JSONPath，而是本项目自己的简化语法。

支持的常见写法：

- `$`：根对象
- `$.data`：取根对象里的 `data`
- `$.data[0]`：取数组第 0 项
- `$.data[number]`：取当前遍历到的这一项
- `$.win10[key]`：取当前遍历到的对象键名

#### 常见例子

```json
"FileName": "$.data[number].FileName"
```

意思是：

- 远程 JSON 里有个 `data` 数组
- 程序遍历 `data`
- 每一项都取它的 `FileName`

再比如：

```json
"Sha1": "$.data[number].Sha1"
```

意思是：

- 对当前这条数据，取它的 `Sha1`

### `[number]` 和 `[key]` 是什么

这是最容易混淆的地方。

#### `[number]`

表示“当前遍历到的这一项的值”。

常用于数组遍历：

```json
"FileName": "$.data[number].FileName"
```

#### `[key]`

表示“当前遍历到的这一项的键名”。

常用于对象遍历。

例如远程 JSON 是：

```json
{
  "win10": {
    "Windows 10 Consumer": {
      "file": "a.iso",
      "arch": "64"
    }
  }
}
```

如果程序遍历 `$.win10`：

- `$.win10[key]` 得到 `Windows 10 Consumer`
- `$.win10[number].file` 得到 `a.iso`
- `$.win10[number].arch` 得到 `64`

### 路径写错会怎样

通常表现为：

- 某个字段取不到值
- 条目内容不完整
- 最终没有产生可用结果

建议排查顺序：

1. 先确认远程 JSON 实际结构
2. 再确认路径大小写是否正确
3. 再确认当前遍历层级是否写对

## 模式三：`parser = "section_kv_group_v1"`

这个模式适合解析“分段文本”。

典型场景：

- 远程内容不是 JSON
- 页面内容更像配置文件
- 每段像 `[PEX64]`
- 段里再出现 `PE1Name=...`、`PE1Url=...` 这种字段

### 最小示例

```json
{
  "Source": "easyrc-PE",
  "Rank": 9,
  "Enabled": true,
  "parser": "section_kv_group_v1",
  "url": {
    "url1": "https://example.com/pe.txt"
  },
  "method": "get",
  "headers": {},
  "data": {},
  "SizeUnit": "MB",
  "timeout": 15000,
  "sections": {
    "PEX64": {
      "Arch": "64"
    },
    "PEX86": {
      "Arch": "32"
    }
  },
  "group": {
    "key_regex": "^PE(?P<num>[0-9]+)(?P<field>Name|Url|Url2|MS)$",
    "allowed_numbers": ["1", "2"],
    "required_fields": ["Name", "Url", "MS"]
  },
  "extract": {
    "Description": {
      "from": "Meta",
      "regex": "^(.*?)\\\\N发布时间:"
    },
    "PublishDate": {
      "from": "Meta",
      "regex": "发布时间:(\\d{4}-\\d{2}-\\d{2})"
    },
    "Size": {
      "from": "Meta",
      "regex": "大小:(\\d+(?:\\.\\d+)?)MB",
      "type": "float"
    }
  }
}
```

### `parser`

当前这个模式固定写：

```json
"parser": "section_kv_group_v1"
```

不要自己改成别的名字，除非程序已经支持。

### `sections`

这个字段用来指定“要解析哪些分段”以及“这个分段的默认字段”。

示例：

```json
"sections": {
  "PEX64": {
    "Arch": "64"
  },
  "PEX86": {
    "Arch": "32"
  },
  "XPPE": {
    "Arch": "32"
  }
}
```

效果：

- 解析到 `PEX64` 段时，默认给该段条目加上 `Arch: 64`
- 解析到 `PEX86` 段时，默认给该段条目加上 `Arch: 32`

适用场景：

- 某些属性并不写在每条记录上，而是由整个分段决定

### `group`

这个字段决定“如何把一组文本键拼成一条记录”。

例如远程文本里有：

```text
PE1Name=xxx
PE1Url=https://...
PE1MS=说明
PE2Name=yyy
PE2Url=https://...
PE2MS=说明
```

你需要告诉程序：

- `PE1Name`、`PE1Url`、`PE1MS` 属于同一条记录
- `PE2Name`、`PE2Url`、`PE2MS` 属于另一条记录

示例：

```json
"group": {
  "key_regex": "^PE(?P<num>[0-9]+)(?P<field>Name|Url|Url2|MS)$",
  "allowed_numbers": ["1", "2"],
  "required_fields": ["Name", "Url", "MS"]
}
```

#### `key_regex`

这是分组规则的核心。

作用：

- 把 `PE1Name` 拆成“编号 1 + 字段 Name”
- 把 `PE2Url` 拆成“编号 2 + 字段 Url”

只有当远程字段名风格很固定时，这种写法才好用。

#### `allowed_numbers`

表示“只保留哪些编号”。

示例：

```json
"allowed_numbers": ["1", "2"]
```

效果：

- 只解析 `PE1`、`PE2`
- `PE3`、`PE4` 即使存在也忽略

如果你想全部保留，通常可以不填这个字段。

#### `required_fields`

表示“缺了这些字段就丢弃整条记录”。

示例：

```json
"required_fields": ["Name", "Url", "MS"]
```

效果：

- 如果某组里没有 `Name`
- 或没有 `Url`
- 或没有 `MS`

那这一组就不生成结果。

### `field_map`

这个字段用来把远程原始字段映射成统一字段名。

示例：

```json
"field_map": {
  "Name": "Name",
  "Link1": "Url",
  "Link2": "Url2",
  "Description": "MS"
}
```

意思是：

- 最终的 `Name` 来自远程字段 `Name`
- 最终的 `Link1` 来自远程字段 `Url`
- 最终的 `Link2` 来自远程字段 `Url2`
- 最终的 `Description` 来自远程字段 `MS`

如果远程字段名本来就正好是常见写法，有时可以省略这个字段。

### `extract`

这个字段用来“从一大段文本里再抠出更细的字段”。

典型场景：

- 远程返回一段说明文字
- 说明文字里同时包含描述、发布日期、大小
- 你想再用正则把这些信息拆出来

示例：

```json
"extract": {
  "Description": {
    "from": "Meta",
    "regex": "^(.*?)\\\\N发布时间:"
  },
  "PublishDate": {
    "from": "Meta",
    "regex": "发布时间:(\\d{4}-\\d{2}-\\d{2})"
  },
  "Size": {
    "from": "Meta",
    "regex": "大小:(\\d+(?:\\.\\d+)?)MB",
    "type": "float"
  }
}
```

#### `from`

表示从哪个字段的文本里提取。

常见来源：

- `Meta`
- `Description`
- `MS`

#### `regex`

表示用什么正则提取值。

建议：

- 尽量写一个明确、稳定的表达式
- 如果用了捕获组，通常取第一个捕获组

#### `type`

可选值：

- `"int"`
- `"float"`

不写时，默认按字符串处理。

效果：

- `"int"`：把提取结果转成整数
- `"float"`：把提取结果转成小数

## `image-sources` 和 `pe-sources` 的区别

两者格式非常像，但用途不同。

### `image-sources`

通常放：

- Windows ISO
- WIM
- ESD
- 微软原版镜像
- 整理好的第三方镜像列表

### `pe-sources`

通常放：

- PE 的 boot.wim
- 可直接下载的 PE 镜像
- 需要从 EXE 里提取 boot.wim 的 PE 包

`pe-sources` 更容易用到这些字段：

- `offset`
- 多个镜像站 `link1` / `link2`
- 文本解析模式



## 下划线注释字段是什么

你会在一些 JSON 里看到：

- `_`
- `_1`
- `_2`

这些通常只是注释字段。

效果：

- 它们主要用于说明配置
- 一般不参与实际逻辑

建议：

- 可以保留
- 也可以改成你自己能看懂的说明
- 但不要把真正的配置写到这些字段里

## 推荐写法

如果你是第一次写规则，优先按下面的习惯来：

1. 每个规则文件都显式写 `Source`
2. 每个规则文件都显式写 `Rank`
3. 每个规则文件都显式写 `Enabled`
4. 静态清单优先用 `items`
5. 一个规则文件尽量只放同一类来源
6. 一种语言尽量单独放一个文件
7. 能填校验值就填 `hash`
8. 普通 ISO 不要乱填 `offset`

## 常见错误

### 1. `items` 里没有 `link`

后果：

- 条目可能无法下载
- 结果可能被视为无效

### 2. `Size` 和 `SizeUnit` 对不上

例如：

- `Size` 写的是 GB 数字
- `SizeUnit` 却写成了 `MB`

后果：

- 展示大小不对
- 进度和体积判断可能不准确

### 3. `rules` 路径写错

后果：

- 远程接口明明有数据，但解析不到

### 4. 把 `offset` 用在普通 ISO 上

后果：

- 没必要
- 还会增加维护成本

### 5. 把注释写进真正字段

例如：

```json
"Rank": "这个来源优先级高"
```

这就是错误写法。

`Rank` 必须写数字，不要把说明文字填到配置字段里。

## 该改哪个目录

按需求判断：

- 加 Windows 镜像来源：改 `image-sources`
- 加 PE 下载来源：改 `pe-sources`

## 最后给一个判断规则

如果你手里的数据是：

- “我已经有最终下载链接了” -> 用 `items`
- “我有一个返回 JSON 的接口” -> 用 `rules`
- “我只有一个网页文本或分段文本来源” -> 用 `section_kv_group_v1`
