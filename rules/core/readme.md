# 内置规则

- `image-sources`：系统镜像来源规则
- `pe-sources`：PE 来源规则
- `workflows`：工作流规则

当前已存在的典型规则：

- `PE-direct.json`：PE 直链规则
- `easyrc.json`：解析 EasyRC 的分段键值文本
- `win10-ms.json` / `win11-ms.json`：解析微软下载接口
- `win*-zh-cn1.json`：解析 `Windows.json` 中的第三方镜像
- `direct/*.json`：无需远程解析的直链规则

## 通用约定

- 空字符串 `""` 表示该字段不需要解析，解析器应直接返回空值，不报错。
- 规则文件中的路径是自定义 DSL，不是标准 JSONPath。
- 路径不存在时返回空字符串，不报错。
- 当 `parser` 被显式指定时，解析器优先按 `parser` 分支处理，不再要求同时存在 `items` 或 `rules`。
- `link.type` 可选；未填写时默认值为 `url`。
- `system` / `System` 表示目标系统代号，例如 `7`、`8`、`10`、`11`。
- `SizeUnit` 表示当前规则中 `Size` 的单位，可用值至少包括 `B`、`KB`、`MB`、`GB`。
- `timeout` 单位为毫秒。

## 三种规则模式

### 1. 解析模式

适用于需要先请求远程 JSON，再按规则提取字段。

常见字段：

- `system`：目标系统代号，比如"10","8"...
- `url`：待请求的接口地址集合
- `method`：`get` 或 `post`,如果下载的link链接是bt这个将会失效
- `headers`：请求头
- `data`：`post` 请求提交的数据
- `SizeUnit`：当前规则中 `Size` 的单位
- `timeout`：请求超时，单位毫秒
- 遇到带简单 JS Cookie 校验的站点时，建议把 `timeout` 设得稍高一些，例如 `15000`
- `rules`：字段提取规则

### 2. 直链模式

适用于本文件已经直接给出最终下载项，不需要再请求远程接口。

常见字段：

- `method` / `headers` / `data` / `timeout`：可保留通用结构，但解析器可忽略
- `SizeUnit`：当前规则中 `Size` 的单位
- `items`：最终下载项集合

### 3. 文本分段模式

适用于像 `PEDownload.html` 这类“按 `[Section]` 分段，再用 `key=value` 组织内容”的文本接口。

当前内置解析器：

- `section_kv_group_v1`

常见字段：

- `parser`：固定写 `section_kv_group_v1`
- `url`：待请求的文本地址集合
- `method`：通常为 `get`
- `SizeUnit`：当前规则中 `Size` 的单位
- `timeout`：请求超时，单位毫秒
- `sections`：需要解析的段名，以及该段的默认字段
- `group`：如何把 `PE1Name`、`PE1Url`、`PE1MS` 这类键聚合成一条结果
- `field_map`：把分组里的原始字段名映射到统一字段名；未填写时使用默认映射
- `extract`：从说明文本中进一步提取描述、发布日期、大小等字段

`sections` 示例：

```json
{
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

`group` 示例：

```json
{
  "key_regex": "^PE(?P<num>[0-9]+)(?P<field>Name|Url|Url2|MS)$",
  "allowed_numbers": ["1", "2"],
  "required_fields": ["Name", "Url", "MS"]
}
```

含义：

- `key_regex`：把 `PE1Name` 这类键拆成“编号 + 字段名”
- `allowed_numbers`：只保留指定编号，例如只解析 `PE1`、`PE2`
- `required_fields`：缺少这些字段的分组将被丢弃

`field_map` 默认值：

```json
{
  "Name": "Name",
  "Link1": "Url",
  "Link2": "Url2",
  "Meta": "MS"
}
```

如果远端字段名正好就是 `Name / Url / Url2 / MS`，可以不写 `field_map`。

`extract` 示例：

```json
{
  "Description": {
    "from": "Meta",
    "regex": "^(.*?)\\\\N发布日期:"
  },
  "PublishDate": {
    "from": "Meta",
    "regex": "发布日期:(\\d{4}-\\d{2}-\\d{2})"
  },
  "Size": {
    "from": "Meta",
    "regex": "大小:(\\d+(?:\\.\\d+)?)MB",
    "type": "float"
  }
}
```

含义：

- `from`：从哪个字段取原始文本，可引用 `field_map` 结果或原始字段名
- `regex`：用正则提取目标值；如果有捕获组，默认取第一个捕获组
- `type`：可选，支持 `int`、`float`；未填写时按字符串处理

一个完整示例：

```json
{
  "parser": "section_kv_group_v1",
  "url": {
    "url1": "https://www.51cxsoft.com/EasyRC/PEDownload.html"
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
    },
    "XPPE": {
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
      "regex": "^(.*?)\\\\N发布日期:"
    },
    "PublishDate": {
      "from": "Meta",
      "regex": "发布日期:(\\d{4}-\\d{2}-\\d{2})"
    },
    "Size": {
      "from": "Meta",
      "regex": "大小:(\\d+(?:\\.\\d+)?)MB",
      "type": "float"
    }
  }
}
```

## 路径语法

### 根节点

- `$` 表示 JSON 根对象

### 普通取值

- `$.data`
- `$.data[0].FileName`
- `$.win10`

### 数组遍历

- `[number]` 表示当前遍历到的数组下标
- `[0]`、`[1]` 这类写法表示固定下标

示例：

- `$.data[number].FileName`
- `$.data[number].Sha1`

### 对象遍历

对象遍历时，需要同时支持“当前键名”和“当前键对应的值对象”：

- `[key]` 表示当前对象项的键名
- `[number]` 表示当前对象项的值对象

也就是说，在下面这种结构中：

```json
{
  "win10": {
    "Windows 10 xxx": {
      "arch": "64",
      "file": "a.iso"
    }
  }
}
```

当遍历 `$.win10` 时：

- `$.win10[key]` 得到 `Windows 10 xxx`
- `$.win10[number].arch` 得到 `64`
- `$.win10[number].file` 得到 `a.iso`

`[key]` 和 `[number]` 必须指向同一轮遍历中的同一项，不能分离。

## `items` 字段说明

`items` 模式下，每个子项都是一个最终可下载项。

推荐字段：

- `System`：目标系统代号
- `Name`：显示名称
- `FileName`：下载后文件名
- `Description`：说明文本
- `PublishDate`：发布日期
- `Language`：语言代码，例如 `zh-cn`、`en-us`
- `Arch`：架构，例如 `32`、`64`
- `Size`：文件大小，单位由 `SizeUnit` 决定
- `Edition`：发行信息
- `ver`：版本号或版本标识
- `index`：安装镜像时选择的index
- `hash`：校验信息，支持 `Sha1`、`Sha256`、`MD5`
- `link`：下载链接集合
- `offset`：目前微pe专属，仅用于从exe文件中剥离镜像时的偏移范围，格式为 `起始 | 结束`

`link` 子字段：

- `type`：`url` 或 `bt`
- `link1`、`link2`...：候选下载链接

## `rules` 字段说明

`rules` 模式下，每个字段都表示“如何从远程 JSON 中取值”。

推荐字段：

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

`hash` 子字段：

- `Sha1`
- `Sha256`
- `MD5`

`link` 子字段：

- `type`
- `link1`、`link2`...

## 约束建议

- `hash` 字段名建议统一使用 `Sha1`、`Sha256`、`MD5`，不要混用 `SHA1` / `sha1`。
- 非 微PE 的镜像直链规则通常不应填写 `offset`。
- 如果规则文件标记了某种语言，例如 `zh-cn`，则文件内容最好只包含该语言条目；混入其它语言时，建议拆到单独规则文件。
- 同一类规则尽量保持字段齐全，例如 `index`、`link.type`、`hash` 子键名统一，避免解析器里写特判。
