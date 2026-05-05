# data

`src/data` 是面向镜像源和 WinPE 源的规则加载与规范化层。

该包主要负责三件事：

1. 从 `rules/core/image-sources` 和 `rules/core/pe-sources` 加载规则文件。
2. 将多种规则格式解析为统一的数据模型。
3. 对解析结果进行排序、规范化和去重，供后续安装与下载代码使用。

如果需要回答以下问题，应优先阅读该包：

* 可安装镜像候选项来自哪里？
* 一个 JSON 规则文件如何转换成 `RuleItem`？
* 为什么某个来源覆盖了另一个来源？
* 为什么重命名后的 JSON 文件仍然会被加载？
* WinPE 源选择与普通镜像选择有什么不同？

## 范围

该包负责：

* 规则目录发现
* 递归收集 JSON 文件
* 解析规则文件
* 通过 HTTP 或 PowerShell 获取动态规则
* 解码非 UTF-8 响应文本
* 将不同规则格式转换为 `RuleItem`
* 将通用规则项转换为 `WinPEImg`
* 稳定排序与去重

该包不负责：

* 实际下载镜像文件
* 校验下载文件哈希
* 挂载、应用或安装镜像
* UI 展示
* 持久化缓存已解析的规则结果

## 文件

* [Data.go](/C:/Users/Administrator/Desktop/ReSys/src/data/Data.go)：目录扫描、聚合、规范化、排序、WinPE 转换与选择
* [parser.go](/C:/Users/Administrator/Desktop/ReSys/src/data/parser.go)：单个规则解析、远程获取逻辑、路径 DSL、文本提取与规则项构建

## 公共 API

### `GetInstallImageItems(system string) ([]RuleItem, error)`

加载某个目标 Windows 版本的全部镜像源规则。

行为：

* 将输入的系统名称规范化为 `7`、`8`、`10`、`11` 之一
* 扫描 `rules/core/image-sources/<system>`
* 递归解析每个 `.json` 文件
* 跳过已禁用文件
* 规范化每个条目
* 对镜像候选项去重
* 按稳定优先级排序

可接受的输入示例：

* `7`
* `win7`
* `windows7`
* `win10-x64`

只使用主系统版本号。例如，`win10-x64` 仍会解析到 `image-sources/10` 目录。

### `RuleItemFileName(it RuleItem, ln string) string`

返回镜像候选项的推荐输出文件名。

优先级如下：

1. `RuleItem.FileName`
2. 下载 URL 中的 basename
3. 如果链接只暴露扩展名，则使用 `windows_image.<ext>`
4. `windows_image.iso`

### `GetWinPE() ([]WinPEImg, error)`

从 `rules/core/pe-sources` 加载并返回全部 PE 候选项。

行为：

* 递归扫描 PE 规则树
* 解析每个规则文件
* 将通用 `RuleItem` 转换为 `WinPEImg`
* 将 `Offset` 解析为 `OffsetStart` 和 `OffsetEnd`
* 根据规则路径分配分组名称
* 对候选项去重并排序

### `PELnk() (string, float64, []string, error)`

返回适合当前机器架构的首选 PE 候选项。

选择策略：

1. 加载并排序所有 PE 候选项
2. 优先选择与 `winos.SystemArch()` 匹配的架构
3. 如果没有精确匹配，则回退到排序后的第一个候选项

### `ParseRuleFile(rulePath string) (*RuleParseResult, error)`

解析单个规则文件，并返回文件级元数据及其规范化后的条目。

调试单个 JSON 规则时，这是最合适的入口。

### `ParseRuleItems(rulePath string) ([]RuleItem, error)`

`ParseRuleFile` 的便捷封装。适用于只需要规范化条目的场景。

### `ParseRuleWinPEs(rulePath string) ([]WinPEImg, error)`

`ParseRuleItems` 的便捷封装，并额外将每个条目转换为 WinPE 专用结构。

## 核心数据模型

### `RuleItem`

`RuleItem` 是该包范围内统一的规范化模型。所有规则格式最终都会收敛到这个结构。

重要字段：

| 字段            | 含义                             |      |
| ------------- | ------------------------------ | ---- |
| `ID`          | 规则文件内的条目标识                     |      |
| `Source`      | 逻辑来源名称                         |      |
| `Rank`        | 文件级优先级，会复制到每个条目上               |      |
| `System`      | 目标系统代码，例如 `7`、`10`、`11`        |      |
| `Name`        | 面向用户的显示名称                      |      |
| `FileName`    | 推荐文件名                          |      |
| `Description` | 可选描述                           |      |
| `PublishDate` | 可选发布日期字符串                      |      |
| `Language`    | 语言标签，例如 `zh-cn` 或 `en-us`      |      |
| `Arch`        | 规范化后的架构                        |      |
| `Size`        | 数值形式的大小                        |      |
| `SizeUnit`    | `Size` 的单位，通常是 `B`、`MB` 或 `GB` |      |
| `Edition`     | 可选版本名称                         |      |
| `Ver`         | 可选版本字符串                        |      |
| `Index`       | 可选镜像索引或排序提示                    |      |
| `Hash`        | SHA1、SHA256 或 MD5 元数据          |      |
| `Link`        | 链接类型，以及一个或多个 URL 或磁力链接         |      |
| `Offset`      | 仅 PE 使用的偏移文本，例如 `start         | end` |

### `RuleHash`

附加在规则条目上的哈希元数据。

支持字段：

* `Sha1`
* `Sha256`
* `MD5`

### `RuleLink`

附加在规则条目上的下载元数据。

支持字段：

* `Type`
* `Links`

如果省略 `Type`，默认值为 `url`。

### `WinPEImg`

`WinPEImg` 是 PE 选择和下载代码使用的 PE 专用输出结构。

除 `RuleItem` 字段外，还包含：

* `Grp`：根据规则路径派生出的分组名称
* `OffsetStart`
* `OffsetEnd`

## 目录布局与扫描规则

镜像规则位于：

```text
rules/core/image-sources/<system>/
```

PE 规则位于：

```text
rules/core/pe-sources/
```

目录扫描规则：

* 递归扫描
* 包含所有扩展名为 `.json` 的文件
* 解析前按路径排序
* 解析后跳过已禁用文件
* 文件名本身不是查找键

最后一点很重要：该包不会按名称查找 `win7-en-us1.json`。它会扫描目录，并解析找到的所有 JSON 文件。

## 规则文件生命周期

该包分两层处理规则文件。

### 第 1 层：目录聚合

[Data.go](/C:/Users/Administrator/Desktop/ReSys/src/data/Data.go:321) 中的 `loadRules` 负责：

* 遍历目录树
* 使用 `ParseRuleFile` 解析每个文件
* 跳过 `Enabled == false` 的文件
* 跳过未生成任何条目的文件
* 按 `Rank`、`Source` 和路径排序聚合后的来源

这一层不关心具体规则格式的细节。

### 第 2 层：单文件解析

[parser.go](/C:/Users/Administrator/Desktop/ReSys/src/data/parser.go:133) 中的 `ParseRuleFile` 负责处理单个 JSON 文件。

解析前应用的默认值：

* `method`：默认 `GET`
* `SizeUnit`：默认 `B`
* `timeout`：默认 `8000` 毫秒
* `Enabled`：默认 `true`
* `Source`：省略时默认使用文件 basename

模式选择规则：

1. 如果设置了 `parser`，使用对应的命名解析器模式
2. 否则如果存在 `items`，使用直接条目模式
3. 否则如果存在 `rules`，使用动态 JSON 映射模式
4. 否则返回错误

## 支持的规则模式

当前支持三种规则模式。

## 1. `items` 模式

这是最简单的规则格式。JSON 文件中已经包含了具体条目对象。

适用场景：

* 来源是静态的
* 不需要远程请求
* 希望规则具备最高可读性

最小示例：

```json
{
  "Source": "win7-en-us1",
  "Rank": 9,
  "Enabled": true,
  "SizeUnit": "GB",
  "items": {
    "Windows 7 Ultimate": {
      "System": "7",
      "Name": "Windows 7 Ultimate with Service Pack 1 (x64)",
      "FileName": "win7sp1_x64_en-us.iso",
      "Language": "en-us",
      "Arch": "64",
      "Size": "5.47",
      "hash": {
        "SHA1": "7CC76B0015220DE956328FB934D61B710A94293D"
      },
      "link": {
        "type": "bt",
        "link1": "magnet:?xt=urn:btih:..."
      }
    }
  }
}
```

实现说明：

* `items` 下的每个 key 会成为默认 `ID`
* 每个 value 必须是 JSON 对象
* 如果条目省略 `System`，则回退到文件级 `system`
* `Description` 接受别名 `Desc`
* `PublishDate` 接受别名 `Date`
* `Ver` 接受别名 `ver` 或 `Ver`

## 2. `rules` 模式

该模式会获取远程 JSON，并将字段映射到 `RuleItem`。

适用场景：

* 上游来源提供结构化 JSON
* 条目列表会随时间变化
* 需要远程驱动的数据源，但不想编写自定义 Go 代码

最小示例：

```json
{
  "Source": "example-api",
  "Rank": 8,
  "system": "10",
  "method": "get",
  "url": {
    "primary": "https://example.test/images.json"
  },
  "SizeUnit": "GB",
  "rules": {
    "Name": "$.data.items[number].title",
    "FileName": "$.data.items[number].file_name",
    "Language": "$.data.items[number].lang",
    "Arch": "$.data.items[number].arch",
    "Size": "$.data.items[number].size",
    "hash": {
      "Sha1": "$.data.items[number].sha1"
    },
    "link": {
      "type": "url",
      "link1": "$.data.items[number].url"
    }
  }
}
```

工作流程：

1. 读取并排序 `url` map 中的值
2. 获取每个远程 JSON 文档
3. 从第一个包含 `[number]` 或 `[key]` 的动态路径推断迭代容器
4. 为每个数组元素或对象条目构建一个迭代上下文
5. 解析每个已配置字段
6. 对多个 URL 生成的条目去重

重要限制：

* 不支持通配符语法
* 迭代由 `[number]` 和 `[key]` 驱动
* 如果没有找到动态路径，则将根对象视为一个单独条目

## 3. `parser = "section_kv_group_v1"`

该模式会获取文本，将其拆分为 section，按编号 key/value 字段分组，然后构建条目。

适用场景：

* 上游来源是纯文本，而不是 JSON
* 数据以 key/value 块组织
* 相关值通过编号字段表达，例如 `PE1Name`、`PE1Url`、`PE2Name`

整体流程：

1. 获取远程文本
2. 解码 UTF-8 或 GBK
3. 将内容拆分为 `[Section]` 块
4. 解析每个 section 内的松散 `Key=Value` 键值对
5. 使用 `group.key_regex` 对编号字段进行分组
6. 每个分组构建一个 `RuleItem`
7. 可选地使用正则提取额外字段

最小示例：

```json
{
  "Source": "easyrc-pe",
  "Rank": 9,
  "parser": "section_kv_group_v1",
  "system": "10",
  "url": {
    "primary": "https://example.test/pe.txt"
  },
  "SizeUnit": "MB",
  "sections": {
    "WinPE": {
      "Arch": "64",
      "Language": "zh-cn"
    }
  },
  "group": {
    "key_regex": "^PE(?P<num>[0-9]+)(?P<field>Name|Url|Url2|MS)$",
    "required_fields": ["Name", "Url"]
  },
  "field_map": {
    "Name": "Name",
    "Link1": "Url",
    "Link2": "Url2",
    "Description": "MS"
  },
  "extract": {
    "Ver": {
      "from": "Name",
      "regex": "([0-9]+(?:\\.[0-9]+)*)"
    }
  }
}
```

默认 `field_map` 值如下：

| 规范化字段   | 默认来源字段 |
| ------- | ------ |
| `Name`  | `Name` |
| `Link1` | `Url`  |
| `Link2` | `Url2` |
| `Meta`  | `MS`   |

## 根级规则字段

以下根字段在所有适用的规则模式中都可使用。

| 字段         | 是否必需 | 含义                         |
| ---------- | ---- | -------------------------- |
| `Source`   | 否    | 稳定的逻辑来源名称                  |
| `Rank`     | 否    | 优先级，数值越高优先级越高              |
| `Enabled`  | 否    | 该规则是否参与目录聚合                |
| `system`   | 否    | 条目的默认系统代码                  |
| `method`   | 否    | HTTP 方法，通常为 `get` 或 `post` |
| `headers`  | 否    | 额外 HTTP 请求头                |
| `data`     | 否    | `POST` 请求的 JSON 请求体        |
| `SizeUnit` | 否    | 生成条目的默认大小单位                |
| `timeout`  | 否    | 请求超时时间，单位为毫秒               |

`rules` 模式专用字段：

* `url`
* `rules`

section 解析器专用字段：

* `parser`
* `sections`
* `group`
* `field_map`
* `extract`

`items` 模式专用字段：

* `items`

## `Source`、`Rank` 和 `Enabled`

这三个元数据字段控制大部分聚合行为。

### `Source`

`Source` 是附加到文件并复制到其条目上的逻辑来源名称。

规则：

* 如果提供，则按原值使用
* 如果省略，则使用不带扩展名的 JSON 文件名
* 解析出的 `RuleItem.Source` 来自文件级元数据

建议：

* 将 `Source` 视为稳定标识符
* 除非有意绑定文件名，否则不要依赖文件名作为身份标识

### `Rank`

`Rank` 是来源优先级。数值越高，排序越靠前。

该包在以下场景使用 `Rank`：

* 聚合时的来源排序
* 镜像候选项排序
* PE 候选项排序
* 去重时的冲突处理，因为高优先级来源会先被看到

### `Enabled`

`Enabled` 控制某个规则文件是否参与目录聚合。

行为：

* 省略时表示启用
* `false` 表示该文件仍可被单独解析，但在目录聚合时会被 `loadRules` 跳过

## `rules` 模式使用的路径 DSL

该包不使用 JSONPath，而是使用自定义的小型路径语言。

支持语法：

| 语法                | 含义         |
| ----------------- | ---------- |
| `$`               | 根对象        |
| `$.field`         | 对象字段       |
| `$.field.sub`     | 嵌套字段       |
| `$.list[0]`       | 数组索引       |
| `$.items[number]` | 当前迭代项      |
| `$.items[key]`    | 当前迭代对象 key |

示例：

| 表达式                          | 结果           |
| ---------------------------- | ------------ |
| `$.data.items[number].title` | 当前条目的标题      |
| `$.data.items[number].url`   | 当前条目的 URL    |
| `$.data.catalog[key].sha1`   | 当前对象条目的 SHA1 |

重要语义：

* `[number]` 表示“当前迭代值”，不只是严格意义上的整数占位符
* `[key]` 只在迭代对象时有意义
* 动态路径解析失败会返回空值，而不是硬错误
* 容器路径本身必须成功解析，否则解析会失败

## HTTP 获取行为

动态规则可以获取远程数据。

请求行为：

* 支持 `GET` 和 `POST`
* `POST` 时将 `data` 序列化为 JSON
* 应用自定义 `headers`
* 如果未提供，会注入一个类似浏览器的默认 `User-Agent`
* 如果未提供，会注入 `Accept: */*`
* 使用毫秒级 `timeout`
* HTTP 请求失败时重试一次

验证 cookie 行为：

* 该包会在第一次响应中扫描 `document.cookie="..."`
* 如果找到，会提取第一个 cookie 键值对
* 然后携带该 cookie 重试请求

Windows 回退行为：

* 如果原生 Go HTTP 请求失败，该包会尝试使用 PowerShell `Invoke-WebRequest` 作为回退
* 该回退仅在 Windows 上可用

## 文本解码行为

基于文本的解析模式会调用 `decodeRuleText`。

行为：

* 如果响应是有效 UTF-8，则直接使用
* 否则尝试 GBK 解码
* 如果 GBK 解码失败，则回退到原始字节

这样做是因为部分上游规则源会返回旧式中文编码。

## 规范化规则

解析后，该包会规范化多个字段。

### 系统规范化

镜像加载时，用户输入会由 `normalizeSystemCode` 规范化。

可接受的最终值：

* `7`
* `8`
* `10`
* `11`

其他值会返回错误。

### 架构规范化

`normalizeArch` 会将常见别名映射为规范值。

映射关系：

* `arm64`、`aarch64` -> `arm64`
* `x64`、`amd64`、`64` -> `64`
* `x86`、`i386`、`32`、`86` -> `32`

### 链接规范化

* 移除空链接
* 移除重复链接
* 保留首次出现时的链接顺序
* 缺失的 `link.type` 默认为 `url`

## 排序与去重

理解排序很重要，因为该包会保留同一去重键下第一个出现的候选项。

### 来源排序

规则文件按以下顺序排序：

1. `Rank` 越高越靠前
2. `Source` 字典序越小越靠前
3. 规则路径

### 镜像条目去重键

镜像候选项按以下字段去重：

* 规范化后的 `Arch`
* `Link.Type`
* `Hash.Sha1`
* `FileName`
* `Index`
* 按顺序拼接后的全部链接值

以上字段相同的两个条目会被视为同一个镜像候选项。

### 镜像条目最终排序顺序

镜像候选项按以下规则排序：

1. `Rank` 越高越靠前
2. `Link.Type` 字典序越小越靠前
3. `Index` 越高越靠前
4. `FileName` 字典序越小越靠前
5. `Source` 字典序越小越靠前
6. 稳定条目 key

### PE 去重键

PE 候选项按以下字段去重：

* `Name`
* 规范化后的 `Arch`
* 链接列表
* `MD5`
* `OffsetStart`
* `OffsetEnd`

### PE 最终排序顺序

PE 候选项按以下规则排序：

1. `Rank` 越高越靠前
2. 从 `Ver` 或 `Name` 解析出的数值版本越高越靠前
3. `Name` 字典序越小越靠前
4. `Source` 字典序越小越靠前
5. 稳定 PE key

## WinPE 专用行为

PE 聚合相比普通镜像聚合多了几条规则。

### 分组派生

`peGroupFromRule` 会根据规则路径派生分组标签。

示例：

* `pe-sources/direct/a.json` -> `direct`
* `pe-sources/easyrc.json` -> `easyrc`

### Offset 解析

`Offset` 期望使用以下格式：

```text
start | end
```

行为：

* 缺失或不完整的偏移会被忽略
* 无效数字会在 PE 转换期间返回错误

## 错误处理模型

该包在目录级别有意保持容错。

### 目录级行为

扫描目录时：

* 单个错误规则文件不会立即终止整个扫描
* 错误会被累积
* 成功解析的文件仍会被使用
* 如果最终没有任何可用结果，则返回聚合错误

### 单文件行为

解析单个规则文件时：

* 无效 JSON 是致命错误
* 未知解析器名称是致命错误
* 缺少规则模式所需字段是致命错误
* 动态字段值缺失通常会变为空字符串，而不是错误

这种权衡让远程规则解析具有韧性，同时仍能暴露格式错误的规则定义。

## 给规则作者的实践建议

来源静态时，优先使用 `items` 模式。

以下情况使用 `rules` 模式：

* 上游 API 是 JSON
* schema 稳定
* 不需要自定义 Go 逻辑

以下情况使用 `section_kv_group_v1`：

* 上游来源是旧式文本
* 数据通过编号字段分组

建议：

* 始终显式设置 `Source`
* 始终显式设置 `Rank`
* 尽量让单个文件只包含一个语言系列
* 使用稳定的文件名和来源标识符
* 编写新规则时，将哈希字段名规范为 `Sha1`、`Sha256`、`MD5`
* 避免在一个文件中混合无关来源

## 调试提示

如果某个规则文件没有出现在聚合结果中，优先检查：

1. 文件是否位于正确的目录树下。
2. 扩展名是否仍为 `.json`。
3. `Enabled` 是否不是 `false`。
4. 文件是否至少生成了一个带文件名或链接的条目。
5. 是否已有另一个更高优先级规则命中了相同去重键。

如果 `rules` 模式文件返回零条目，检查：

1. 由 `[number]` 或 `[key]` 推断出的容器路径是否真实存在。
2. 远程 JSON 字段名是否仍与表达式匹配。
3. 解析出的链接是否非空。

如果某个 PE 规则被忽略，检查：

1. 该规则是否至少生成了一个链接。
2. `Offset` 是否为空，或可解析为 `start | end`。
3. 是否已有重复 PE 候选项更早被接受。

## 维护说明

该包刻意保持数据驱动。添加新的自定义 Go 解析器之前，先确认该来源确实无法用以下方式表达：

* `items`
* `rules`
* `section_kv_group_v1`

只有当来源形态本质上不同，无法通过现有 DSL 与提取步骤建模时，才应添加新的解析器模式。

## 相关代码

* [src/install/download.go](/C:/Users/Administrator/Desktop/ReSys/src/install/download.go)：消费 `RuleItem` 镜像源
* [rules/core/readme.md](/C:/Users/Administrator/Desktop/ReSys/rules/core/readme.md)：仓库级规则编写说明

## 快速参考

### 应该调用哪个函数？

| 需求                 | 函数                     |
| ------------------ | ---------------------- |
| 解析单个规则文件           | `ParseRuleFile`        |
| 只获取某个文件中的规范化条目     | `ParseRuleItems`       |
| 将某个规则文件转换为 PE 对象   | `ParseRuleWinPEs`      |
| 加载某个目标系统的全部安装镜像候选项 | `GetInstallImageItems` |
| 加载全部 PE 候选项        | `GetWinPE`             |
| 为当前机器选择首选 PE       | `PELnk`                |

### 应该使用哪种规则模式？

| 场景              | 推荐模式                  |
| --------------- | --------------------- |
| 静态 URL 或磁力链接列表  | `items`               |
| 远程 JSON API     | `rules`               |
| 旧式文本配置或 INI 类来源 | `section_kv_group_v1` |
