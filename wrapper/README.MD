copy /b wrapper.exe + config.txt + payload.7z Wrapper1.exe

## 1. 这份“配置文件”到底是什么？

该程序不是从磁盘上读取一个独立的 `xxx.ini` 或 `config.json`，而是**把配置文本直接拼接在可执行文件（EXE）尾部**，紧接着再拼接一个 7z payload（压缩包）。运行时，wrapper 会从自身文件末尾反向查找两段标记，从而定位配置与 payload。

- 配置块起始标记：

  ```text
  ;!@Install@!UTF-8!
  ```

- 配置块结束标记：

  ```text
  ;!@InstallEnd@!
  ```

- 结束标记后面去掉空白（空格/换行/Tab）紧跟的内容，会被当作 **7z 压缩包**。


---

## 2. 配置语法

### 2.1 编码与行

- **编码：必须为 UTF-8**（源码用 `MultiByteToWideChar(CP_UTF8)` 解码）。
- 行分隔：按 `\n` 分行解析（Windows 下 `CRLF` 也可，解析前后会 trim）。

### 2.2 注释与空行

- 空行会被忽略。
- 以 `;` 或 `#` 开头的行会被当作注释并忽略。

### 2.3 键值对与大小写

- 只识别形如 `Key = Value` 的行；没有 `=` 的行会被忽略。
- Key 大小写不敏感（`lstrcmpiW`），因此 `Path`、`path`、`PATH` 等价。
- Key/Value 两侧空白会被剔除。

### 2.4 引号与转义

对大多数 Value（除 `RunProgram` / `lnk` / `Platform` 这类“列表型”）会执行：

1) 去掉首尾空白；
2) 若整体被一对双引号包裹，会去掉外层 `"..."`；
3) 支持反斜杠转义（在文档中写成双斜杠仅为展示，实际文件里写单斜杠）：

- `\\`  -> `\`
- `\"` -> `"`
- `\n`  -> 换行
- `\r`  -> 回车
- `\t`  -> Tab

### 2.5 列表型值（CSV）

`RunProgram`、`lnk`、`Platform` 设计为支持用 **逗号分隔的列表（CSV 风格）**：

- 逗号`,`分隔多个条目；
- 条目可以用双引号包裹，以包含空白或逗号；
- 条目内部同样支持上述反斜杠转义；

示例：

```ini
RunProgram = "setup.exe", "tools\\post.exe"
```

---

## 3. 路径变量展开（Path / Directory 的“魔法”）

程序支持三类变量：

1) **环境变量**：通过 Windows `ExpandEnvironmentStringsW` 展开，例如 `%temp%`、`%USERPROFILE%`。
2) **自定义变量 `%working%`**：当前进程启动时的工作目录（`GetCurrentDirectoryW`）。
3) **自定义变量 `%located%`**：注意这个变量在不同字段里含义不同：

- 在 `Path` 字段中：`%located%` = wrapper.exe 所在目录（EXE Directory）。
- 在 `Directory` 字段中：`%located%` = 解压后的运行根目录 `runroot`（见下文 Platform 映射）。

这点很容易踩坑：同样写 `%located%`，在不同字段会展开成不同路径。

---

## 4. 配置项总览（按功能分组）

### 4.1 交互提示

#### `Title`
- 类型：字符串
- 作用：提示框标题。

#### `BeginPrompt`
- 类型：字符串
- 作用：提示框正文。
- 规则：只有当 `Title` 和 `BeginPrompt` **都非空**时，才会弹 `MessageBox(OK/CANCEL)`；用户点 Cancel 会直接退出。

示例：

```ini
Title = "安装提示"
BeginPrompt = "即将开始安装，是否继续？"
```

---

### 4.2 解压目录与复用策略

#### `Path`
- 类型：路径字符串（可含变量）
- 默认：`%temp%`
- 作用：解压根目录。

#### `PathName`
- 类型：目录名字符串
- 默认：`WrapperTemp`
- 作用：在 `Path` 下创建的子目录名，最终解压目录为：

  ```text
  outdir = <Path 展开后> \ <PathName>
  ```

- 额外规则：`PathName` 会被“净化”：过滤掉 Windows 不允许的文件名字符（如 `<>:"/\\|?*`），并去掉末尾的 `.` 或空格；若净化后为空，则回退为 `WrapperTemp`。

#### `cover`
- 类型：整数
- 默认：`0`
- 语义（源码注释是“0=覆盖；非0=跳过”）：
  - `0`：解压时若目标文件已存在，会覆盖写入。
  - 非 `0`：解压时若目标文件已存在，会跳过该文件（不覆盖）。

注意：如果 payload 与上次完全一致且已解压成功，wrapper 可能会整体跳过解压（根据 CRC+size 判断）。在这种“整体跳过”的情况下，`cover` 不参与决策。

---

### 4.3 日志

#### `log`
- 类型：整数
- 默认：`0`
- 语义：
  - `0`：启用日志（写文件 + OutputDebugString）。
  - 非 `0`：完全禁用日志（不写文件也不输出调试字符串）。

日志文件路径优先级：

1) `exe_dir\<exe_basename>.log`
2) 如果 1) 无法创建/写入，则使用：`%TEMP%\<exe_basename>_<pid>.log`

日志采用 UTF-16LE（带 BOM）。

---

### 4.4 运行与参数转发

wrapper 有两套执行路径：

- **单目标模式**：配置了 `ExecuteFile` 时走这一套；
- **列表模式**：否则走 `RunProgram` 列表（若列表为空默认 `setup.exe`）。

并且：**`ExecuteFile` 优先级高于 `RunProgram`**。

#### `ExecuteFile`
- 类型：路径（相对/绝对）
- 默认：空
- 作用：指定要启动的主程序。
- 路径解析：若为相对路径，则相对 `runroot` 解析。

#### `ExecuteParameters`
- 类型：字符串
- 默认：空
- 作用：追加到 `ExecuteFile` 的命令行后面。
- 注意：这里只是“拼字符串”，如果参数里需要引号，请自行在配置里写好并正确转义。

示例：

```ini
ExecuteFile = "bin\\installer.exe"
ExecuteParameters = "/S /D=\"%ProgramFiles%\\MyApp\""
```

#### `RunProgram`
- 类型：列表（CSV）
- 默认：空（运行时会自动补一个 `setup.exe`）
- 作用：依次启动列表中的程序。

**重要限制（来自源码的真实行为）**：

- 在当前实现中，`RunProgram` 条目更适合写“纯可执行文件路径/文件名”，不要在同一个条目里附带参数。
- 原因：执行时 wrapper 会把条目当作“路径”去解析生成 `exepath`，再组装为 `"exepath"` 或 `"exepath" <forward_tail>`，这会让“带参数的条目”被误当成文件名，导致找不到文件。

推荐：

- 需要“带参数运行一个程序”时，优先用 `ExecuteFile + ExecuteParameters`。
- `RunProgram` 用于串行/并行启动多个 **不带自定义参数** 的可执行文件。

#### `Directory`
- 类型：路径（可含变量）
- 默认：`.\\`
- 作用：`RunProgram` 模式下的工作目录。
- 解析规则：
  - 值为空或等价于 `.` / `.\\` / `./` 时，使用 `runroot`；
  - 相对路径：拼到 `runroot` 下；
  - 绝对路径：直接使用。

#### `Forward`
- 类型：整数（1-based）
- 默认：`0`
- 作用：把 wrapper 自身收到的命令行“尾巴参数”（也就是运行 wrapper 时传入的参数）追加转发到第 N 个 `RunProgram`。
- 规则：
  - `Forward <= 0`：不转发。
  - `Forward = 1`：转发给第 1 个 `RunProgram`。
  - 仅对 `RunProgram` 模式生效；`ExecuteFile` 模式不使用该逻辑。

#### `async`
- 类型：整数
- 默认：`0`
- 作用：控制 `RunProgram` 模式的等待策略。
  - `0`：同步等待（依次 `CreateProcess` 并等待退出码）。
  - 非 `0`：异步启动（不等待）。

注意：`async != 0` 时，会强制禁用 `Forward`（源码里直接把 `forward_index` 设为 -1）。

---

### 4.5 平台目录映射（Platform）

#### 目标
同一个 payload 中可能包含多个平台目录（例如 `win732/`、`win764/`、`win1064/`），wrapper 会先识别当前系统平台，然后把运行根目录 `runroot` 指向匹配的子目录。

#### 平台标签格式
运行时生成的 `platform_label` 形如：

- `Windows7 32`
- `Windows7 64`
- `Windows10 64`
- `Windows11 64`
- `Windows ARM64`（若系统为 ARM64）

匹配时会忽略空白并大小写不敏感。

#### `Platform`
- 类型：列表（CSV）
- 设计语义：每个条目形如：

  ```text
  <platform_label> : <subdir>
  ```

  其中 `<subdir>` 是相对 `outdir` 的目录名。

- 行为：
  - 找到匹配条目后，若 `outdir\subdir` 存在，则 `runroot = outdir\subdir`；
  - 若目录不存在或未匹配，则回退到 `runroot = outdir`。

示例：

```ini
Platform = "Windows7 32:win732", "Windows7 64:win764", "Windows10 64:win1064", "Windows11 64:win1164"
```

---

### 4.6 桌面快捷方式（lnk）

#### `lnk`
- 类型：列表（CSV）
- 设计语义：每个条目是一个四段式 spec：

  ```text
  <src>, <desc>, <linkname>, <iconfile>
  ```

- 字段说明：
  - `src`：快捷方式指向的目标路径；如果是相对路径，则相对 `outdir`。
  - `desc`：快捷方式描述。
  - `linkname`：桌面上的快捷方式文件名（可带或不带 `.lnk`，不带会自动补）。
  - `iconfile`：图标文件路径；若为空则默认使用 `src`。

示例：

```ini
lnk = "bin\\MyApp.exe, 我的程序, MyApp, bin\\MyApp.exe"
```

限制：解析 `lnk` spec 时是按逗号硬切分（不支持带逗号的字段）。

---

## 5. 清理策略（删除解压目录）

#### `TimeOut`
- 类型：整数（秒）
- 默认：`0`
- 语义：
  - `< 0`：不删除解压目录。
  - `>= 0`：在运行结束后，wrapper 会启动一个隐藏的子进程，延迟 `TimeOut` 秒后尝试删除 `outdir`。

实现要点：

- 解压目录里会写一个 token 文件（`.cleanup_token`），子进程会校验 token 匹配才删除，以避免误删“新一轮运行”刚写入的目录。

---

## 6. 一份可用的完整示例

### 示例 A：最小配置（默认解压到 %temp%\WrapperTemp，运行 setup.exe）

```ini
;!@Install@!UTF-8!
; 最小配置：不写 RunProgram 时默认 setup.exe
;!@InstallEnd@!
```

### 示例 B：弹窗确认 + 指定安装器 + 60 秒后清理

```ini
;!@Install@!UTF-8!
Title = "安装提示"
BeginPrompt = "即将开始安装，是否继续？"

Path = "%temp%"
PathName = "MyApp_InstallCache"
TimeOut = 60

ExecuteFile = "bin\\installer.exe"
ExecuteParameters = "/S"
;!@InstallEnd@!
```

### 示例 C：多阶段 RunProgram + 参数转发（把 wrapper 的参数转给第 2 个程序）

```ini
;!@Install@!UTF-8!
Path = "%temp%"
PathName = "MyApp"
Directory = ".\\"
RunProgram = "setup.exe", "post.exe"
Forward = 2
async = 0
TimeOut = 10
;!@InstallEnd@!
```

### 示例 D：平台目录映射 + 桌面快捷方式

```ini
;!@Install@!UTF-8!
Platform = "Windows7 32:win732", "Windows7 64:win764", "Windows10 64:win1064", "Windows11 64:win1164"
RunProgram = "MyApp.exe"
Directory = ".\\"
lnk = "MyApp.exe, 我的程序, MyApp, MyApp.exe"
;!@InstallEnd@!
```

---

## 7. 已知实现注意（强烈建议你看一眼）

根据当前 `wrapper.c`，`lnk` 与 `Platform` 在解析阶段的处理逻辑存在明显的拷贝粘贴错误：

- 解析到 `lnk=` 或 `Platform=` 时，代码把条目错误地加入了 `RunProgram` 列表，而不是分别加入 `LnkSpec` / `PlatformMap`。
- 结果：即使你写了 `lnk` / `Platform`，运行时 `LnkCount` 和 `MapCount` 仍然可能为 0，从而快捷方式与平台映射不会生效。

如果你最终使用的是“这份源码编译出的 wrapper”，建议修正为：

- `lnk` 应调用 `cfg_add_lnk(...)`
- `Platform` 应调用 `cfg_add_map_dir(...)`

修复后，本文档第 4.5 / 4.6 与示例 D 才能完整生效。

---

## 8. 打包拼接方法（附录，常见做法）

通常流程是：

1) 用 7-Zip 生成 payload：`payload.7z`（确保压缩包内路径全是相对路径，且不包含 `..`、盘符、绝对路径）。
2) 准备 `config.txt`：内容就是从 `;!@Install@!UTF-8!` 到 `;!@InstallEnd@!` 的整段文本（UTF-8）。
3) 二进制拼接生成最终 EXE（Windows CMD 示例）：

```bat
copy /b wrapper.exe + config.txt + payload.7z out.exe
```

---

## 9. 排障小抄

- 运行失败优先看日志：
  - 同目录 `out.exe.log`；若写不进去则在 `%TEMP%` 下。
- 解压目录里会出现这些“哨兵文件”（用于安全删除与复用）：
  - `.wrapper_marker`：标记该目录确实由 wrapper 创建（防止误删）。
  - `.payload_id`：记录 payload 的 CRC 与 size，用于判断能否跳过解压。
  - `.extracted_ok`：解压完成标记。
  - `.cleanup_token`：延迟删除校验 token。

