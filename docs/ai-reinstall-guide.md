# ReSys AI 调用文档（重装系统）

本文档面向自动化 Agent（AI），用于调用 `ReSys.exe` 执行重装，并通过 `progress.txt` 获取进度与错误信息。

## 1. 推荐入口（优先）

优先使用这 4 个参数：

- `--win7`
- `--win10`
- `--win11`
- `--smart`

示例：

```powershell
ReSys.exe --win10
```

说明：

- 这 4 个参数内部仍是 JSON 驱动。
- 分别对应 `rules/install/auto/win7.json`、`win10.json`、`win11.json`。
- `--smart` 会先判断正在运行的系统，再选择对应自动重装配置，一般重装的系统就是目前正在运行的系统一致的大版本。

## 2. JSON 入口（高级）

当 AI 需要自定义参数时，再用 `--json`：

```powershell
ReSys.exe --json "C:/Users/Administrator/Desktop/rules/install/auto/win10.json"
```

`--json <source>` 支持：

- JSON 文件路径（推荐）
- JSON 文本（首字符为 `{` 或 `[`）

JSON 示例可直接参考：

- `rules/install/auto/win7.json`
- `rules/install/auto/win10.json`
- `rules/install/auto/win11.json`
- `rules/install/default.json`

## 3. 参数互斥规则

以下参数互斥，不能混用：

- `--json`
- `--win7`
- `--win10`
- `--win11`
- `--smart`

冲突示例（会失败）：

- `ReSys.exe --json xxx --win10`
- `ReSys.exe --win7 --win11`

## 4. JSON 常用字段

- `mode`: `auto` / `manual`
- `target_os`: `win7` / `win10` / `win11`
- `image_path`: 安装镜像路径
- `index`: 镜像索引（`-1` 为自动）
- `partition`: 目标分区（手动模式常用）
- `PEwim`: 指定 PE WIM
- `file`: 安装后复制文件
- `shortcut`: 安装后创建快捷方式
- `win7fix`: Win7 修复资源

路径规则：

- `image_path`、`PEwim`、`win7fix.*` 若是相对路径，会按程序目录（`ReSys.exe` 所在目录）解析。

## 5. 镜像与 PE 的选择逻辑

镜像：

- 若 `image_path` 有效：直接使用该路径，不再走扫描/下载。
- 若 `image_path` 为空或无效：再走本地扫描与下载流程。

PE：

- 若 `PEwim` 有效：直接使用该路径。
- 若 `PEwim` 为空：走自动 PE 获取流程。

## 6. progress.txt（AI 必读）

程序会在 `ReSys.exe` 同目录写入：

- `progress.txt`

格式：

- 每行一条：`<百分比>%, <说明>`
- 示例：`35%, 下载镜像中... 12.3MB/s`

行为：

- 普通阶段：追加新行。
- 高频阶段（下载/应用镜像）：覆盖最后一行，避免文件无限增长。

## 7. JSON 错误回传

当 `--json` 的 JSON 语法、字段值、`mode` 等出错时：

- UI 会弹窗提示。
- 同时会把错误写入 `progress.txt`（例如 `0%, JSON配置错误: ...`）。

这意味着 AI 不读日志也能从 `progress.txt` 判断 JSON 是否正确。

## 8. AI 调用建议流程

1. 优先调用 `--win7/--win10/--win11/--smart`。
2. 仅在需要自定义时使用 `--json`，并基于 `rules/install/auto/*.json` 生成配置，比如要重装指定的镜像系统。
3. 启动后每 `0.5` 到 `1` 秒读取一次 `progress.txt` 最后一行。
4. 若出现 `JSON配置错误:`，直接判定参数无效并停止重试。
