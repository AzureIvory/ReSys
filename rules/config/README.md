# 应用配置

这个目录只有 `app.json` 一个文件，由 `src/config/appcfg.go` 加载和解析。

---

## 结构一览

```json
{
  "language":   { "ui_language": "auto", "image_default_language": "zh-CN" },
  "paths":      { "Download_Dir_Name", "PE_Dir_Name", "Driver_Backup_Dir_Name", ... },
  "image":      { "Scan_Depth": 2, "Min_Local_Image": 1, "Skip_Names": [...] },
  "disk":       { "Min_Free_Space": 7516192768, "Need_Free_Space": 10737418240 },
  "pe":         [ ["group", "sdi_pattern", "wim_pattern", "arch", "label"], ... ],
  "ui":         { "Theme": "rules\\ui\\default\\default.json", "Advert": false }
}
```

## 各节点说明

| 节点 | 用途 | 对应 Go 代码 |
|---|---|---|
| `language.ui_language` | UI 语言，默认 `"auto"`（自动检测）。有效值见 `rules/lang/*.json` | `appcfg.go:AppLanguageConfig` |
| `language.image_default_language` | 安装镜像默认语言（如 `zh-CN`），用于 dism 选择索引 | 同上 |
| `paths.Download_Dir_Name` | 镜像下载临时目录名 | `appcfg.go:AppPathsConfig` |
| `paths.PE_Dir_Name` | PE 资源目录名，pe 项的 pattern 路径以此开头 | 同上 |
| `paths.Driver_Backup_Dir_Name` | 驱动备份目录名 | 同上 |
| `paths.Install_Plan` | 安装计划文件名（运行时生成到磁盘根目录） | 同上 |
| `paths.Image_Hint` | 上次使用的镜像路径记录文件 | 同上 |
| `paths.Temp_Marker` | 临时分区标记文件路径 | 同上 |
| `image.Scan_Depth` | 本地镜像扫描深度，越大越慢 | `appcfg.go:AppImageConfig` |
| `image.Min_Local_Image` | 最小镜像体积（GB），小于此值跳过 | 同上 |
| `image.Skip_Names` | 需要跳过的镜像文件名（如 pe.wim） | 同上 |
| `disk.Min_Free_Space` | 有效分区的最小空闲字节数 | `appcfg.go:AppDiskConfig` |
| `disk.Need_Free_Space` | 临时分区需要的空间字节数 | 同上 |
| `pe` | PE 候选列表：`[分组名, SDI路径, WIM路径, 架构, 标签]` | `appcfg.go:AppPEEntry` |
| `ui.Theme` | UI 主题 JSON 路径 | `appcfg.go:AppUIConfig` |
| `ui.Advert` | 是否显示广告位 | 同上 |

## `src/config` 包结构

| 文件 | 职责 |
|---|---|
| `appcfg.go` | 加载/解析 `app.json`，定义 `AppConfig` 结构体和所有默认常量 |
| `installcfg.go` | 定义安装计划模型（`Config`/`FileItem`/`ShortcutItem`/`Win7Fix` 等），提供 `Marshal`/`ParseSource` |

### 关键常量（`appcfg.go`）

```
DefaultUIBundleLanguage = "zh_CN"          // 回退语言
DefaultLanguageDirRelative = `rules\lang`  // 语言包目录
DefaultUIThemeRelativePath = `rules\ui\default\default.json`
DefaultDownloadDirName = "tempimg"
DefaultPEDirName = "PETEMP"
DefaultInstallPlanFileName = "restall_win.dat"
```

### 关键模型（`installcfg.go`）

```
FileItem { Src, Dst, Overwrite, Required, Launch }
ShortcutItem { Target, Name, Dir }
Config { Mode, TargetOS, ImageArch, ..., File, Shortcut, Win7Fix, ... }
```
