# app_config_probe

`app_config_probe` 用来验证 `rules/config/app.json` 里的 `paths`、`image`、`disk` 配置是否真的生效。

它不是只打印原始 JSON。
它会同时输出三类信息：

1. `app.json` 解析后的原始值。
2. 业务层实际调用到的函数返回值。
3. 部分真实执行结果，例如本地镜像扫描和磁盘候选分区查询。

## 适用场景

适合在你改完 `app.json` 之后快速确认下面这些配置是否已经接进业务：

- `paths.Download_Dir_Name`
- `paths.PE_Dir_Name`
- `paths.Driver_Backup_Dir_Name`
- `paths.Install_Plan`
- `paths.Image_Hint`
- `paths.Temp_Marker`
- `image.Scan_Depth`
- `image.Min_Local_Image`
- `image.Skip_Names`
- `disk.Min_Free_Space`
- `disk.Need_Free_Space`

## 运行方式

在仓库根目录执行：

```powershell
go run ./test/app_config_probe
```

输出 JSON：

```powershell
go run ./test/app_config_probe -json
```

指定用于派生路径的根分区和镜像路径：

```powershell
go run ./test/app_config_probe -root D:\ -image-path D:\images\install.wim
```

## 输出说明

### 1. `raw_paths` 和 `raw_image`

这是 `app.json` 原样解析后的配置值。

### 2. `path_functions`

这是安装侧真正使用的函数返回值，对应当前代码里的实际入口：

- `app_download_dir_name` 对应 `install.AppDownloadDirName()`
- `app_pe_dir_name` 对应 `install.AppPEDirName()`
- `app_driver_backup_dir_name` 对应 `install.AppDriverBackupDirName()`
- `app_install_plan_file_name` 对应 `install.AppInstallPlanFileName()`
- `app_image_hint_file_name` 对应 `install.AppImageHintFileName()`
- `app_temp_marker_relative_path` 对应 `install.AppTempMarkerRelativePath()`

如果你改了 `app.json`，这里没变，说明配置没有真正接进去。

### 3. `paths`

这是根据当前配置和输入参数派生出来的实际路径，例如：

- 下载目录完整路径
- PE 工作目录完整路径
- 安装计划文件完整路径
- 镜像提示文件完整路径
- 临时分区标记文件完整路径
- 驱动备份目录完整路径

### 4. `image_config`

这是本地镜像扫描策略的生效值：

- 扫描深度
- 最小镜像体积
- 跳过文件名单

### 5. `image_live`

这部分会真的执行一次 `image.Findimg()`。

也就是说，它会：

- 真扫描本机各盘
- 真按 `Scan_Depth` 搜索
- 真按 `Min_Local_Image` 过滤
- 真按 `Skip_Names` 跳过文件

如果你改了 `image` 配置，这部分最能直接证明行为是否变化。

### 6. `disk_config`

这是磁盘配置的生效值：

- `min_free_space_threshold` 对应 `disk.Min_Free_Space`
- `need_free_space_floor` 对应 `disk.Need_Free_Space`
- `effective_need_bytes` 表示把“配置下限 + 内置最小值 + 安全余量”一起应用后的结果

### 7. `disk_live`

这部分会真的执行一次 `disk.Findpart()`。

也就是说，它会：

- 真读取当前机器的磁盘剩余空间
- 真按 `Min_Free_Space` 过滤
- 真返回当前会被业务层当作候选盘的分区列表

默认情况下，它不会改磁盘。

## 危险操作

如果你显式加上：

```powershell
go run ./test/app_config_probe -split-temp-volume
```

那么 probe 会真的调用 `disk.NewTempVolume()`。

这不是模拟。
这会触发真实的临时分区创建流程，可能包括：

- 使用现有未分配空间创建分区
- 或者尝试压缩当前系统盘后再创建分区

因此这会直接修改磁盘布局。

如果你只想验证配置是否生效，不要加这个参数。

如果你确实要测试它，可以再配合：

```powershell
go run ./test/app_config_probe -split-temp-volume -split-need-gib 12.5
```

这里的 `12.5` 表示请求大小为 `12.5 GiB`。
最终实际申请值仍然会受到 `disk.Need_Free_Space` 下限和程序内置最小值影响。

## 推荐验证顺序

建议按这个顺序看：

1. 先看 `raw_paths` / `raw_image`，确认 JSON 读到了。
2. 再看 `path_functions` / `paths`，确认 `paths` 已经进入业务层。
3. 再看 `image_config` / `image_live`，确认扫描策略真的变了。
4. 再看 `disk_config` / `disk_live`，确认候选盘筛选真的变了。
5. 只有在明确要测试分区创建时，才使用 `-split-temp-volume`。

## 常见问题

### 为什么 `image_live.candidates` 为空

常见原因：

- 没有符合最小体积要求的镜像
- `Scan_Depth` 太小，没扫到目标目录
- `Skip_Names` 把目标文件过滤掉了
- 镜像文件结构无效，没通过校验

### 为什么 `disk_live.candidates` 比预期少

常见原因：

- 分区剩余空间没有达到 `Min_Free_Space`
- 分区类型不是可用的数据盘
- 读取分区信息失败

### 为什么 `path_functions` 和 `raw_paths` 不一致

这是正常的，如果配置经过了归一化。

例如：

- 路径分隔符被统一
- 空值回退到了默认值
- 相对路径被保留为业务约定格式

## 相关文件

- 入口程序：[main.go](/C:/Users/Administrator/Desktop/ReSys/test/app_config_probe/main.go)
- 安装侧路径配置入口：[app_paths.go](/C:/Users/Administrator/Desktop/ReSys/src/install/app_paths.go)
- 镜像扫描配置入口：[config.go](/C:/Users/Administrator/Desktop/ReSys/src/image/config.go)
- 磁盘配置入口：[config.go](/C:/Users/Administrator/Desktop/ReSys/src/disk/config.go)
