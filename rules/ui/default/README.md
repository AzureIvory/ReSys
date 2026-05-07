# AI 速查：UI 组件树

本目录是 ReSys 的 **WinUI 声明式 JSON 模板**，代码由 `src/ui/host.go` 加载并构建真实的 WinUI 窗口。

> 不要直接读这些 JSON。看这份速查表就够了，除非你需要修改具体的 UI 布局。

---

## 文件概述

| 文件 | 行数 | 对应界面 |
|---|---|---|
| `default.json` | 51 | 根清单：注册组件 + 定义主窗口 |
| `components/pages/select_page.json` | 249 | **选择页**：自动重装 - 选系统版本 |
| `components/pages/manual_page.json` | 100 | **手动重装页**：容器，引用下面 4 个子组件 |
| `components/pages/manual_header.json` | ~110 | ↳ 返回按钮 + 标题 + 语言选择 |
| `components/pages/manual_image_form.json` | ~260 | ↳ 镜像选择 + 索引 + 系统 + 汇总 |
| `components/pages/manual_disk_section.json` | ~470 | ↳ 分区列表 + 详情 + PE + 引导 |
| `components/pages/manual_options_section.json` | ~225 | ↳ 选项复选框网格 + 开始重装按钮 |
| `components/pages/progress_page.json` | 148 | **进度页**：安装进度条 + 日志输出 |
| `components/modals/manual_driver_modal.json` | 301 | 驱动备份规则弹窗 |
| `components/modals/manual_postprocess_modal.json` | 688 | 后处理规则弹窗（文件拷贝 + 启动方式 + 快捷方式） |
| `components/modals/bitlocker_prompt.json` | 398 | BitLocker 解锁弹窗 |

---

## JSON 约定

### 组件注册 (`default.json`)

```json
"components": {
    "page-manual": "components/pages/manual_page.json",
},
"wins": [{
    "id": "main",
    "root": {
        "children": [
            { "component": "page-select" },
            { "component": "page-progress" },
            { "component": "page-manual" }
        ]
    }
}]
```

所有页面/弹窗都挂在主窗口 `root` 下，通过 `visible` 状态控制显隐。页面之间是**平铺叠加**关系，不是导航栈。

### Widget 节点

每个节点包含：`type`（widget 类型）、可选的 `id`（状态绑定键）、`children`（子节点）、`frame`（x/y/w/h 布局）、`style`（样式）、事件绑定（`onClick`/`onChange`）。

常见 type：`panel`、`label`、`button`、`input`、`image`、`list`、`switch`、`check`、`text`、`progress`。

### 状态绑定

- `"bind": "key.path"` — 绑定到 `manualStore` 中对应的值
- `"default": "value"` — 初始默认值
- 代码侧通过 `manualSetState` / `manualPatchState` 更新

### 事件处理

- `"onClick"` / `"onChange"` → 调用同名的 Go 导出函数（如 `HandlePostProcessFileAdd`）
- 函数注册在 `src/ui/callbacks.go`

---

## 各组件关键 ID

### select_page（选择页）
- 选择系统版本（Win7/Win10/Win11）

### manual_page（手动重装页）
- `manual-back` — 返回按钮
- `manual.image` — 镜像选择下拉 + 路径
- `manual.system.selected` — 系统下拉（win7/win10/win11/other）
- `manual.language.selected` / `manual.language.items` — 语言切换下拉
- `manual.options.postProcess` — 后处理开关
- `manual.options.driverBackup` — 驱动备份开关
- `manual.options.win7Fix` — Win7 修复开关
- `manual.install` — 开始安装按钮
- `manual.summary` — 底部汇总文本

### progress_page（进度页）
- `progress.spinnerPlaying` — 加载动画
- `progress.primaryText` / `progress.secondaryText` — 主/副状态文字
- `progress.log` — 日志输出区
- `progress.progressValue` / `progress.progressVisible` — 进度条

### manual_postprocess_modal（后处理弹窗）
- `manual.postprocess.visible` — 弹窗显隐
- `manual.postprocess.files.items` — 文件列表
- `manual.postprocess.files.form.src/dst/overwrite/required` — 文件编辑表单基础字段
- `manual.postprocess.files.form.launch` — 启动方式（none/firstLogon/specialize）
- `manual.postprocess.files.form.launchItems` — 启动方式下拉选项
- `manual.postprocess.shortcuts.items` — 快捷方式列表
- `manual.postprocess.shortcuts.form.*` — 快捷方式编辑表单
- 操作按钮绑定：`HandlePostProcessFileAdd/Save/Delete`、`HandlePostProcessFileLaunchChange`、`HandlePostProcessShortcutAdd/Save/Delete`、`HandlePostProcessConfirm/Cancel/Reset`

### manual_driver_modal（驱动弹窗）
- 驱动备份的文件匹配规则和 GUID 过滤规则

### bitlocker_prompt（BitLocker 弹窗）
- BitLocker 解锁密码输入

---

## 代码对应关系

- **加载 JSON** → `src/ui/host.go` 中的组件构建逻辑
- **事件处理** → `src/ui/callbacks.go` 注册所有 `onClick`/`onChange` 回调
- **状态读写** → `src/ui/strategy.go` 中的 `manualSetState`/`manualPatchState`/`manualStoreString` 等
- **业务逻辑** → `src/ui/postprocess_dialog.go`（后处理）、`src/ui/runtime.go`（手动模式事件）、`src/ui/i18n.go`（语言/国际化）等
- **数据结构** → `src/config/installcfg.go`（FileItem 含 Launch 字段表示启动方式）
