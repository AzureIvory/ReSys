# Windows 10/11 自动化配置脚本说明

本文档用于说明当前 Windows 10/11 自动化部署与优化过程中涉及的脚本文件及其作用。

---

## 文件说明

### Clean.ps1

用于执行系统清理操作，主要包括：

- 删除预装的 Appx 应用
- 清空 Windows 11 开始菜单固定项
- 删除 Windows Capability 功能组件

---

### PauseWindowsUpdate.ps1

用于暂停 Windows 更新。

功能说明：

- 将 Windows 更新暂停时间设置为当前时间起 7 天

---

### PauseWindowsUpdate.xml

计划任务配置文件，配合 `PauseWindowsUpdate.ps1` 使用。

功能说明：

- 让暂停 Windows 更新的操作每天自动刷新
- 确保 Windows 更新始终保持暂停状态

---

### unattend-01.cmd

用户首次登录后执行的脚本。

执行阶段：

- 用户首次登录后
- 通过 `RunOnce` 执行

---

### unattend-02.cmd

在 Windows 安装的 `specialize` 阶段执行的脚本。

执行阶段：

- `specialize` 阶段
- 加载默认用户配置时执行

---

## Specialize.ps1

`specialize` 阶段的主脚本，用于执行系统级配置和优化操作。

功能说明：

- 允许不支持 TPM / CPU 的设备执行升级
- 绕过联网要求 `BypassNRO`
- 删除 OneDrive 安装文件和快捷方式
- 删除 DevHome / Outlook 更新调度项
- 关闭 Chat 自动安装
- 调用 `RemovePackages.ps1`
- 调用 `RemoveCapabilities.ps1`
- 调用 `RemoveFeatures.ps1`
- 注册 `PauseWindowsUpdate` 计划任务
- 关闭安全中心通知
- 关闭 SmartScreen 相关项
- 关闭 UAC
- 设置 PowerShell 执行策略
- 禁用最后访问时间
- 设置 Windows Update 策略
- 注册 `MoveActiveHours` 计划任务
- 关闭快速启动
- 禁用 Widgets / News
- 阻止设备加密
- 关闭 Edge 首次运行体验和启动增强
- 调用 `Clean.ps1`

---

## DefaultUser.ps1

用于修改默认用户配置，会影响之后新建用户的默认设置。

功能说明：

- 删除默认用户中的 `OneDriveSetup` 启动项
- 显示文件扩展名
- 关闭 Edge / Windows SmartScreen 用户侧配置
- 关闭内容推荐、广告推荐、预装推荐
- 关闭鼠标指针加速
- 执行 `unattend-02.cmd`
  - 即执行：`start C:\drive.exe`
- 写入以下注册表项：

```reg
HKU\DefaultUser\...\RunOnce