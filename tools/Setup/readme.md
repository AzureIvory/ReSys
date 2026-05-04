---

## 应答文件说明

### win10.xml

Windows 10 自动应答文件，用于自动化安装与首次登录配置。

功能说明：

- 接受 EULA
- 使用 Win10 Pro 通用安装 Key
- 保留以下兼容性绕过项：
  - `BypassTPMCheck`
  - `BypassSecureBootCheck`
  - `BypassRAMCheck`
- 在 `specialize` 阶段调用外置脚本：
  - `Specialize.ps1`
- 加载默认用户注册表，并调用：
  - `DefaultUser.ps1`
- 创建本地管理员用户：
  - `Admin`
- 设置 `Administrator` 自动登录一次
- 在 OOBE 阶段调用外置脚本：
  - `FirstLogon.ps1`

---

### win7.xml

Windows 7 自动应答文件，用于简化 OOBE 阶段配置。

功能说明：

- 在 OOBE 阶段跳过首次开机设置
- 尝试自动登录：
  - `Administrator`

---

## 应答文件关系说明

| 文件名 | 适用系统 | 主要作用 |
|---|---|---|
| `win10.xml` | Windows 10 | 自动接受协议、设置安装 Key、创建管理员用户、调用外置配置脚本 |
| `win7.xml` | Windows 7 | 跳过 OOBE 首次开机设置，并尝试自动登录 Administrator |

---

## win10.xml 执行流程概览

```text
Windows 10 安装流程
│
├─ 安装阶段
│  ├─ 接受 EULA
│  ├─ 使用 Win10 Pro 通用安装 Key
│  └─ 保留 TPM / Secure Boot / RAM 检查绕过项
│
├─ specialize 阶段
│  ├─ 调用 Specialize.ps1
│  ├─ 加载默认用户注册表
│  └─ 调用 DefaultUser.ps1
│
├─ 用户配置阶段
│  ├─ 创建 Admin 本地管理员用户
│  └─ 设置 Administrator 自动登录一次
│
└─ OOBE 阶段
   └─ 调用 FirstLogon.ps1