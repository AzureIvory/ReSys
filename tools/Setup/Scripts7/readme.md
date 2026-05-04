# Windows 7 自动化配置脚本说明

本文档用于说明当前 Windows 7 自动化部署与优化过程中涉及的脚本文件及其作用。

---

## 文件说明

### FirstLogon.cmd

用户首次登录后执行的脚本。

执行阶段：

- 用户首次登录后
- 通过 `RunOnce` 执行

---

### Specialize.cmd

在 Windows 安装的 `specialize` 阶段执行的脚本。

执行阶段：

- `specialize` 阶段
- 加载默认用户配置时执行

---

## Specialize.ps1

`specialize` 阶段的主脚本


## FirstLogon.ps1

`FirstLogon` 阶段的主脚本


