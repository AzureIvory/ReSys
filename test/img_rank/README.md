# img_rank

`img_rank` 是一个用于查看镜像候选顺序的小工具。  
它会读取 `ReSys` 当前规则，并尽量按实际下载前的筛选逻辑输出结果，方便排查：

- 为什么某个系统先用了哪条镜像规则
- 当前会优先选 `32` 还是 `64`
- 当前语言偏好是中文、英文还是其他语言
- 最终候选里，哪条会更早被尝试

## 编译

在项目根目录执行：

```bat
test\img_rank\build.bat
```

生成文件：

```text
test\img_rank\img_rank.exe
```

## 用法

最常用：

```bat
test\img_rank\img_rank.exe 7
test\img_rank\img_rank.exe 10
test\img_rank\img_rank.exe 11
```

也支持显式参数：

```bat
test\img_rank\img_rank.exe -system 7
test\img_rank\img_rank.exe 10 -limit 8
test\img_rank\img_rank.exe 11 -arch 64 -lang zh-cn
```

## 参数说明

- `system`：目标系统号，例如 `7`、`10`、`11`
- `-arch`：指定目标架构，可填 `32` 或 `64`
- `-lang`：指定语言偏好，例如 `zh-cn`、`en-us`
- `-limit`：限制显示条数，`0` 表示全部

## 输出说明

示例：

```text
system=7 total=3 shown=3
arch=64 source=runtime mode=exact
lang=en-us source=system-ui scope=ms-only
try=url first, then non-url
ORD  TRY  SOURCE  RANK  TYPE  LANG  ARCH  FILE
```

字段含义：

- `system`：当前查看的目标系统
- `total`：筛选后候选总数
- `shown`：本次实际显示条数
- `arch`：当前使用的目标架构
- `source`：这个架构或语言值来自哪里
- `mode`：架构筛选方式
- `scope`：语言筛选作用范围

表格列说明：

- `ORD`：规则聚合后的候选顺序
- `TRY`：更接近实际下载尝试顺序的编号
- `SOURCE`：规则来源名
- `RANK`：规则文件中的优先级，数值越大越靠前
- `TYPE`：链接类型，例如 `url`、`bt`
- `LANG`：镜像语言
- `ARCH`：镜像架构
- `FILE`：镜像文件名

## 你最需要注意的两点

1. `ORD` 不是绝对的最终下载顺序。  
   下载阶段会先尝试 `url`，再尝试非 `url`，所以真正更接近下载顺序的是 `TRY`。

2. `RANK` 是数值越大越优先。  
   不是越小越优先。

## 适合什么时候用

- 改了 `rules/core/image-sources` 后，想确认排序是否符合预期
- 怀疑某条直链没有被优先使用
- 想看当前语言或架构筛选是否影响了结果
- 排查为什么某个镜像没有进入最终候选列表
