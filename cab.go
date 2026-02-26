package main

//! Windows Cabinet (.cab) 文件解压模块
//!
//! 使用 Windows SetupAPI (setupapi.dll) 的 SetupIterateCabinet 函数实现 .cab 文件解压。
//! 主要用于解压 Windows 更新包（如 KB2990941、KB3087873 等 NVMe 驱动补丁）。
