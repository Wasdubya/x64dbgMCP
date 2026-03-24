# feat: 增强内存分析能力并重构MCP工具架构

## C++ 端新增API (MCPx64dbg.cpp)
  - /Debug/GetProcessId: 获取调试进程PID
  - /Memory/WorkingSet: 内存工作集详情（页面有效性、共享、NUMA等）
  - /Memory/Info: 统一内存信息查询（VirtualQuery + WorkingSet）

## Python端新增工具（49个）

### 命令发现系统
  - ListCommands: 列出x64dbg命令（可按类别过滤）
  - GetCommandHelp: 获取命令详细帮助

### 依赖新C++ API
  - GetProcessId: 获取调试进程PID
  - GetWorkingSet: 内存工作集信息
  - GetMemoryInfo: 统一内存信息查询
  - GetValue: 表达式求值

### 调试控制
  - CmdInit: 初始化调试文件
  - CmdAttach: 附加到进程（PID自动转16进制）
  - CmdDetach: 分离调试器
  - CmdRun: 继续执行
  - CmdPause: 暂停执行
  - CmdStop: 停止调试
  - CmdStepInto: 单步进入
  - CmdStepOver: 单步跳过
  - CmdStepOut: 执行到返回

### 断点管理
  - CmdSetBreakpoint: 设置软件断点
  - CmdDeleteBreakpoint: 删除软件断点
  - CmdSetHardwareBreakpoint: 设置硬件断点（新增size参数）
  - CmdDeleteHardwareBreakpoint: 删除硬件断点
  - CmdSetMemoryBreakpoint: 设置内存断点
  - CmdSetDllBreakpoint: 设置DLL加载断点

### 搜索功能
  - CmdFind: 查找字节模式
  - CmdFindAll: 查找所有匹配
  - CmdFindAllMem: 全内存搜索
  - CmdFindAsm: 查找汇编指令
  - CmdFindRef: 查找引用
  - CmdFindStrings: 查找字符串引用
  - CmdFindIntermodCalls: 查找跨模块调用

### 内存操作
  - CmdAlloc: 分配内存
  - CmdFree: 释放内存
  - CmdMemFill: 填充内存
  - CmdSetPageRights: 设置页面权限
  - CmdSaveData: 保存内存到文件

### 分析功能
  - CmdAnalyze: 分析当前模块
  - CmdAnalyzeFunction: 分析函数
  - CmdAnalyzeXrefs: 分析交叉引用
  - CmdDownloadSymbols: 下载符号

### 用户数据
  - CmdSetComment: 设置注释
  - CmdSetLabel: 设置标签
  - CmdSetBookmark: 设置书签
  - CmdAddFunction: 添加函数定义

### 跟踪功能
  - CmdTraceInto: 条件跟踪进入
  - CmdTraceOver: 条件跟踪跳过

### 脚本支持
  - CmdLog: 输出日志
  - CmdExecScript: 执行脚本文件

### 其他
  - CmdAssemble: 汇编指令（新增fill_nops参数）
  - CmdGetProcAddr: 获取导出函数地址
  - CmdLoadDll: 加载DLL
  - CmdHideDebugger: 隐藏调试器

## 删除并替代的工具（13个）

| 原工具                   | 新工具                      | 变化                        |
| ------------------------ | --------------------------- | --------------------------- |
| DebugRun                 | CmdRun                      | 重构：API端点 → ExecCommand |
| DebugPause               | CmdPause                    | 重构                        |
| DebugStop                | CmdStop                     | 重构                        |
| DebugStepIn              | CmdStepInto                 | 重构                        |
| DebugStepOver            | CmdStepOver                 | 重构                        |
| DebugStepOut             | CmdStepOut                  | 重构                        |
| DebugSetBreakpoint       | CmdSetBreakpoint            | 重构                        |
| DebugDeleteBreakpoint    | CmdDeleteBreakpoint         | 重构                        |
| SetHardwareBreakpoint    | CmdSetHardwareBreakpoint    | 新增size参数                |
| DeleteHardwareBreakpoint | CmdDeleteHardwareBreakpoint | 重构                        |
| MemoryRemoteAlloc        | CmdAlloc                    | 重构                        |
| MemoryRemoteFree         | CmdFree                     | 重构                        |
| SetPageRights            | CmdSetPageRights            | 重构                        |

## 功能修复/改进
  - CmdAttach: PID自动转换为16进制格式（修复x64dbg attach命令格式要求）
  - CmdFind系列: size参数从十进制改为十六进制
  - CmdSetHardwareBreakpoint: 新增size参数，type参数简化
  - CmdAssemble: 合并AssemblerAssemble/AssemblerAssembleMem，新增fill_nops参数

## 新增文档
  - docs/x64dbg_commands.json: x64dbg命令数据库

## 架构变化
  - 新工具统一使用ExecCommand调用x64dbg命令
  - 保留原有41个工具，向后兼容
  - 工具总数：56 → 92（+36）