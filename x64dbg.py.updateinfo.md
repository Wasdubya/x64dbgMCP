# feat: Enhanced Memory Analysis Capabilities and Refactored MCP Tool Architecture

## C++ New APIs (MCPx64dbg.cpp)
  - /Debug/GetProcessId: Get debugged process PID
  - /Memory/WorkingSet: Memory working set details (page validity, sharing, NUMA, etc.)
  - /Memory/Info: Unified memory information query (VirtualQuery + WorkingSet)

## Python New Tools (49)

### Command Discovery System
  - ListCommands: List x64dbg commands (filterable by category)
  - GetCommandHelp: Get detailed command help

### Dependent on New C++ APIs
  - GetProcessId: Get debugged process PID
  - GetWorkingSet: Memory working set information
  - GetMemoryInfo: Unified memory information query
  - GetValue: Expression evaluation

### Debug Control
  - CmdInit: Initialize debugging file
  - CmdAttach: Attach to process (PID auto-converted to hex)
  - CmdDetach: Detach debugger
  - CmdRun: Resume execution
  - CmdPause: Pause execution
  - CmdStop: Stop debugging
  - CmdStepInto: Step into
  - CmdStepOver: Step over
  - CmdStepOut: Step out (run until return)

### Breakpoint Management
  - CmdSetBreakpoint: Set software breakpoint
  - CmdDeleteBreakpoint: Delete software breakpoint
  - CmdSetHardwareBreakpoint: Set hardware breakpoint (added size parameter)
  - CmdDeleteHardwareBreakpoint: Delete hardware breakpoint
  - CmdSetMemoryBreakpoint: Set memory breakpoint
  - CmdSetDllBreakpoint: Set DLL load breakpoint

### Search Functions
  - CmdFind: Find byte pattern
  - CmdFindAll: Find all matches
  - CmdFindAllMem: Search entire memory
  - CmdFindAsm: Find assembly instruction
  - CmdFindRef: Find references
  - CmdFindStrings: Find string references
  - CmdFindIntermodCalls: Find inter-modular calls

### Memory Operations
  - CmdAlloc: Allocate memory
  - CmdFree: Free memory
  - CmdMemFill: Fill memory
  - CmdSetPageRights: Set page rights
  - CmdSaveData: Save memory to file

### Analysis Functions
  - CmdAnalyze: Analyze current module
  - CmdAnalyzeFunction: Analyze function
  - CmdAnalyzeXrefs: Analyze cross-references
  - CmdDownloadSymbols: Download symbols

### User Data
  - CmdSetComment: Set comment
  - CmdSetLabel: Set label
  - CmdSetBookmark: Set bookmark
  - CmdAddFunction: Add function definition

### Tracing Functions
  - CmdTraceInto: Conditional trace into
  - CmdTraceOver: Conditional trace over

### Script Support
  - CmdLog: Output log
  - CmdExecScript: Execute script file

### Others
  - CmdAssemble: Assemble instruction (added fill_nops parameter)
  - CmdGetProcAddr: Get export function address
  - CmdLoadDll: Load DLL
  - CmdHideDebugger: Hide debugger

## Removed and Replaced Tools (13)

| Original Tool            | New Tool                   | Change                       |
| ------------------------ | -------------------------- | ---------------------------- |
| DebugRun                 | CmdRun                     | Refactored: API endpoint → ExecCommand |
| DebugPause               | CmdPause                   | Refactored                   |
| DebugStop                | CmdStop                    | Refactored                   |
| DebugStepIn              | CmdStepInto                | Refactored                   |
| DebugStepOver            | CmdStepOver                | Refactored                   |
| DebugStepOut             | CmdStepOut                 | Refactored                   |
| DebugSetBreakpoint       | CmdSetBreakpoint           | Refactored                   |
| DebugDeleteBreakpoint    | CmdDeleteBreakpoint        | Refactored                   |
| SetHardwareBreakpoint    | CmdSetHardwareBreakpoint   | Added size parameter         |
| DeleteHardwareBreakpoint | CmdDeleteHardwareBreakpoint| Refactored                   |
| MemoryRemoteAlloc        | CmdAlloc                   | Refactored                   |
| MemoryRemoteFree         | CmdFree                    | Refactored                   |
| SetPageRights            | CmdSetPageRights           | Refactored                   |

## Bug Fixes/Improvements
  - CmdAttach: PID automatically converted to hex format (fixes x64dbg attach command format requirement)
  - CmdFind series: size parameter changed from decimal to hexadecimal
  - CmdSetHardwareBreakpoint: Added size parameter, simplified type parameter
  - CmdAssemble: Merged AssemblerAssemble/AssemblerAssembleMem, added fill_nops parameter

## New Documentation
  - docs/x64dbg_commands.json: x64dbg command database

## Architecture Changes
  - New tools use ExecCommand to call x64dbg commands uniformly
  - Preserved 41 original tools for backward compatibility
  - Total tools: 56 → 92 (+36)