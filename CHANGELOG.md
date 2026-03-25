# Changelog

All notable changes to x64dbgMCP are documented in this file.

## [fireundubh]

### Added
- Composite tools: `BreakpointContext`, `ThreadContext`, `RunUntilBreakpoint`
- Memory map filtering by address, protection, type, and module name
- Register dump filtering (`gpr`, `gpr+flags`, `all`)
- `MemoryReadValues` for reading typed values (byte/word/dword/qword)
- `FollowPointerChain` for walking pointer chains with offsets
- `DisasmGetInstructionRangeEx` with optional raw bytes and bulk read optimization
- `SetPageRights` for changing memory page protection
- `SetHardwareBreakpoint` / `DeleteHardwareBreakpoint`
- Configurable timeouts per endpoint

### Fixed
- `findallmem` returning empty results via `ExecCommand` reference view polling
- `Pattern/FindMem` corruption when scanning unmapped pages
- `PatternFindMem` failures on inaccessible memory regions (now walks accessible pages)

### Changed
- Extracted shared helpers (`_parse_response_dict`, `_parse_response_list`, `_read_memory_bytes`) to reduce duplication
- Memory map returns a summary instead of full dump when unfiltered and page count exceeds 200

## [build1.1] - 2026-03-15

### Fixed
- `FlagGet` now uses proper thread context and GUI updates
- `FlagSet` now uses proper thread context and GUI updates
- `Script::Register::CFlags()` for bitwise flag get/set operations

## [v1.0.0] - 2026-02-13

### Added
- Thread support: `GetThreadList`, `GetTebAddress`, `GetCallStack`
- Symbol enumeration by module (`QuerySymbols` / `SymbolEnum` endpoint) with pagination
- 10+ new tools: `EnumHandles`, `EnumTcpConnections`, `GetPatchList`, `GetPatchAt`, `XrefGet`, `XrefCount`, `LabelSet`, `LabelGet`, `LabelList`, `CommentSet`, `CommentGet`, `StringGetAt`, `GetBranchDestination`, `MemoryRemoteAlloc`, `MemoryRemoteFree`, `MemoryBase`
- `GetBreakpointList` with type filtering

### Fixed
- `ExecCommand` reference view bug returning stale data on subsequent tool call failures
- Corrected pattern sanitizer for byte pattern matching

### Changed
- Removed legacy tools and AI-generated jargon from tool descriptions
- Log redirection for commands / cleaned up code

## [1-2026.v2_Release] - 2026-01-29

### Fixed
- Corrected pattern sanitizer for `PatternFindMem`

## [1-2026.Release] - 2026-01-23

### Added
- Symbol enumeration by module
- Cursor IDE example walkthrough
- Pre-built releases in GitHub

### Changed
- Cleaned up source files and removed build artifacts from repo

## [Release] - 2025-10-15

### Added
- x32dbg support (dual-architecture CMake build producing both `.dp32` and `.dp64` plugins)
- Claude API CLI mode (`python x64dbg.py claude`) for direct chat with tool use
- Claude Desktop MCP server compatibility

### Changed
- Updated README with API compatibility notes and setup guidance

## Initial Release - 2025-06-25

### Added
- C++ x64dbg plugin (`MCPx64dbg.cpp`) exposing 40+ debugging APIs over HTTP on `localhost:8888`
- Python MCP server (`x64dbg.py`) wrapping all HTTP endpoints as MCP tools
- Core tools: `ExecCommand`, `RegisterGet/Set`, `MemoryRead/Write`, `DebugRun/Pause/Stop/StepIn/StepOver/StepOut`
- Breakpoint tools: `DebugSetBreakpoint`, `DebugDeleteBreakpoint`
- Assembly tools: `AssemblerAssemble`, `AssemblerAssembleMem`, `DisasmGetInstructionRange`
- Stack tools: `StackPop`, `StackPush`, `StackPeek`
- Flag tools: `FlagGet`, `FlagSet`
- Pattern search: `PatternFindMem` with wildcard support
- Module listing: `GetModuleList`
- Expression parsing: `MiscParseExpression`, `MiscRemoteGetProcAddress`
- Debugger state: `IsDebugActive`, `IsDebugging`
- CLI tool invocation mode

[fireundubh]: https://github.com/x64dbg/x64dbgMCP/compare/build1.1...HEAD
[build1.1]: https://github.com/x64dbg/x64dbgMCP/compare/v1.0.0...build1.1
[v1.0.0]: https://github.com/x64dbg/x64dbgMCP/compare/1-2026.v2_Release...v1.0.0
[1-2026.v2_Release]: https://github.com/x64dbg/x64dbgMCP/compare/1-2026.Release...1-2026.v2_Release
[1-2026.Release]: https://github.com/x64dbg/x64dbgMCP/compare/Release...1-2026.Release
[Release]: https://github.com/x64dbg/x64dbgMCP/compare/24f042c...Release
