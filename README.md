# x32dbg MCP Server

**Model Context Protocol (MCP) server for x32dbg debugger**

Give Claude direct access to x32dbg debugging capabilities through natural language!

![Architecture](https://img.shields.io/badge/x32dbg-MCP%20Server-blue)
![Language](https://img.shields.io/badge/C++-Python-green)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

---

## 🎯 What is This?

This project connects x32dbg (Windows debugger) to Claude AI through the Model Context Protocol (MCP). You can:

- Debug programs using natural language
- Ask Claude to analyze functions, find crypto, set breakpoints
- Get real-time debugging context and assistance
- Automate reverse engineering workflows

---

## 🚀 Quick Start

### Prerequisites

- **x32dbg** installed ([download here](https://x64dbg.com/))
- **Python 3.8+** ([download here](https://www.python.org/downloads/))
- **Visual Studio 2019+** with C++ support (for compiling plugin)
- **Claude Desktop** or **Claude Code** (VSCode extension)

### Installation

#### 1. Build the Plugin

Just double-click `build.bat` - it handles everything!

```batch
# OR manually:
cmake -S . -B build32 -A Win32 -DBUILD_BOTH_ARCHES=OFF
cmake --build build32 --config Release
```

The compiled plugin will be at: `build/MCPx64dbg.dp32`

#### 2. Install the Plugin

Copy the plugin to your x32dbg plugins folder:

```
C:\Program Files\x64dbg\release\x32\plugins\MCPx64dbg.dp32
```

#### 3. Setup Python MCP Server

```bash
# Install dependencies
pip install mcp requests

# Test the server
python mcp_server.py
```

#### 4. Configure Claude Desktop

Edit your Claude Desktop config file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Mac/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "x32dbg": {
      "command": "python",
      "args": [
        "C:\\path\\to\\x64dbgMCP\\mcp_server.py"
      ],
      "env": {
        "X64DBG_URL": "http://127.0.0.1:8888"
      }
    }
  }
}
```

For **Claude Code (VSCode)**, add to `.vscode/settings.json`:

```json
{
  "mcp.servers": {
    "x32dbg": {
      "command": "python",
      "args": ["C:\\path\\to\\x64dbgMCP\\mcp_server.py"],
      "env": {
        "X64DBG_URL": "http://127.0.0.1:8888"
      }
    }
  }
}
```

---

## ✅ Verify Installation

1. **Start x32dbg**
2. **Check plugin loaded:** Press `ALT+L` to open logs, you should see:
   ```
   [MCP] Plugin loading...
   [MCP] HTTP server started on port 8888
   ```
3. **Test HTTP API:** Open browser to `http://127.0.0.1:8888/status`
4. **Start Claude Desktop** and verify x32dbg server appears in MCP settings

---

## 📖 Usage Examples

### Basic Debugging

```
You: "Set a breakpoint at 0x401000 and show me the disassembly"

Claude: [Uses set_breakpoint and disassemble_at tools]
```

### Function Analysis

```
You: "Analyze the current function"

Claude: [Uses analyze_function prompt, gets registers, disassembles, analyzes flow]
```

### Memory Operations

```
You: "Read 32 bytes from ESP and show me the stack contents"

Claude: [Uses get_register("esp") and read_memory tools]
```

### Automation

```
You: "Find all calls to GetProcAddress in the current module"

Claude: [Uses get_modules, searches memory, sets breakpoints]
```

---

## 🔧 Available Tools

### Status & Control
- `get_status()` - Get debugger state
- `execute_command(cmd)` - Run raw x32dbg command
- `run_process()` / `pause_process()` - Control execution

### Stepping
- `step_execution()` - Step into (F7)
- `step_over()` - Step over (F8)
- `step_out()` - Step out (Ctrl+F9)

### Registers
- `get_register(name)` - Read register (EAX, EBX, EIP, etc.)
- `set_register(name, value)` - Write register

### Memory
- `read_memory(addr, size)` - Read memory with ASCII view
- `write_memory(addr, data)` - Write hex bytes

### Breakpoints
- `set_breakpoint(addr)` - Set BP
- `delete_breakpoint(addr)` - Remove BP

### Analysis
- `disassemble_at(addr)` - Get instruction
- `get_modules()` - List loaded modules
- `analyze_current_location()` - Get full context

---

## 🎨 MCP Resources

Resources provide Claude with contextual information:

- `debugger://status` - Current debugging state
- `debugger://modules` - Loaded modules list

---

## 🎭 MCP Prompts

Prompts guide Claude for common tasks:

- `analyze_function` - Start function analysis workflow
- `find_crypto` - Search for crypto patterns
- `trace_execution` - Setup execution tracing

---

## 🏗️ Architecture

```
Claude Desktop/VSCode
        ↕ (MCP Protocol)
  mcp_server.py (Python)
        ↕ (HTTP REST API)
  MCPx64dbg.dp32 (C++ Plugin)
        ↕ (x64dbg SDK)
      x32dbg.exe
```

---

## 🐛 Troubleshooting

### Plugin Not Loading

1. Check logs (ALT+L in x32dbg)
2. Ensure plugin is in correct folder
3. Try restarting x32dbg

### HTTP Server Not Responding

1. Check port 8888 is not in use: `netstat -ano | findstr 8888`
2. Check firewall settings
3. Try changing port in plugin (recompile needed)

### MCP Server Can't Connect

1. Ensure x32dbg is running with plugin loaded
2. Test manually: `curl http://127.0.0.1:8888/status`
3. Check X64DBG_URL environment variable

### Build Errors

1. Ensure Visual Studio is installed with C++ support
2. Ensure CMake is in PATH
3. Check `deps/pluginsdk` folder exists

---

## 📦 Repository Structure

```
x64dbgMCP/
├── build.bat              # One-click build script
├── mcp_server.py          # Python MCP server
├── src/
│   └── MCPx64dbg.cpp      # C++ plugin source (570 lines)
├── deps/
│   └── pluginsdk/         # x64dbg SDK headers
├── build/
│   └── MCPx64dbg.dp32     # Compiled plugin
├── CMakeLists.txt         # Build configuration
└── README.md              # This file
```

---

## 🎯 Features

✅ **Clean Architecture** - Modern C++ and Python
✅ **JSON Responses** - Structured data for Claude
✅ **Error Handling** - Proper error messages
✅ **MCP Resources** - Contextual information
✅ **MCP Prompts** - Guided workflows
✅ **Cross-Process** - No DLL injection needed
✅ **Safe** - Read-only by default
✅ **Fast** - Direct API access

---

## 🤝 Contributing

This is a rewrite of the original x64dbgMCP project with significant improvements:

- 63% code reduction in C++ plugin
- Complete Python rewrite with proper MCP support
- Added resources and prompts
- Better error handling
- Cleaner API design

---

## 📝 License

MIT License - Do whatever you want with this!

---

## 🙏 Credits

- Original idea from [Wasdubya/x64dbgMCP](https://github.com/Wasdubya/x64dbgMCP)
- Built for the x64dbg debugger
- Uses Anthropic's Model Context Protocol (MCP)

---

## 🔗 Links

- [x64dbg](https://x64dbg.com/) - The debugger
- [MCP Documentation](https://modelcontextprotocol.io/) - Protocol docs
- [Claude Desktop](https://claude.ai/download) - Get Claude

---

**Happy Reversing! 🔍**
