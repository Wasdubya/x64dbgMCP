<h1 align="center"><b> x64dbg MCP </b> </h1>



<p align="center">
  <a href="https://www.buymeacoffee.com/WASDUBYA" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="120"/>
  </a>
</p>
<p align="center">
  <img src="https://img.shields.io/github/stars/wasdubya/x64dbgmcp?style=for-the-badge" />
  <img src="https://img.shields.io/github/downloads/wasdubya/x64dbgmcp/total?style=for-the-badge" />
</p>

<div align="center"> An MCP server that can bridge various LLMS (Claude and Cursor tested) with the x64dbg debugger, providing direct access to debugging applications through prompts. This is the best open source dynamic analysis assistant combined with a smart model! </div>
<h2 align="center"> <b>Features</b> </h2>

- **40+ x64dbg SDK Tools** - Provides access to almost every single debugging feature given by the SDK for smart debugging. 
- **Cross-Architecture Support** - Works with both x64dbg and x32dbg.
- **API Compatibility** - Runable from cmd using the args given in the python file.
<br><br>

<b>Latest Features</b>(2/2026): 
- Symbol parsing by Module with pagination
- Thread management features 
- Xrefs by addr and string
- Removed log redirection upon the discovery of the GuiReferenceGetRowCount & GuiReferenceGetCellContent, with pagination.
<h2> Quick Setup </h2

1. **Download Plugin**
   - Grab .dp64 or .dp32 from this repo's build/release directory
   - Copy to your local: [x64dbg_dir]/release/x64/plugins/

2. **Configure Claude Desktop**
   - Copy x64dbgmcp.py from this repos src directory
   - Update local claude_desktop_config.json with path to x64dbgmcp.py

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "Path\\To\\Python",
      "args": [
        "Path\\to\\x64dbg.py"
      ]
    }
  }
}
```
      
4. **Start Debugging**
   - Launch x64dbg
   - Start Claude Desktop
   - Check plugin loaded successfully (ALT+L in x64dbg for logs)
<br>
<br>
<h2> Build from Source </h2>


- git clone [repository-url]
- cd x64dbgmcp
- cmake -S . -B build
- cmake --build build --target all_plugins --config Release

**TIP**

1. Use the --target all_plugins argument to specify both x32 and x64, otherwise use -A flag to distinguish between either x64 or Win32 build. For example 32 bit build would be:
- cmake -S . -B build32  -A Win32 -DBUILD_BOTH_ARCHES=OFF
- cmake --build build32 --config Release
<br>
<br>
<h2> Usage Examples </h2>


**Register inspection:**
```
"What's the current value of RAX and RIP registers?"
```

**Pattern searching:**
```
"Find the pattern '48 8B 05' in the current module"
```
**Example from [Cursor](https://github.com/Wasdubya/x64dbgMCP/blob/main/Cursor.Opus4.5-Find-PEB.md)**
<br>
<br>
**More Usage**
  - If you do not provide the model you are working with context of where your exe is, it wont have the capabiltiy to restart the binary if it crashes or hangs. So, provide it with the full path of the binary so it can call the CMDEXEC function like "init C:\Absolute\Path\to\EXE".
  - GetModuleBase is the best place to start for models so it will query for the right addresses, x64dbg will not respond to addresses out of range.

🧀 **Enjoy Automated Debugging** 🛎️
