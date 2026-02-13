<h1 align="center"><b> x64dbg MCP </b> </h1>



<p align="center">
  <a href="https://www.buymeacoffee.com/WASDUBYA" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="200"/>
  </a>
</p>

<h2 align="center"> <b>Model Context Protocol for x64dbg</b> </h2>

<div align="center"> An MCP server that can bridge various LLMS with the x64dbg debugger, providing direct access to debugging functionality through prompts! </div>
<h2 align="center"> <b>Features</b> </h2>

- **40+ x64dbg SDK Tools** - Provides access to almost every single debugging feature given by the SDK for smart debugging. 
- **Cross-Architecture Support** - Works with both x64dbg and x32dbg.
- **API Compatibility** :
     - Runable from cmd using the args given in the python file. (API Key, max tool calls, Claude is limited to 25 but the api has a much higher limit.)
     - *IF* you have issues connecting to the x64dbg session from the python file, open the logs tab in x64dbg to view what port the plugin is running on and add that as the argument to your python script.   

<b>Latest Features</b>(2/2026): 
- Symbol parsing by Module 
- Thread management features 

### Quick Setup

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

### Build from Source


- git clone [repository-url]
- cd x64dbgmcp
- cmake -S . -B build
- cmake --build build --target all_plugins --config Release

🟨**---TIPS---**🟨

1. Use the --target all_plugins argument to specify both x32 and x64, otherwise use -A flag to distinguish between either x64 or Win32 build. For example 32 bit build would be:
- cmake -S . -B build32  -A Win32 -DBUILD_BOTH_ARCHES=OFF
- cmake --build build32 --config Release

2. If you do not provide the model you are working with with context of where your exe is, it wont have the capabiltiy to restart the binary if it crashes or hangs. So, provide it with the full path of the binary so it can call the CMDEXEC function like "init C:\Absolute\Path\to\EXE"

</b> This will allow for even more automated analysis. </b> 

## Usage Examples


**Register inspection:**
```
"What's the current value of RAX and RIP registers?"
```

**Pattern searching:**
```
"Find the pattern '48 8B 05' in the current module"
```
**Example from [Cursor](https://github.com/Wasdubya/x64dbgMCP/blob/main/Cursor.Opus4.5-Find-PEB.md)**
