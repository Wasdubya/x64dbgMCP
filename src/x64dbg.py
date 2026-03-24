"""
x64dbg MCP Enhanced Server - Enhanced version with typed command tools and documentation.

This module provides an MCP (Model Context Protocol) server for x64dbg integration.
It includes:
1. Generic ExecCommand for any x64dbg command
2. Typed command tools for high-frequency operations with built-in documentation
3. ListCommands tool for command discovery
"""

import sys
import os
import json
from typing import Any, Dict, List, Optional
import requests
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Default x64dbg HTTP server URL
DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"

def _resolve_server_url() -> str:
    """Resolve x64dbg server URL from environment or args."""
    env_url = os.getenv("X64DBG_URL")
    if env_url and env_url.startswith("http"):
        return env_url
    if len(sys.argv) > 1 and isinstance(sys.argv[1], str) and sys.argv[1].startswith("http"):
        return sys.argv[1]
    return DEFAULT_X64DBG_SERVER

x64dbg_server_url = _resolve_server_url()

def set_x64dbg_server_url(url: str) -> None:
    """Set the x64dbg server URL."""
    global x64dbg_server_url
    if url and url.startswith("http"):
        x64dbg_server_url = url

# Initialize FastMCP
mcp = FastMCP("x64dbg-mcp-enhanced")

# Load command database
_COMMAND_DB: Dict[str, Any] = {}

def _load_command_db() -> Dict[str, Any]:
    """Load the x64dbg command database from JSON file."""
    global _COMMAND_DB
    if _COMMAND_DB:
        return _COMMAND_DB

    db_path = Path(__file__).parent / "docs" / "x64dbg_commands.json"
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            _COMMAND_DB = json.load(f)
    except Exception as e:
        print(f"Warning: Could not load command database: {e}")
        _COMMAND_DB = {"categories": {}}

    return _COMMAND_DB

def safe_get(endpoint: str, params: dict = None) -> Any:
    """Perform a GET request to the x64dbg HTTP server."""
    if params is None:
        params = {}

    url = f"{x64dbg_server_url}{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=15)
        response.encoding = 'utf-8'
        if response.ok:
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post(endpoint: str, data: dict | str) -> Any:
    """Perform a POST request to the x64dbg HTTP server."""
    try:
        url = f"{x64dbg_server_url}{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)

        response.encoding = 'utf-8'

        if response.ok:
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


# =============================================================================
# Command Discovery Tool
# =============================================================================

@mcp.tool()
def ListCommands(category: str = "") -> dict:
    """
    List available x64dbg commands, optionally filtered by category.

    Parameters:
        category: Filter by category (debug_control, breakpoint, memory, searching,
                  analysis, thread, tracing, user_database, variables, general_purpose,
                  misc, gui, script, os_control). Leave empty for all commands.

    Returns:
        Dictionary with command information including descriptions and arguments.
    """
    db = _load_command_db()
    categories = db.get("categories", {})

    result = {"categories": {}}

    for cat_name, cat_data in categories.items():
        if category and category.lower() != cat_name.lower():
            continue

        cat_info = {
            "description": cat_data.get("description", ""),
            "commands": []
        }

        for cmd_name, cmd_data in cat_data.get("commands", {}).items():
            cmd_info = {
                "name": cmd_name,
                "aliases": cmd_data.get("aliases", []),
                "description": cmd_data.get("description", ""),
                "arguments": cmd_data.get("arguments", []),
                "result": cmd_data.get("result", "")
            }
            cat_info["commands"].append(cmd_info)

        result["categories"][cat_name] = cat_info

    result["total_categories"] = len(result["categories"])
    result["total_commands"] = sum(
        len(cat["commands"]) for cat in result["categories"].values()
    )

    return result


@mcp.tool()
def GetCommandHelp(command: str) -> dict:
    """
    Get detailed help for a specific x64dbg command.

    Parameters:
        command: Command name to get help for (e.g., "bp", "find", "init")

    Returns:
        Dictionary with command details including description, aliases, arguments, and result.
    """
    db = _load_command_db()
    categories = db.get("categories", {})

    command_lower = command.lower()

    for cat_name, cat_data in categories.items():
        for cmd_name, cmd_data in cat_data.get("commands", {}).items():
            # Check main name and aliases
            if cmd_name.lower() == command_lower:
                return {
                    "found": True,
                    "name": cmd_name,
                    "category": cat_name,
                    "aliases": cmd_data.get("aliases", []),
                    "description": cmd_data.get("description", ""),
                    "arguments": cmd_data.get("arguments", []),
                    "result": cmd_data.get("result", ""),
                    "usage_example": _generate_usage_example(cmd_name, cmd_data)
                }

            # Check aliases
            for alias in cmd_data.get("aliases", []):
                if alias.lower() == command_lower:
                    return {
                        "found": True,
                        "name": cmd_name,
                        "category": cat_name,
                        "aliases": cmd_data.get("aliases", []),
                        "description": cmd_data.get("description", ""),
                        "arguments": cmd_data.get("arguments", []),
                        "result": cmd_data.get("result", ""),
                        "usage_example": _generate_usage_example(cmd_name, cmd_data)
                    }

    return {"found": False, "error": f"Command '{command}' not found"}

def _generate_usage_example(cmd_name: str, cmd_data: dict) -> str:
    """Generate a usage example for a command."""
    args = cmd_data.get("arguments", [])
    if not args:
        return cmd_name

    parts = [cmd_name]
    for arg in args:
        name = arg.get("name", "arg")
        required = arg.get("required", False)
        if required:
            parts.append(f"<{name}>")
        else:
            parts.append(f"[{name}]")

    return " ".join(parts)


# =============================================================================
# Generic Command Execution
# =============================================================================

@mcp.tool()
def ExecCommand(cmd: str, offset: int = 0, limit: int = 100) -> dict:
    """
    Execute any x64dbg command and return its output.

    Use this for commands that don't have dedicated typed tools.
    Use ListCommands or GetCommandHelp to discover available commands.

    Parameters:
        cmd: x64dbg command to execute (e.g., "bp 0x401000", "find cip, \"48 8B\"")
        offset: Pagination offset for reference view results (default: 0)
        limit: Maximum number of reference view rows to return (default: 100, max: 5000)

    Returns:
        Dictionary with:
        - success: Whether the command executed successfully
        - refView: References tab data if the command populated it
    """
    return safe_get("ExecCommand", {"cmd": cmd, "offset": offset, "limit": limit})


# =============================================================================
# Debug Control Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdInit(filepath: str) -> dict:
    """
    Initialize debugging a file (load executable into x64dbg).

    Parameters:
        filepath: Path to the executable file to debug

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"init \"{filepath}\""})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdRun() -> dict:
    """
    Resume execution of the debugged process.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "run"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdStop() -> dict:
    """
    Stop debugging and detach from the process.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "stop"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdStepInto() -> dict:
    """
    Step into the next instruction (follow calls).

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "sti"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdStepOver() -> dict:
    """
    Step over the next instruction (skip calls).

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "sto"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdStepOut() -> dict:
    """
    Step out of current function (run until return).

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "rtr"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdAttach(pid: int) -> dict:
    """
    Attach debugger to a running process.

    Parameters:
        pid: Process ID to attach to (decimal or hex)

    Returns:
        Dictionary with success status
    """
    # x64dbg attach command requires hex format
    hex_pid = hex(pid) if isinstance(pid, int) else pid
    result = safe_get("ExecCommand", {"cmd": f"attach {hex_pid}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdDetach() -> dict:
    """
    Detach debugger from the debugged process.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "detach"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Breakpoint Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdSetBreakpoint(addr: str, name: str = "") -> dict:
    """
    Set a software breakpoint at the specified address.

    Parameters:
        addr: Address to set breakpoint at (hex string, e.g., "0x401000")
        name: Optional name for the breakpoint

    Returns:
        Dictionary with success status
    """
    cmd = f"bp {addr}"
    if name:
        cmd += f', "{name}"'
    result = safe_get("ExecCommand", {"cmd": cmd})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdDeleteBreakpoint(addr: str) -> dict:
    """
    Delete a software breakpoint.

    Parameters:
        addr: Address of the breakpoint to delete (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"bpc {addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSetHardwareBreakpoint(addr: str, type: str = "x", size: int = 1) -> dict:
    """
    Set a hardware breakpoint at the specified address.

    Hardware breakpoints use CPU debug registers (limited to 4).

    Parameters:
        addr: Address to set breakpoint at (hex string, e.g., "0x401000")
        type: Breakpoint type - "x" (execute, default), "r" (read), "w" (write)
        size: Size in bytes (1, 2, 4, or 8). Default is 1.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"bphws {addr}, {type}, {size}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdDeleteHardwareBreakpoint(addr: str) -> dict:
    """
    Delete a hardware breakpoint.

    Parameters:
        addr: Address of the hardware breakpoint to delete (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"bphwc {addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSetMemoryBreakpoint(addr: str, size: str = "", type: str = "") -> dict:
    """
    Set a memory breakpoint on a memory region.

    Parameters:
        addr: Address of the memory region (hex string)
        size: Size of the memory region (hex string). If not specified, uses page size.
        type: Type - "r" (read), "w" (write), "x" (execute)

    Returns:
        Dictionary with success status
    """
    cmd = f"bpm {addr}"
    if size:
        cmd += f", {size}"
    if type:
        cmd += f", {type}"
    result = safe_get("ExecCommand", {"cmd": cmd})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSetDllBreakpoint(dll_name: str) -> dict:
    """
    Set a DLL load breakpoint.

    Parameters:
        dll_name: Name of the DLL to break on (supports wildcards, e.g., "kernel32.dll", "ntdll*")

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"bpdll {dll_name}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Searching Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdFind(addr: str, pattern: str, size: str = "") -> dict:
    """
    Find a byte pattern in memory starting at the specified address.

    Parameters:
        addr: Start address (hex string, e.g., "0x401000" or "cip")
        pattern: Byte pattern with optional wildcards (e.g., "48 8B ?? ?? ?? ?? 8B")
        size: Size to search in bytes (hex string). Default is the memory region size.

    Returns:
        Dictionary with:
        - success: Whether pattern was found
        - address: Address of first match (if found)
        - refView: Search results
    """
    cmd = f"find {addr}, \"{pattern}\""
    if size:
        cmd += f", {size}"
    return safe_get("ExecCommand", {"cmd": cmd})

@mcp.tool()
def CmdFindAll(addr: str, pattern: str, size: str = "") -> dict:
    """
    Find all occurrences of a byte pattern in a memory page.

    Parameters:
        addr: Start address (hex string)
        pattern: Byte pattern with optional wildcards
        size: Size to search in bytes (hex string)

    Returns:
        Dictionary with:
        - success: Whether command executed
        - refView: All search results (rowCount and rows)
    """
    cmd = f"findall {addr}, \"{pattern}\""
    if size:
        cmd += f", {size}"
    return safe_get("ExecCommand", {"cmd": cmd, "limit": 5000})

@mcp.tool()
def CmdFindAllMem(addr: str, pattern: str, size: str = "", filter_type: str = "") -> dict:
    """
    Find all occurrences of a pattern in the entire memory map.

    Parameters:
        addr: Start address (hex string)
        pattern: Byte pattern with optional wildcards
        size: Size to search in bytes (hex string). Default is entire memory.
        filter_type: Filter - "user", "system", or "module"

    Returns:
        Dictionary with all search results across all memory regions
    """
    cmd = f"findallmem {addr}, \"{pattern}\""
    if size:
        cmd += f", {size}"
    if filter_type:
        cmd += f", {filter_type}"
    return safe_get("ExecCommand", {"cmd": cmd, "limit": 5000})

@mcp.tool()
def CmdFindAsm(instruction: str, addr: str = "", size: str = "") -> dict:
    """
    Find assembled instructions in memory.

    Parameters:
        instruction: Assembly instruction to find (quoted, e.g., "mov eax, ebx")
        addr: Start address (hex string). Default is CIP.
        size: Size to search in bytes (hex string)

    Returns:
        Dictionary with instruction search results
    """
    cmd = f'findasm "{instruction}"'
    if addr:
        cmd += f", {addr}"
    if size:
        cmd += f", {size}"
    return safe_get("ExecCommand", {"cmd": cmd, "limit": 5000})

@mcp.tool()
def CmdFindRef(value: str, addr: str = "", size: str = "") -> dict:
    """
    Find references to a specific value in memory.

    Parameters:
        value: Value to find references to (hex string)
        addr: Start address (hex string). Default is CIP.
        size: Size to search in bytes (hex string)

    Returns:
        Dictionary with reference search results
    """
    cmd = f"reffind {value}"
    if addr:
        cmd += f", {addr}"
    if size:
        cmd += f", {size}"
    return safe_get("ExecCommand", {"cmd": cmd, "limit": 5000})

@mcp.tool()
def CmdFindStrings(addr: str = "", size: str = "") -> dict:
    """
    Find all referenced text strings in memory.

    Parameters:
        addr: Start address (hex string). Default is CIP.
        size: Size to search in bytes (hex string)

    Returns:
        Dictionary with string references (rowCount and rows with string addresses/content)
    """
    cmd = "refstr"
    if addr:
        cmd += f" {addr}"
    if size:
        cmd += f", {size}"
    return safe_get("ExecCommand", {"cmd": cmd, "limit": 5000})

@mcp.tool()
def CmdFindIntermodCalls(addr: str = "", size: str = "") -> dict:
    """
    Find all inter-modular calls (calls to other modules/DLLs).

    Parameters:
        addr: Start address (hex string). Default is CIP.
        size: Size to search in bytes (hex string)

    Returns:
        Dictionary with inter-modular call references
    """
    cmd = "modcallfind"
    if addr:
        cmd += f" {addr}"
    if size:
        cmd += f", {size}"
    return safe_get("ExecCommand", {"cmd": cmd, "limit": 5000})


# =============================================================================
# Memory Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdAlloc(size: str, addr: str = "0") -> dict:
    """
    Allocate memory in the debuggee's address space.

    Parameters:
        size: Size in bytes to allocate (hex string, e.g., "0x1000")
        addr: Preferred base address (hex string). Default "0" for any address.

    Returns:
        Dictionary with:
        - success: Whether allocation succeeded
        - address: Allocated memory address (from $result)
    """
    result = safe_get("ExecCommand", {"cmd": f"alloc {size}, {addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdFree(addr: str) -> dict:
    """
    Free memory in the debuggee's address space.

    Parameters:
        addr: Address of memory to free (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"free {addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdMemFill(addr: str, size: str, value: str) -> dict:
    """
    Fill memory with a byte value.

    Parameters:
        addr: Start address (hex string)
        size: Size of region to fill (hex string)
        value: Byte value to fill with (hex, e.g., "0x90" for NOP)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"memset {addr}, {size}, {value}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSetPageRights(addr: str, rights: str) -> dict:
    """
    Set memory page protection rights.

    Parameters:
        addr: Address of the page (hex string)
        rights: Rights string (e.g., "rwx", "rx", "rw", "r")

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"setpagerights {addr}, {rights}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSaveData(filepath: str, addr: str, size: str) -> dict:
    """
    Save memory region to a file.

    Parameters:
        filepath: Path to save the file
        addr: Start address (hex string)
        size: Size of region to save (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f'savedata "{filepath}", {addr}, {size}'})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Analysis Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdAnalyze() -> dict:
    """
    Perform function analysis on the current module.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "anal"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdAnalyzeFunction(addr: str) -> dict:
    """
    Perform analysis on a single function.

    Parameters:
        addr: Base address of the function (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"analr {addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdAnalyzeXrefs() -> dict:
    """
    Perform cross-reference analysis on the current module.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "analx"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdDownloadSymbols(module: str = "") -> dict:
    """
    Download symbols from a Symbol Store.

    Parameters:
        module: Module name (e.g., "kernel32.dll"). If empty, downloads for all modules.

    Returns:
        Dictionary with success status
    """
    cmd = "symdownload"
    if module:
        cmd += f" {module}"
    result = safe_get("ExecCommand", {"cmd": cmd})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# User Database Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdSetComment(addr: str, text: str) -> dict:
    """
    Set a comment at an address.

    Parameters:
        addr: Address to set the comment at (hex string)
        text: Comment text

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f'cmt {addr}, "{text}"'})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSetLabel(addr: str, text: str) -> dict:
    """
    Set a label at an address.

    Parameters:
        addr: Address to set the label at (hex string)
        text: Label text (no spaces allowed)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f'lbl {addr}, "{text}"'})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdSetBookmark(addr: str) -> dict:
    """
    Set a bookmark at an address.

    Parameters:
        addr: Address to set the bookmark at (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"bookmark {addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdAddFunction(start_addr: str, end_addr: str) -> dict:
    """
    Add a function definition.

    Parameters:
        start_addr: Function start address (hex string)
        end_addr: Function end address (hex string)

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"func {start_addr}, {end_addr}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Misc Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdAssemble(addr: str, instruction: str, fill_nops: bool = False) -> dict:
    """
    Assemble an instruction at the specified address.

    Parameters:
        addr: Address to place the assembled instruction (hex string)
        instruction: Assembly instruction text (e.g., "mov eax, 1")
        fill_nops: If True, fill remainder of previous instruction with NOPs

    Returns:
        Dictionary with:
        - success: Whether assembly succeeded
        - size: Size of assembled instruction (from $result)
    """
    cmd = f'asm {addr}, "{instruction}"'
    if fill_nops:
        cmd += ", 1"
    result = safe_get("ExecCommand", {"cmd": cmd})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdGetProcAddr(export_name: str, dll_name: str = "") -> dict:
    """
    Get the address of an export inside a DLL.

    Parameters:
        export_name: Name of the exported function
        dll_name: Optional DLL name

    Returns:
        Dictionary with:
        - success: Whether export was found
        - address: Export address (from $result)
    """
    cmd = f"gpa {export_name}"
    if dll_name:
        cmd += f", {dll_name}"
    result = safe_get("ExecCommand", {"cmd": cmd})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdLoadDll(dll_path: str) -> dict:
    """
    Load a DLL into the debugged process.

    Parameters:
        dll_path: Path or name of the DLL to load

    Returns:
        Dictionary with:
        - success: Whether load succeeded
        - address: Loaded library address (from $result)
    """
    result = safe_get("ExecCommand", {"cmd": f'loadlib "{dll_path}"'})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdHideDebugger() -> dict:
    """
    Hide the debugger from simple detection methods.
    Modifies PEB so IsDebuggerPresent() returns false.

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": "dbh"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Tracing Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdTraceInto(condition: str) -> dict:
    """
    Trace into instructions until condition is met.

    Parameters:
        condition: Condition expression (e.g., "cip == 0x401000", "eax == 0")

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"ticnd {condition}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdTraceOver(condition: str) -> dict:
    """
    Trace over instructions until condition is met.

    Parameters:
        condition: Condition expression

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f"tocnd {condition}"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Script Commands (Typed)
# =============================================================================

@mcp.tool()
def CmdLog(message: str = "") -> dict:
    """
    Output a message to the x64dbg log.

    Parameters:
        message: Message to log (supports string formatting)

    Returns:
        Dictionary with success status
    """
    if message:
        result = safe_get("ExecCommand", {"cmd": f'log "{message}"'})
    else:
        result = safe_get("ExecCommand", {"cmd": "log"})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}

@mcp.tool()
def CmdExecScript(script_path: str) -> dict:
    """
    Load and execute a script file.

    Parameters:
        script_path: Path to the script file

    Returns:
        Dictionary with success status
    """
    result = safe_get("ExecCommand", {"cmd": f'scriptexec "{script_path}"'})
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Stack Operations (from original implementation)
# =============================================================================

@mcp.tool()
def StackPeek(offset: str = "0") -> str:
    """
    Peek at stack value using Script API.

    Parameters:
        offset: Stack offset (default: "0")

    Returns:
        Stack value in hex format
    """
    return safe_get("Stack/Peek", {"offset": offset})

@mcp.tool()
def StackPop() -> str:
    """
    Pop value from stack using Script API.

    Returns:
        Popped value in hex format
    """
    return safe_get("Stack/Pop")

@mcp.tool()
def StackPush(value: str) -> str:
    """
    Push value to stack using Script API.

    Parameters:
        value: Value to push (in hex format, e.g., "0x1000")

    Returns:
        Previous top value in hex format
    """
    return safe_get("Stack/Push", {"value": value})


# =============================================================================
# CPU Flags Operations (from original implementation)
# =============================================================================

@mcp.tool()
def FlagGet(flag: str) -> bool:
    """
    Get CPU flag value using TitanEngine.

    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)

    Returns:
        Flag value (True/False)
    """
    result = safe_get("Flag/Get", {"flag": flag})
    if isinstance(result, bool):
        return result
    if isinstance(result, str):
        return result.lower() == "true"
    return False

@mcp.tool()
def FlagSet(flag: str, value: bool) -> str:
    """
    Set CPU flag value using Script API.

    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
        value: Flag value (True/False)

    Returns:
        Status message
    """
    return safe_get("Flag/Set", {"flag": flag, "value": "true" if value else "false"})


# =============================================================================
# Memory Utilities (from original implementation)
# =============================================================================

@mcp.tool()
def MemoryIsValidPtr(addr: str) -> bool:
    """
    Check if memory address is valid.

    Parameters:
        addr: Memory address (in hex format, e.g., "0x1000")

    Returns:
        True if valid, False otherwise
    """
    result = safe_get("Memory/IsValidPtr", {"addr": addr})
    if isinstance(result, str):
        return result.lower() == "true"
    return False

@mcp.tool()
def MemoryGetProtect(addr: str) -> str:
    """
    Get memory protection flags.

    Parameters:
        addr: Memory address (in hex format, e.g., "0x1000")

    Returns:
        Protection flags in hex format
    """
    return safe_get("Memory/GetProtect", {"addr": addr})

@mcp.tool()
def MemoryBase(addr: str) -> dict:
    """
    Find the base address and size of a module containing the given address.

    Parameters:
        addr: Memory address (in hex format, e.g., "0x7FF12345")

    Returns:
        Dictionary containing base_address and size of the module
    """
    result = safe_get("MemoryBase", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            if "," in result:
                parts = result.split(",")
                return {"base_address": parts[0], "size": parts[1]}
            return {"raw_response": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Debug Control (Extended from original)
# =============================================================================

@mcp.tool()
def CmdPause() -> dict:
    """
    Pause execution of the debugged process.

    Returns:
        Dictionary with success status
    """
    result = safe_get("Debug/Pause")
    if isinstance(result, dict):
        return result
    return {"success": "Error" not in str(result), "raw": result}


# =============================================================================
# Assembler Operations (from original implementation)
# =============================================================================

@mcp.tool()
def AssemblerAssemble(addr: str, instruction: str) -> dict:
    """
    Assemble instruction at address using Script API.

    Parameters:
        addr: Memory address (in hex format, e.g., "0x1000")
        instruction: Assembly instruction (e.g., "mov eax, 1")

    Returns:
        Dictionary with assembly result including bytes and size
    """
    result = safe_get("Assembler/Assemble", {"addr": addr, "instruction": instruction})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse assembly result", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def AssemblerAssembleMem(addr: str, instruction: str) -> str:
    """
    Assemble instruction directly into memory using Script API.

    Parameters:
        addr: Memory address (in hex format, e.g., "0x1000")
        instruction: Assembly instruction (e.g., "mov eax, 1")

    Returns:
        Status message
    """
    return safe_get("Assembler/AssembleMem", {"addr": addr, "instruction": instruction})


# =============================================================================
# Pattern Search (from original implementation)
# =============================================================================

@mcp.tool()
def PatternFindMem(start: str, size: str, pattern: str) -> str:
    """
    Find pattern in memory using Script API.

    Parameters:
        start: Start address (in hex format, e.g., "0x1000")
        size: Size to search IN DECIMAL
        pattern: Pattern to find (e.g., "48 8B 05 ?? ?? ?? ??")

    Returns:
        Found address in hex format or error message
    """
    return safe_get("Pattern/FindMem", {"start": start, "size": size, "pattern": pattern})


# =============================================================================
# Miscellaneous Utilities (from original implementation)
# =============================================================================

@mcp.tool()
def MiscParseExpression(expression: str) -> str:
    """
    Parse expression using Script API.

    Parameters:
        expression: Expression to parse (e.g., "[esp+8]", "cip+10")

    Returns:
        Parsed value in hex format
    """
    return safe_get("Misc/ParseExpression", {"expression": expression})

@mcp.tool()
def MiscRemoteGetProcAddress(module: str, api: str) -> str:
    """
    Get remote procedure address using Script API.

    Parameters:
        module: Module name (e.g., "kernel32.dll")
        api: API name (e.g., "GetProcAddress")

    Returns:
        Function address in hex format
    """
    return safe_get("Misc/RemoteGetProcAddress", {"module": module, "api": api})


# =============================================================================
# Disassembly Operations (from original implementation)
# =============================================================================

@mcp.tool()
def DisasmGetInstructionRange(addr: str, count: int = 1) -> list:
    """
    Get disassembly of multiple instructions starting at the specified address.

    Parameters:
        addr: Memory address (in hex format, e.g., "0x1000")
        count: Number of instructions to disassemble (default: 1, max: 100)

    Returns:
        List of dictionaries containing instruction details
    """
    result = safe_get("Disasm/GetInstructionRange", {"addr": addr, "count": str(count)})
    if isinstance(result, list):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return [{"error": "Failed to parse disassembly result", "raw": result}]
    return [{"error": "Unexpected response format"}]

@mcp.tool()
def StepInWithDisasm() -> dict:
    """
    Step into the next instruction and return both step result and current instruction disassembly.

    Returns:
        Dictionary containing step result and current instruction info
    """
    result = safe_get("Disasm/StepInWithDisasm")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse step result", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Symbol Operations (from original implementation)
# =============================================================================

@mcp.tool()
def QuerySymbols(module: str, offset: int = 0, limit: int = 5000) -> dict:
    """
    Enumerate symbols for a specific module. Use GetModuleList first to discover module names.
    Returns imports, exports, and user-defined function symbols for the given module.

    Parameters:
        module: Module name to query symbols for (e.g., "kernel32.dll", "ntdll.dll"). Required.
        offset: Pagination offset - number of symbols to skip (default: 0)
        limit: Maximum number of symbols to return per page (default: 5000, max: 50000)

    Returns:
        Dictionary with:
        - total: Total number of symbols in the module
        - module: The module name queried
        - symbols: List of symbol objects with rva, name, manual, type fields
    """
    params = {"module": module, "offset": str(offset), "limit": str(limit)}
    result = safe_get("SymbolEnum", params)
    if isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return result


# =============================================================================
# Thread Operations (from original implementation)
# =============================================================================

@mcp.tool()
def GetThreadList() -> dict:
    """
    Get list of all threads in the debugged process with detailed information.

    Returns:
        Dictionary with:
        - count: Number of threads
        - currentThread: Index of the currently focused thread
        - threads: List of thread objects with threadNumber, threadId, threadName,
          startAddress, localBase, cip, suspendCount, priority, waitReason,
          lastError, cycles
    """
    result = safe_get("GetThreadList")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse thread list", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetTebAddress(tid: str) -> dict:
    """
    Get the Thread Environment Block (TEB) address for a specific thread.
    Use GetThreadList first to discover thread IDs.

    Parameters:
        tid: Thread ID (decimal integer string, e.g., "1234")

    Returns:
        Dictionary with tid and tebAddress fields
    """
    result = safe_get("GetTebAddress", {"tid": tid})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse TEB response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# String Operations (from original implementation)
# =============================================================================

@mcp.tool()
def StringGetAt(addr: str) -> dict:
    """
    Retrieve the string at a given address in the debugged process.
    Uses x64dbg's internal string detection (same as the disassembly view).

    Parameters:
        addr: Memory address (in hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a string was detected at that address
        - string: The string content (empty if not found)
    """
    result = safe_get("String/GetAt", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Cross-Reference Operations (from original implementation)
# =============================================================================

@mcp.tool()
def XrefGet(addr: str) -> dict:
    """
    Get all cross-references (xrefs) TO the specified address.
    Returns the list of addresses that reference the target address,
    along with the type of each reference (data, jmp, call).

    Note: Results depend on x64dbg's analysis database. Run analysis
    first for comprehensive results.

    Parameters:
        addr: Target address to find references to (hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried target address
        - refcount: Number of cross-references found
        - references: List of reference objects, each with:
          - addr: Address of the referrer (the instruction that references the target)
          - type: Reference type ("data", "jmp", "call", or "none")
          - string: Optional string context at the referrer address
    """
    result = safe_get("Xref/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def XrefCount(addr: str) -> dict:
    """
    Get the count of cross-references to the specified address.
    This is a lightweight check that doesn't fetch the full reference list.

    Parameters:
        addr: Target address to count references for (hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - count: Number of cross-references
    """
    result = safe_get("Xref/Count", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Branch Destination (from original implementation)
# =============================================================================

@mcp.tool()
def GetBranchDestination(addr: str) -> dict:
    """
    Get the destination address of a branch instruction (jmp, call, jcc, etc.).
    Resolves where the branch at the given address would jump/call to.

    Parameters:
        addr: Address of the branch instruction (hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried instruction address
        - destination: The resolved target address
        - resolved: Whether the destination was successfully resolved
    """
    result = safe_get("GetBranchDestination", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Label Operations (from original implementation)
# =============================================================================

@mcp.tool()
def LabelSet(addr: str, text: str) -> dict:
    """
    Set a label at the specified address in x64dbg.
    Labels appear in the disassembly view and are useful for marking important addresses.

    Parameters:
        addr: Address to set the label at (hex format, e.g., "0x1400010a0")
        text: Label text (e.g., "main_decrypt_loop")

    Returns:
        Dictionary with success status, address, and label text
    """
    result = safe_get("Label/Set", {"addr": addr, "text": text})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def LabelGet(addr: str) -> dict:
    """
    Get the label at the specified address.

    Parameters:
        addr: Address to query (hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a label exists at that address
        - label: The label text (empty if not found)
    """
    result = safe_get("Label/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def LabelList() -> dict:
    """
    Get all labels defined in the current debugging session.

    Returns:
        Dictionary with:
        - count: Number of labels
        - labels: List of label objects with module, rva, text, and manual fields
    """
    result = safe_get("Label/List")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Comment Operations (from original implementation)
# =============================================================================

@mcp.tool()
def CommentSet(addr: str, text: str) -> dict:
    """
    Set a comment at the specified address in x64dbg.
    Comments appear in the disassembly view next to the instruction.

    Parameters:
        addr: Address to set the comment at (hex format, e.g., "0x1400010a0")
        text: Comment text

    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Comment/Set", {"addr": addr, "text": text})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def CommentGet(addr: str) -> dict:
    """
    Get the comment at the specified address.

    Parameters:
        addr: Address to query (hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a comment exists
        - comment: The comment text
    """
    result = safe_get("Comment/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Patch Operations (from original implementation)
# =============================================================================

@mcp.tool()
def GetPatchList() -> dict:
    """
    Enumerate all memory patches applied in the current debugging session.
    Shows original and patched byte values for each patched address.

    Returns:
        Dictionary with:
        - count: Number of patches
        - patches: List of patch objects with module, address, oldByte, newByte
    """
    result = safe_get("Patch/List")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetPatchAt(addr: str) -> dict:
    """
    Check if a specific address has been patched and get patch details.

    Parameters:
        addr: Address to check (hex format, e.g., "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - patched: Whether the address is patched
        - module: Module name (if patched)
        - oldByte: Original byte value (if patched)
        - newByte: Patched byte value (if patched)
    """
    result = safe_get("Patch/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Existing Tools (from original implementation)
# =============================================================================

@mcp.tool()
def IsDebugActive() -> bool:
    """Check if debugger is active (running)."""
    result = safe_get("IsDebugActive")
    if isinstance(result, dict) and "isRunning" in result:
        return result["isRunning"] is True
    return False

@mcp.tool()
def IsDebugging() -> bool:
    """Check if x64dbg is debugging a process."""
    result = safe_get("Is_Debugging")
    if isinstance(result, dict) and "isDebugging" in result:
        return result["isDebugging"] is True
    return False

@mcp.tool()
def GetProcessId() -> dict:
    """
    Get the process ID of the currently debugged process.

    Returns:
        Dictionary with 'pid' field containing the process ID
    """
    result = safe_get("Debug/GetProcessId")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": result}
    return {"error": "Unexpected response"}

@mcp.tool()
def GetValue(expression: str) -> str:
    """
    Evaluate an expression and return its value.

    Parameters:
        expression: Expression to evaluate (e.g., "$pid", "cip", "eax", "0x401000+10")

    Returns:
        The evaluated value as hex string (e.g., "0x1234")
    """
    # Handle x64dbg internal variables like $pid, $tid, etc.
    # These need special format for ParseExpression
    if expression.startswith("$"):
        result = safe_get("ExecCommand", {"cmd": f"? {expression}"})
        # The result is in the log, ExecCommand returns success status
        # We need to use a different approach - try direct evaluation
        result = safe_get("Misc/ParseExpression", {"expression": expression})
        if isinstance(result, str) and not result.startswith("Error"):
            return result
        # Fallback: return the raw result
        return result
    return safe_get("Misc/ParseExpression", {"expression": expression})

@mcp.tool()
def RegisterGet(register: str) -> str:
    """Get register value (e.g., "eax", "rax", "rip")."""
    return safe_get("Register/Get", {"register": register})

@mcp.tool()
def RegisterSet(register: str, value: str) -> str:
    """Set register value."""
    return safe_get("Register/Set", {"register": register, "value": value})

@mcp.tool()
def MemoryRead(addr: str, size: str) -> str:
    """Read memory at address."""
    return safe_get("Memory/Read", {"addr": addr, "size": size})

@mcp.tool()
def MemoryWrite(addr: str, data: str) -> str:
    """Write data to memory address."""
    return safe_get("Memory/Write", {"addr": addr, "data": data})

@mcp.tool()
def GetModuleList() -> list:
    """Get list of loaded modules."""
    result = safe_get("GetModuleList")
    if isinstance(result, list):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return [{"raw": result}]
    return [{"error": "Unexpected response format"}]

@mcp.tool()
def GetMemoryMap() -> dict:
    """Get the full virtual memory map of the debugged process."""
    result = safe_get("MemoryMap")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetWorkingSet(addr: str) -> dict:
    """
    Get the working set information for a specific memory address.

    Uses NtQueryVirtualMemory with MemoryWorkingSetExInformation to query
    detailed page attributes including valid, share count, protection, etc.

    Parameters:
        addr: Address to query (hex string, e.g., "0x7ff734f10000")

    Returns:
        Dictionary with working set attributes:
        - valid: Whether the page is valid (committed and in working set)
        - shareCount: Number of processes sharing this page
        - win32Protection: Win32 page protection (PAGE_* flags)
        - shared: Whether the page is shared
        - node: NUMA node number
        - locked: Whether the page is locked in memory
        - largePage: Whether this is a large page
        - priority: Page priority
        - sharedOriginal: Whether this is the original shared page
        - bad: Whether the page has errors
        - win32GraphicsProtection: Graphics protection flags (x64 only)
    """
    result = safe_get("Memory/WorkingSet", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetMemoryInfo(addr: str) -> dict:
    """
    Get comprehensive memory information for a specific address.

    Combines VirtualQuery and WorkingSet information into a single query.
    Returns all memory attributes including state, type, protection,
    allocation info, and working set details.

    Parameters:
        addr: Address to query (hex string, e.g., "0x7ff734f10000")

    Returns:
        Dictionary with memory attributes:
        - address: The queried address
        - base: Memory region base address
        - allocationBase: Original allocation base address
        - size: Memory region size
        - state: MEM_COMMIT / MEM_RESERVE / MEM_FREE
        - type: IMG / MAP / PRV
        - protect: Current protection (ERW, ER-, -RW, etc.)
        - protectValue: Raw protection value (e.g., 0x40)
        - allocationProtect: Original allocation protection
        - allocationProtectValue: Raw allocation protection value
        - module: Module name if address is in a module
        - workingSet: Working set attributes (if committed):
            - valid: Page is valid
            - shareCount: Number of processes sharing
            - win32Protection: Page protection
            - shared: Is shared page
            - node: NUMA node
            - locked: Is locked in memory
            - largePage: Is large page
            - priority: Page priority
            - sharedOriginal: Is original shared page
            - bad: Page has errors
            - win32GraphicsProtection: Graphics protection (x64)
    """
    result = safe_get("Memory/Info", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetRegisterDump() -> dict:
    """Get a complete dump of all CPU registers."""
    result = safe_get("RegisterDump")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetBreakpointList(type: str = "all") -> dict:
    """Get list of all breakpoints."""
    result = safe_get("Breakpoint/List", {"type": type})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def GetCallStack() -> dict:
    """Get the current call stack."""
    result = safe_get("GetCallStack")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def EnumHandles() -> dict:
    """Enumerate all open handles in the debugged process."""
    result = safe_get("EnumHandles")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def EnumTcpConnections() -> dict:
    """Enumerate all TCP connections of the debugged process."""
    result = safe_get("EnumTcpConnections")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--serve", "serve"):
            mcp.run()
        else:
            print(f"Usage: {sys.argv[0]} [--serve]")
            print("  --serve: Run MCP server")
    else:
        mcp.run()