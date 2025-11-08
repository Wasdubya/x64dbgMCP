#!/usr/bin/env python3
"""
x32dbg MCP Server - Model Context Protocol server for x32dbg debugger
Provides Claude with direct access to x32dbg debugging capabilities
"""

import os
import sys
from typing import Optional, Dict, Any, List
import requests
from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("x32dbg")

# Configuration
X64DBG_URL = os.getenv("X64DBG_URL", "http://127.0.0.1:8888")
REQUEST_TIMEOUT = 5

#=============================================================================
# HTTP Communication Layer
#=============================================================================

class DebuggerError(Exception):
    """Raised when debugger operations fail"""
    pass

def api_request(endpoint: str, params: Optional[Dict[str, str]] = None) -> Any:
    """Make HTTP request to x32dbg plugin and return parsed response"""
    try:
        url = f"{X64DBG_URL}{endpoint}"
        response = requests.get(url, params=params or {}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        # Try to parse as JSON first
        try:
            return response.json()
        except ValueError:
            # Return text if not JSON
            return response.text.strip()

    except requests.exceptions.Timeout:
        raise DebuggerError("Request timed out - is x32dbg running?")
    except requests.exceptions.ConnectionError:
        raise DebuggerError("Cannot connect to x32dbg - is the plugin loaded?")
    except requests.exceptions.HTTPError as e:
        raise DebuggerError(f"HTTP error {e.response.status_code}: {e.response.text}")
    except Exception as e:
        raise DebuggerError(f"Unexpected error: {str(e)}")

#=============================================================================
# MCP Resources - Contextual Information
#=============================================================================

@mcp.resource("debugger://status")
def get_debugger_status() -> str:
    """Get current debugger status and basic information"""
    try:
        status = api_request("/status")
        return f"""Debugger Status:
- Architecture: {status.get('arch', 'unknown')}
- Debugging Active: {status.get('debugging', False)}
- Process Running: {status.get('running', False)}
- Plugin Version: {status.get('version', 'unknown')}
"""
    except DebuggerError as e:
        return f"Error: {str(e)}"

@mcp.resource("debugger://modules")
def get_loaded_modules() -> str:
    """Get list of all loaded modules in the debugged process"""
    try:
        modules = api_request("/modules")
        if not modules:
            return "No modules loaded (process not running?)"

        result = f"Loaded Modules ({len(modules)}):\n\n"
        for mod in modules:
            result += f"📦 {mod['name']}\n"
            result += f"   Base: {mod['base']}\n"
            result += f"   Size: {mod['size']}\n"
            result += f"   Entry: {mod['entry']}\n"
            result += f"   Path: {mod['path']}\n\n"

        return result
    except DebuggerError as e:
        return f"Error: {str(e)}"

#=============================================================================
# MCP Prompts - Common RE Tasks
#=============================================================================

@mcp.prompt()
def analyze_function() -> str:
    """Start analyzing a function in the debugged process"""
    return """I'll help you analyze this function. Let me:
1. Check the current debugging state
2. Get the current instruction pointer (EIP/RIP)
3. Disassemble the function
4. Examine registers and stack

First, let me check the debugger status..."""

@mcp.prompt()
def find_crypto() -> str:
    """Look for cryptographic operations in the current module"""
    return """I'll search for common crypto patterns. Let me:
1. Get the current module information
2. Search for crypto constants (magic numbers)
3. Look for suspicious loops and XOR operations
4. Check for common crypto function names

Starting analysis..."""

@mcp.prompt()
def trace_execution() -> str:
    """Set up execution tracing from current location"""
    return """I'll set up execution tracing. Let me:
1. Get current location
2. Set strategic breakpoints
3. Configure step-through analysis
4. Monitor register changes

Preparing trace..."""

#=============================================================================
# MCP Tools - Debugger Operations
#=============================================================================

@mcp.tool()
def get_status() -> Dict[str, Any]:
    """Get current debugger status including architecture and process state

    Returns:
        Dictionary with debugger status information
    """
    try:
        return api_request("/status")
    except DebuggerError as e:
        return {"error": str(e), "debugging": False, "running": False}

@mcp.tool()
def execute_command(cmd: str) -> Dict[str, Any]:
    """Execute a raw x32dbg command

    Args:
        cmd: Command to execute (e.g., "bp main", "disasm 0x401000")

    Returns:
        Dictionary with execution result
    """
    try:
        return api_request("/cmd", {"cmd": cmd})
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def get_register(name: str) -> Dict[str, Any]:
    """Get value of a CPU register

    Args:
        name: Register name (e.g., "eax", "ebx", "eip", "esp")

    Returns:
        Dictionary with register name and value in hex format
    """
    try:
        return api_request("/register/get", {"name": name})
    except DebuggerError as e:
        return {"error": str(e), "register": name}

@mcp.tool()
def set_register(name: str, value: str) -> Dict[str, bool]:
    """Set value of a CPU register

    Args:
        name: Register name (e.g., "eax", "ebx")
        value: Value to set (hex format, e.g., "0x1000" or decimal)

    Returns:
        Dictionary indicating success or failure
    """
    try:
        return api_request("/register/set", {"name": name, "value": value})
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def read_memory(addr: str, size: int = 16) -> Dict[str, Any]:
    """Read memory from the debugged process

    Args:
        addr: Memory address in hex format (e.g., "0x401000")
        size: Number of bytes to read (default: 16, max: 1024)

    Returns:
        Dictionary with address, size, and hex data
    """
    try:
        size = min(size, 1024)  # Safety limit
        result = api_request("/memory/read", {"addr": addr, "size": str(size)})

        # Add ASCII interpretation if data is present
        if "data" in result:
            hex_data = result["data"]
            ascii_str = ""
            for i in range(0, len(hex_data), 2):
                byte = int(hex_data[i:i+2], 16)
                ascii_str += chr(byte) if 32 <= byte < 127 else "."
            result["ascii"] = ascii_str

        return result
    except DebuggerError as e:
        return {"error": str(e), "address": addr}

@mcp.tool()
def write_memory(addr: str, data: str) -> Dict[str, Any]:
    """Write memory to the debugged process

    Args:
        addr: Memory address in hex format (e.g., "0x401000")
        data: Hex string to write (e.g., "90909090" for NOPs)

    Returns:
        Dictionary indicating success and bytes written
    """
    try:
        return api_request("/memory/write", {"addr": addr, "data": data})
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def step_execution() -> Dict[str, bool]:
    """Step into the next instruction (single step)

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/debug/step")
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def step_over() -> Dict[str, bool]:
    """Step over the next instruction (skip calls)

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/debug/stepover")
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def step_out() -> Dict[str, bool]:
    """Step out of current function (return to caller)

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/debug/stepout")
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def run_process() -> Dict[str, bool]:
    """Resume execution of the debugged process

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/debug/run")
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def pause_process() -> Dict[str, bool]:
    """Pause execution of the debugged process

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/debug/pause")
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def set_breakpoint(addr: str) -> Dict[str, bool]:
    """Set a breakpoint at specified address

    Args:
        addr: Memory address in hex format (e.g., "0x401000")

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/breakpoint/set", {"addr": addr})
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def delete_breakpoint(addr: str) -> Dict[str, bool]:
    """Delete a breakpoint at specified address

    Args:
        addr: Memory address in hex format (e.g., "0x401000")

    Returns:
        Dictionary indicating success
    """
    try:
        return api_request("/breakpoint/delete", {"addr": addr})
    except DebuggerError as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def disassemble_at(addr: str) -> Dict[str, Any]:
    """Disassemble instruction at specified address

    Args:
        addr: Memory address in hex format (e.g., "0x401000")

    Returns:
        Dictionary with address, instruction text, and size
    """
    try:
        return api_request("/disasm", {"addr": addr})
    except DebuggerError as e:
        return {"error": str(e), "address": addr}

@mcp.tool()
def get_modules() -> List[Dict[str, str]]:
    """Get list of all loaded modules in the process

    Returns:
        List of dictionaries containing module information (name, base, size, entry, path)
    """
    try:
        modules = api_request("/modules")
        return modules if isinstance(modules, list) else []
    except DebuggerError as e:
        return [{"error": str(e)}]

@mcp.tool()
def analyze_current_location() -> Dict[str, Any]:
    """Get comprehensive information about current debugging location

    This is a convenience tool that fetches:
    - Current EIP/RIP register
    - Current instruction disassembly
    - Debugger status

    Returns:
        Dictionary with current location details
    """
    try:
        status = api_request("/status")
        eip_reg = "eip" if status.get("arch") == "x32" else "rip"
        eip_data = api_request("/register/get", {"name": eip_reg})

        if "value" in eip_data:
            instr = api_request("/disasm", {"addr": eip_data["value"]})
            return {
                "status": status,
                "location": eip_data["value"],
                "instruction": instr.get("instruction", "unknown"),
                "instruction_size": instr.get("size", 0)
            }

        return {"error": "Could not get current location", "status": status}
    except DebuggerError as e:
        return {"error": str(e)}

#=============================================================================
# Main Entry Point
#=============================================================================

if __name__ == "__main__":
    # Check if x32dbg is reachable
    try:
        status = api_request("/status")
        print(f"✅ Connected to x32dbg (arch: {status.get('arch', 'unknown')})", file=sys.stderr)
    except Exception as e:
        print(f"⚠️  Warning: Cannot connect to x32dbg: {e}", file=sys.stderr)
        print(f"   Make sure x32dbg is running with the MCP plugin loaded!", file=sys.stderr)

    # Run the MCP server
    mcp.run()
