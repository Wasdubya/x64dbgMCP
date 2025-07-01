import sys
import requests
import json

from mcp.server.fastmcp import FastMCP

DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"
x64dbg_server_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_X64DBG_SERVER

mcp = FastMCP("x64dbg-mcp")

def safe_get(endpoint: str, params: dict = None):
    """
    Perform a GET request with optional query parameters.
    Returns parsed JSON if possible, otherwise text content
    """
    if params is None:
        params = {}

    url = f"{x64dbg_server_url}{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=15)
        response.encoding = 'utf-8'
        if response.ok:
            # Try to parse as JSON first
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post(endpoint: str, data: dict | str):
    """
    Perform a POST request with data.
    Returns parsed JSON if possible, otherwise text content
    """
    try:
        url = f"{x64dbg_server_url}{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        
        response.encoding = 'utf-8'
        
        if response.ok:
            # Try to parse as JSON first
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

# =============================================================================
# UNIFIED COMMAND EXECUTION
# =============================================================================

@mcp.tool()
def ExecCommand(cmd: str) -> str:
    """
    Execute a command in x64dbg and return its output
    
    Parameters:
        cmd: Command to execute
    
    Returns:
        Command execution status and output
    """
    return safe_get("ExecCommand", {"cmd": cmd})

# =============================================================================
# DEBUGGING STATUS
# =============================================================================

@mcp.tool()
def IsDebugActive() -> bool:
    """
    Check if debugger is active (running)
    
    Returns:
        True if running, False otherwise
    """
    result = safe_get("IsDebugActive")
    if isinstance(result, str):
        return result.lower() == "true"
    return False

@mcp.tool()
def IsDebugging() -> bool:
    """
    Check if x64dbg is debugging a process
    
    Returns:
        True if debugging, False otherwise
    """
    result = safe_get("Is_Debugging")
    if isinstance(result, str):
        return result.lower() == "true"
    return False

# =============================================================================
# REGISTER API
# =============================================================================

@mcp.tool()
def RegisterGet(register: str) -> str:
    """
    Get register value using Script API
    
    Parameters:
        register: Register name (e.g. "eax", "rax", "rip")
    
    Returns:
        Register value in hex format
    """
    return safe_get("Register/Get", {"register": register})

@mcp.tool()
def RegisterSet(register: str, value: str) -> str:
    """
    Set register value using Script API
    
    Parameters:
        register: Register name (e.g. "eax", "rax", "rip")
        value: Value to set (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return safe_get("Register/Set", {"register": register, "value": value})

# =============================================================================
# MEMORY API (Enhanced)
# =============================================================================

@mcp.tool()
def MemoryRead(addr: str, size: str) -> str:
    """
    Read memory using enhanced Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        size: Number of bytes to read
    
    Returns:
        Hexadecimal string representing the memory contents
    """
    return safe_get("Memory/Read", {"addr": addr, "size": size})

@mcp.tool()
def MemoryWrite(addr: str, data: str) -> str:
    """
    Write memory using enhanced Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        data: Hexadecimal string representing the data to write
    
    Returns:
        Status message
    """
    return safe_get("Memory/Write", {"addr": addr, "data": data})

@mcp.tool()
def MemoryIsValidPtr(addr: str) -> bool:
    """
    Check if memory address is valid
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
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
    Get memory protection flags
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Protection flags in hex format
    """
    return safe_get("Memory/GetProtect", {"addr": addr})

# =============================================================================
# DEBUG API
# =============================================================================

@mcp.tool()
def DebugRun() -> str:
    """
    Resume execution of the debugged process using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/Run")

@mcp.tool()
def DebugPause() -> str:
    """
    Pause execution of the debugged process using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/Pause")

@mcp.tool()
def DebugStop() -> str:
    """
    Stop debugging using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/Stop")

@mcp.tool()
def DebugStepIn() -> str:
    """
    Step into the next instruction using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/StepIn")

@mcp.tool()
def DebugStepOver() -> str:
    """
    Step over the next instruction using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/StepOver")

@mcp.tool()
def DebugStepOut() -> str:
    """
    Step out of the current function using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/StepOut")

@mcp.tool()
def DebugSetBreakpoint(addr: str) -> str:
    """
    Set breakpoint at address using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return safe_get("Debug/SetBreakpoint", {"addr": addr})

@mcp.tool()
def DebugDeleteBreakpoint(addr: str) -> str:
    """
    Delete breakpoint at address using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return safe_get("Debug/DeleteBreakpoint", {"addr": addr})

# =============================================================================
# ASSEMBLER API
# =============================================================================

@mcp.tool()
def AssemblerAssemble(addr: str, instruction: str) -> dict:
    """
    Assemble instruction at address using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")
    
    Returns:
        Dictionary with assembly result
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
    Assemble instruction directly into memory using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")
    
    Returns:
        Status message
    """
    return safe_get("Assembler/AssembleMem", {"addr": addr, "instruction": instruction})

# =============================================================================
# STACK API
# =============================================================================

@mcp.tool()
def StackPop() -> str:
    """
    Pop value from stack using Script API
    
    Returns:
        Popped value in hex format
    """
    return safe_get("Stack/Pop")

@mcp.tool()
def StackPush(value: str) -> str:
    """
    Push value to stack using Script API
    
    Parameters:
        value: Value to push (in hex format, e.g. "0x1000")
    
    Returns:
        Previous top value in hex format
    """
    return safe_get("Stack/Push", {"value": value})

@mcp.tool()
def StackPeek(offset: str = "0") -> str:
    """
    Peek at stack value using Script API
    
    Parameters:
        offset: Stack offset (default: "0")
    
    Returns:
        Stack value in hex format
    """
    return safe_get("Stack/Peek", {"offset": offset})

# =============================================================================
# FLAG API
# =============================================================================

@mcp.tool()
def FlagGet(flag: str) -> bool:
    """
    Get CPU flag value using Script API
    
    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
    
    Returns:
        Flag value (True/False)
    """
    result = safe_get("Flag/Get", {"flag": flag})
    if isinstance(result, str):
        return result.lower() == "true"
    return False

@mcp.tool()
def FlagSet(flag: str, value: bool) -> str:
    """
    Set CPU flag value using Script API
    
    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
        value: Flag value (True/False)
    
    Returns:
        Status message
    """
    return safe_get("Flag/Set", {"flag": flag, "value": "true" if value else "false"})

# =============================================================================
# PATTERN API
# =============================================================================

@mcp.tool()
def PatternFindMem(start: str, size: str, pattern: str) -> str:
    """
    Find pattern in memory using Script API
    
    Parameters:
        start: Start address (in hex format, e.g. "0x1000")
        size: Size to search
        pattern: Pattern to find (e.g. "48 8B 05 ? ? ? ?")
    
    Returns:
        Found address in hex format or error message
    """
    # Remove spaces from pattern
    pattern_clean = pattern.replace(' ', '')
    return safe_get("Pattern/FindMem", {"start": start, "size": size, "pattern": pattern_clean})

# =============================================================================
# MISC API
# =============================================================================

@mcp.tool()
def MiscParseExpression(expression: str) -> str:
    """
    Parse expression using Script API
    
    Parameters:
        expression: Expression to parse (e.g. "[esp+8]", "kernel32.GetProcAddress")
    
    Returns:
        Parsed value in hex format
    """
    return safe_get("Misc/ParseExpression", {"expression": expression})

@mcp.tool()
def MiscRemoteGetProcAddress(module: str, api: str) -> str:
    """
    Get remote procedure address using Script API
    
    Parameters:
        module: Module name (e.g. "kernel32.dll")
        api: API name (e.g. "GetProcAddress")
    
    Returns:
        Function address in hex format
    """
    return safe_get("Misc/RemoteGetProcAddress", {"module": module, "api": api})

# =============================================================================
# LEGACY COMPATIBILITY FUNCTIONS
# =============================================================================

@mcp.tool()
def SetRegister(name: str, value: str) -> str:
    """
    Set register value using command (legacy compatibility)
    
    Parameters:
        name: Register name (e.g. "eax", "rip")
        value: Value to set (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    # Construct command to set register
    cmd = f"r {name}={value}"
    return ExecCommand(cmd)

@mcp.tool()
def MemRead(addr: str, size: str) -> str:
    """
    Read memory at address (legacy compatibility)
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        size: Number of bytes to read
    
    Returns:
        Hexadecimal string representing the memory contents
    """
    return safe_get("MemRead", {"addr": addr, "size": size})

@mcp.tool()
def MemWrite(addr: str, data: str) -> str:
    """
    Write memory at address (legacy compatibility)
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        data: Hexadecimal string representing the data to write
    
    Returns:
        Status message
    """
    return safe_get("MemWrite", {"addr": addr, "data": data})

@mcp.tool()
def SetBreakpoint(addr: str) -> str:
    """
    Set breakpoint at address (legacy compatibility)
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return ExecCommand(f"bp {addr}")

@mcp.tool()
def DeleteBreakpoint(addr: str) -> str:
    """
    Delete breakpoint at address (legacy compatibility)
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return ExecCommand(f"bpc {addr}")

@mcp.tool()
def Run() -> str:
    """
    Resume execution of the debugged process (legacy compatibility)
    
    Returns:
        Status message
    """
    return ExecCommand("run")

@mcp.tool()
def Pause() -> str:
    """
    Pause execution of the debugged process (legacy compatibility)
    
    Returns:
        Status message
    """
    return ExecCommand("pause")

@mcp.tool()
def StepIn() -> str:
    """
    Step into the next instruction (legacy compatibility)
    
    Returns:
        Status message
    """
    return ExecCommand("sti")

@mcp.tool()
def StepOver() -> str:
    """
    Step over the next instruction (legacy compatibility)
    
    Returns:
        Status message
    """
    return ExecCommand("sto")

@mcp.tool()
def StepOut() -> str:
    """
    Step out of the current function (legacy compatibility)
    
    Returns:
        Status message
    """
    return ExecCommand("rtr")

@mcp.tool()
def GetCallStack() -> list:
    """
    Get call stack of the current thread (legacy compatibility)
    
    Returns:
        Command result information
    """
    result = ExecCommand("k")
    return [{"info": "Call stack information requested via command", "result": result}]

@mcp.tool()
def Disassemble(addr: str) -> dict:
    """
    Disassemble at address (legacy compatibility)
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Dictionary containing disassembly information
    """
    return {"addr": addr, "command_result": ExecCommand(f"dis {addr}")}

@mcp.tool()
def DisasmGetInstruction(addr: str) -> dict:
    """
    Get disassembly of a single instruction at the specified address
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Dictionary containing instruction details
    """
    result = safe_get("Disasm/GetInstruction", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse disassembly result", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def DisasmGetInstructionRange(addr: str, count: int = 1) -> list:
    """
    Get disassembly of multiple instructions starting at the specified address
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
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
def DisasmGetInstructionAtRIP() -> dict:
    """
    Get disassembly of the instruction at the current RIP
    
    Returns:
        Dictionary containing current instruction details
    """
    result = safe_get("Disasm/GetInstructionAtRIP")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse disassembly result", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def StepInWithDisasm() -> dict:
    """
    Step into the next instruction and return both step result and current instruction disassembly
    
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


@mcp.tool()
def GetModuleList() -> list:
    """
    Get list of loaded modules
    
    Returns:
        List of module information (name, base address, size, etc.)
    """
    result = safe_get("GetModuleList")
    if isinstance(result, list):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return [{"error": "Failed to parse module list", "raw": result}]
    return [{"error": "Unexpected response format"}]

@mcp.tool()
def MemoryBase(addr: str) -> dict:
    """
    Find the base address and size of a module containing the given address
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x7FF12345")
    
    Returns:
        Dictionary containing base_address and size of the module
    """
    try:
        # Make the request to the endpoint
        result = safe_get("MemoryBase", {"addr": addr})
        
        # Handle different response types
        if isinstance(result, dict):
            return result
        elif isinstance(result, str):
            try:
                # Try to parse the string as JSON
                return json.loads(result)
            except:
                # Fall back to string parsing if needed
                if "," in result:
                    parts = result.split(",")
                    return {
                        "base_address": parts[0],
                        "size": parts[1]
                    }
                return {"raw_response": result}
        
        return {"error": "Unexpected response format"}
            
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    mcp.run()