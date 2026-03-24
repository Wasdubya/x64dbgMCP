import sys
import os
import inspect
import json
from typing import Any, Dict, List, Callable
import requests

from mcp.server.fastmcp import FastMCP

DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"

def _resolve_server_url_from_args_env() -> str:
    env_url = os.getenv("X64DBG_URL")
    if env_url and env_url.startswith("http"):
        return env_url
    if len(sys.argv) > 1 and isinstance(sys.argv[1], str) and sys.argv[1].startswith("http"):
        return sys.argv[1]
    return DEFAULT_X64DBG_SERVER

x64dbg_server_url = _resolve_server_url_from_args_env()

def set_x64dbg_server_url(url: str) -> None:
    global x64dbg_server_url
    if url and url.startswith("http"):
        x64dbg_server_url = url

mcp = FastMCP("x64dbg-mcp")

def safe_get(endpoint: str, params: dict = None, timeout: int = 15):
    """
    Perform a GET request with optional query parameters.
    Returns parsed JSON if possible, otherwise text content
    """
    if params is None:
        params = {}

    url = f"{x64dbg_server_url}{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=timeout)
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

def safe_post(endpoint: str, data: dict | str, timeout: int = 15):
    """
    Perform a POST request with data.
    Returns parsed JSON if possible, otherwise text content
    """
    try:
        url = f"{x64dbg_server_url}{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
        
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


def _get_mcp_tools_registry() -> Dict[str, Callable[..., Any]]:
    """
    Build a registry of available MCP-exposed tool callables in this module.
    Heuristic: exported callables starting with an uppercase letter.
    """
    registry: Dict[str, Callable[..., Any]] = {}
    for name, obj in globals().items():
        if not name or not name[0].isupper():
            continue
        if callable(obj):
            try:
                # Validate signature to ensure it's a plain function
                inspect.signature(obj)
                registry[name] = obj
            except (TypeError, ValueError):
                pass
    return registry

def _describe_tool(name: str, func: Callable[..., Any]) -> Dict[str, Any]:
    sig = inspect.signature(func)
    params = []
    for p in sig.parameters.values():
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            # Skip non-JSON friendly params in schema
            continue
        params.append({
            "name": p.name,
            "required": p.default is inspect._empty,
            "type": "string" if p.annotation in (str, inspect._empty) else ("boolean" if p.annotation is bool else ("integer" if p.annotation is int else "string"))
        })
    return {
        "name": name,
        "description": (func.__doc__ or "").strip(),
        "params": params
    }

def _list_tools_description() -> List[Dict[str, Any]]:
    reg = _get_mcp_tools_registry()
    return [_describe_tool(n, f) for n, f in sorted(reg.items(), key=lambda x: x[0].lower())]

def _invoke_tool_by_name(name: str, args: Dict[str, Any]) -> Any:
    reg = _get_mcp_tools_registry()
    if name not in reg:
        return {"error": f"Unknown tool: {name}"}
    func = reg[name]
    try:
        # Prefer keyword invocation; convert all values to strings unless bool/int expected
        sig = inspect.signature(func)
        bound_kwargs: Dict[str, Any] = {}
        for p in sig.parameters.values():
            if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD, inspect.Parameter.POSITIONAL_ONLY):
                continue
            if p.name in args:
                value = args[p.name]
                # Simple coercions for common types
                if p.annotation is bool and isinstance(value, str):
                    value = value.lower() in ("1", "true", "yes", "on")
                elif p.annotation is int and isinstance(value, str):
                    try:
                        value = int(value, 0)
                    except Exception:
                        try:
                            value = int(value)
                        except Exception:
                            pass
                bound_kwargs[p.name] = value
        return func(**bound_kwargs)
    except Exception as e:
        return {"error": str(e)}


def _block_to_dict(block: Any) -> Dict[str, Any]:
    try:
        # Newer anthropic SDK objects are Pydantic models
        if hasattr(block, "model_dump") and callable(getattr(block, "model_dump")):
            return block.model_dump()
    except Exception:
        pass
    if isinstance(block, dict):
        return block
    btype = getattr(block, "type", None)
    if btype == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if btype == "tool_use":
        return {
            "type": "tool_use",
            "id": getattr(block, "id", None),
            "name": getattr(block, "name", None),
            "input": getattr(block, "input", {}) or {},
        }
    # Fallback generic representation
    return {"type": str(btype or "unknown"), "raw": str(block)}


_GPR_KEYS = {"cax", "ccx", "cdx", "cbx", "csp", "cbp", "csi", "cdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cip"}


def _parse_hex_bytes(hex_str: str) -> bytes:
    """Normalize a hex string (with optional spaces/0x prefix) and convert to bytes."""
    return bytes.fromhex(hex_str.replace(" ", "").replace("0x", "").replace("0X", ""))


def _format_hex_bytes(hex_str: str) -> str:
    """Normalize a hex string and format as spaced uppercase hex bytes."""
    raw = hex_str.replace("0x", "").replace("0X", "").replace(" ", "")
    return " ".join(raw[i:i+2].upper() for i in range(0, len(raw), 2))


@mcp.tool()
def ExecCommand(cmd: str, offset: int = 0, limit: int = 100) -> dict:
    """
    Execute a command in x64dbg and return its output
    
    Parameters:
        cmd: Command to execute
        offset: Pagination offset for reference view results (default: 0)
        limit: Maximum number of reference view rows to return (default: 100, max: 5000)
    
    Returns:
        Dictionary with:
        - success: Whether the command executed successfully
        - refView: References tab data populated by the command (if any), with:
          - rowCount: Total number of rows in the references view
          - rows: List of rows (paginated), where each row is a list of cell strings
                  (typically [address, disassembly] or [address, disassembly, string_address, string])
    """
    return safe_get("ExecCommand", {"cmd": cmd, "offset": offset, "limit": limit}, timeout=60)


@mcp.tool()
def IsDebugActive() -> bool:
    """
    Check if debugger is active (running)

    Returns:
        True if running, False otherwise
    """
    result = safe_get("IsDebugActive")
    if isinstance(result, dict) and "isRunning" in result:
        return result["isRunning"] is True
    if isinstance(result, str):
        try:
            import json
            parsed = json.loads(result)
            return parsed.get("isRunning", False) is True
        except Exception:
            return False
    return False

@mcp.tool()
def IsDebugging() -> bool:
    """
    Check if x64dbg is debugging a process

    Returns:
        True if debugging, False otherwise
    """
    result = safe_get("Is_Debugging")
    if isinstance(result, dict) and "isDebugging" in result:
        return result["isDebugging"] is True
    if isinstance(result, str):
        try:
            import json
            parsed = json.loads(result)
            return parsed.get("isDebugging", False) is True
        except Exception:
            return False
    return False

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


@mcp.tool()
def FlagGet(flag: str) -> bool:
    """
    Get CPU flag value using TitanEngine
    
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
    Set CPU flag value using Script API
    
    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
        value: Flag value (True/False)
    
    Returns:
        Status message
    """
    return safe_get("Flag/Set", {"flag": flag, "value": "true" if value else "false"})


@mcp.tool()
def PatternFindMem(start: str, size: str, pattern: str) -> str:
    """
    Find pattern in memory using Script API
    
    Parameters:
        start: Start address (in hex format, e.g. "0x1000")
        size: Size to search IN DECIMAL
        pattern: Pattern to find (e.g. "48 8B 05 ?? ?? ?? ??")
    
    Returns:
        Found address in hex format or error message
    """
    return safe_get("Pattern/FindMem", {"start": start, "size": size, "pattern": pattern})


@mcp.tool()
def MiscParseExpression(expression: str) -> str:
    """
    Parse expression using Script API
    
    Parameters:
        expression: Expression to parse (e.g. "[esp+8]")
    
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
    result = safe_get("GetModuleList", timeout=60)
    if isinstance(result, list):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return [{"raw": result}]
    return [{"error": "Unexpected response format"}]

@mcp.tool()
def QuerySymbols(module: str, offset: int = 0, limit: int = 5000) -> dict:
    """
    Enumerate symbols for a specific module. Use GetModuleList first to discover module names.
    Returns imports, exports, and user-defined function symbols for the given module.
    
    Args:
        module: Module name to query symbols for (e.g. "kernel32.dll", "ntdll.dll"). Required.
        offset: Pagination offset - number of symbols to skip (default: 0)
        limit: Maximum number of symbols to return per page (default: 5000, max: 50000)
    
    Returns:
        Dictionary with:
        - total: Total number of symbols in the module
        - module: The module name queried
        - offset: Current offset
        - limit: Current limit
        - symbols: List of symbol objects with rva, name, manual, type fields
    """
    params = {
        "module": module,
        "offset": str(offset),
        "limit": str(limit),
    }
    
    result = safe_get("SymbolEnum", params)
    
    # Parse JSON response if it's a string
    if isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}

    return result

@mcp.tool()
def ThreadContext(tids: str = "", max_stack: int = 4, filter_game: bool = True) -> dict:
    """
    Get register + call stack context for one or more threads in one call.
    Much more useful than GetThreadList for understanding what threads are doing.

    Parameters:
        tids: Comma-separated thread IDs to inspect (e.g. "49948,11960,35888").
              If empty, inspects all named game threads + main thread.
        max_stack: Maximum call stack frames per thread (default: 4)
        filter_game: If true and tids is empty, only show threads with game code
                     in their RIP or call stack (skip pure system waits). Default: true.

    Returns:
        Dictionary with:
        - count: Number of threads inspected
        - threads: List of thread contexts with tid, name, rip, registers, callstack
    """
    thread_list = safe_get("GetThreadList")
    if isinstance(thread_list, str):
        try:
            thread_list = json.loads(thread_list)
        except:
            return {"error": "Failed to get thread list", "raw": thread_list}
    if not isinstance(thread_list, dict) or "threads" not in thread_list:
        return {"error": "Unexpected thread list format"}

    all_threads = thread_list["threads"]

    if tids:
        target_ids = set(tids.replace(" ", "").split(","))
        selected = [t for t in all_threads if str(t.get("threadId", "")) in target_ids]
    else:
        # Auto-select: main thread + named threads + high-cycle threads
        selected = []
        for t in all_threads:
            name = t.get("threadName", "")
            if name:
                selected.append(t)

    results = []
    for t in selected:
        tid_str = str(t.get("threadId", ""))
        params = {"tid": tid_str}

        regs = safe_get("RegisterDump", params=params)
        if isinstance(regs, str):
            try:
                regs = json.loads(regs)
            except:
                regs = {}

        rip = regs.get("cip", "0")
        gpr = _filter_register_dump(regs, "gpr") if isinstance(regs, dict) else {}

        stack = safe_get("GetCallStack", params=params, timeout=10)
        if isinstance(stack, str):
            try:
                stack = json.loads(stack)
            except:
                stack = {}
        stack_entries = []
        if isinstance(stack, dict) and "entries" in stack:
            entries = stack["entries"]
            stack_entries = entries[:max_stack] if max_stack > 0 else entries

        # Filter: skip threads with only system code if filter_game is on
        if filter_game and not tids:
            has_game_code = False
            if isinstance(rip, str) and rip.startswith("0x14"):
                has_game_code = True
            else:
                for frame in stack_entries:
                    comment = frame.get("comment", "")
                    if "crimsondesert" in comment.lower():
                        has_game_code = True
                        break
            if not has_game_code:
                continue

        results.append({
            "tid": t.get("threadId"),
            "name": t.get("threadName", ""),
            "number": t.get("threadNumber"),
            "priority": t.get("priority", ""),
            "cycles": t.get("cycles", 0),
            "rip": rip,
            "registers": gpr,
            "callstack": stack_entries,
        })

    return {
        "count": len(results),
        "threads": results,
    }

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
    
    Args:
        tid: Thread ID (decimal integer string, e.g. "1234")
    
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
        result = safe_get("MemoryBase", {"addr": addr}, timeout=60)
        
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
        
@mcp.tool()
def SetPageRights(addr: str, rights: str) -> bool:
    """
    Set memory page protection rights at a given address

    Args:
        addr: Virtual address (hex string, e.g. "0x401000")
        rights: Rights string (e.g. "rwx", "rx", "rw")

    Returns:
        True if successful, False otherwise
    """
    params = {
        "addr": addr,
        "rights": rights
    }

    result = safe_post("Memory/SetPageRights", params)

    if isinstance(result, dict):
        return result.get("success", False) is True

    if isinstance(result, str):
        try:
            import json
            parsed = json.loads(result)
            return parsed.get("success", False) is True
        except Exception:
            return result.strip().lower() in ("ok", "true", "success")

    return False


@mcp.tool()
def StringGetAt(addr: str) -> dict:
    """
    Retrieve the string at a given address in the debugged process.
    Uses x64dbg's internal string detection (same as the disassembly view).
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1400010a0")
    
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


@mcp.tool()
def XrefGet(addr: str) -> dict:
    """
    Get all cross-references (xrefs) TO the specified address.
    Returns the list of addresses that reference the target address,
    along with the type of each reference (data, jmp, call).
    
    Note: Results depend on x64dbg's analysis database. Run analysis
    first for comprehensive results.
    
    Parameters:
        addr: Target address to find references to (hex format, e.g. "0x1400010a0")
    
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
        addr: Target address to count references for (hex format, e.g. "0x1400010a0")
    
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


@mcp.tool()
def GetMemoryMap(addr: str = "", protect: str = "", type: str = "", info: str = "") -> dict:
    """
    Get the virtual memory map of the debugged process with optional filtering.
    Without filters, returns ALL pages (can be very large). Use filters for performance.

    Parameters:
        addr: Filter to pages containing this address (hex, e.g. "0x14CC58F00").
              Returns the page that contains the address plus its neighbors.
        protect: Filter by protection flags substring (e.g. "ERW", "ER-", "-RW", "E").
                 Only pages whose protect string contains this value are returned.
        type: Filter by memory type (e.g. "IMG", "MAP", "PRV").
        info: Filter by info/module name substring (case-insensitive, e.g. "crimson", ".exe").

    Returns:
        Dictionary with:
        - count: Number of matching memory pages
        - total: Total pages before filtering (if filtered)
        - pages: List of page objects with base, size, protect, type, and info
    """
    result = safe_get("MemoryMap", timeout=120)

    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result[:500] if len(result) > 500 else result}

    if not isinstance(result, dict):
        return {"error": "Unexpected response format"}

    pages = result.get("pages", [])
    total = len(pages)

    # Apply filters
    has_filter = any([addr, protect, type, info])
    if not has_filter:
        # No filters: return summary instead of full dump to avoid overwhelming output
        if total > 200:
            # Summarize by type/protect
            summary = {}
            for p in pages:
                key = f"{p.get('type', '?')}:{p.get('protect', '?')}"
                if key not in summary:
                    summary[key] = {"count": 0, "total_size": 0, "example_base": p.get("base", "?")}
                summary[key]["count"] += 1
                try:
                    summary[key]["total_size"] += int(p.get("size", "0"), 16) if isinstance(p.get("size"), str) else p.get("size", 0)
                except:
                    pass
            return {
                "total": total,
                "summary": summary,
                "hint": "Use filters (addr, protect, type, info) to get specific pages. Example: protect='ERW' or addr='0x14CC58F00'"
            }
        return {"count": total, "pages": pages}

    filtered = pages

    if addr:
        try:
            target = int(addr, 16) if isinstance(addr, str) else addr
            matched = []
            for p in filtered:
                try:
                    pbase = int(p["base"], 16) if isinstance(p["base"], str) else p["base"]
                    psize = int(p["size"], 16) if isinstance(p["size"], str) else p["size"]
                    if pbase <= target < pbase + psize:
                        matched.append(p)
                except:
                    pass
            filtered = matched
        except:
            pass

    if protect:
        filtered = [p for p in filtered if protect in p.get("protect", "")]

    if type:
        filtered = [p for p in filtered if type.upper() == p.get("type", "").upper()]

    if info:
        info_lower = info.lower()
        filtered = [p for p in filtered if info_lower in p.get("info", "").lower()]

    return {"count": len(filtered), "total": total, "pages": filtered}


@mcp.tool()
def MemoryRemoteAlloc(size: str, addr: str = "0") -> dict:
    """
    Allocate memory in the debuggee's address space.
    Useful for code injection, shellcode testing, or creating data buffers.
    
    Parameters:
        size: Size in bytes to allocate (hex format, e.g. "0x1000")
        addr: Preferred base address (hex format, default "0" for any address)
    
    Returns:
        Dictionary with:
        - address: The allocated memory address
        - size: The requested size
    """
    result = safe_get("Memory/RemoteAlloc", {"addr": addr, "size": size})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def MemoryRemoteFree(addr: str) -> dict:
    """
    Free memory previously allocated in the debuggee's address space via MemoryRemoteAlloc.
    
    Parameters:
        addr: Address of the memory to free (hex format, e.g. "0x1000")
    
    Returns:
        Dictionary with success status
    """
    result = safe_get("Memory/RemoteFree", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetBranchDestination(addr: str) -> dict:
    """
    Get the destination address of a branch instruction (jmp, call, jcc, etc.).
    Resolves where the branch at the given address would jump/call to.
    
    Parameters:
        addr: Address of the branch instruction (hex format, e.g. "0x1400010a0")
    
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


@mcp.tool()
def GetCallStack(max_depth: int = 8, tid: str = "") -> dict:
    """
    Get the current call stack of the debugged thread.

    Parameters:
        max_depth: Maximum number of stack frames to return (default: 8, 0=all)
        tid: Thread ID to query (default: current thread). Use GetThreadList to find IDs.

    Returns:
        Dictionary with:
        - total: Total number of stack frames
        - entries: List of call stack entries (truncated to max_depth), each with:
          - from: Return address (caller)
          - to: Called address (callee)
          - comment: Auto-generated comment (function name, etc.)
    """
    params = {"tid": tid} if tid else {}
    result = safe_get("GetCallStack", params=params, timeout=30)
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    if isinstance(result, dict):
        if max_depth > 0 and "entries" in result:
            entries = result["entries"]
            result = dict(result)
            result["entries"] = entries[:max_depth]
            if len(entries) > max_depth:
                result["truncated"] = len(entries)
        return result
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetBreakpointList(type: str = "all") -> dict:
    """
    Get list of all breakpoints currently set in the debugger.
    
    Parameters:
        type: Breakpoint type filter - "all" (default), "normal", "hardware", "memory", "dll", "exception"
    
    Returns:
        Dictionary with:
        - count: Number of breakpoints
        - breakpoints: List of breakpoint objects with type, addr, enabled, singleshoot,
          active, name, module, hitCount, fastResume, silent, breakCondition, logText, commandText
    """
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
def LabelSet(addr: str, text: str) -> dict:
    """
    Set a label at the specified address in x64dbg.
    Labels appear in the disassembly view and are useful for marking important addresses.
    
    Parameters:
        addr: Address to set the label at (hex format, e.g. "0x1400010a0")
        text: Label text (e.g. "main_decrypt_loop")
    
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
        addr: Address to query (hex format, e.g. "0x1400010a0")
    
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


@mcp.tool()
def CommentSet(addr: str, text: str) -> dict:
    """
    Set a comment at the specified address in x64dbg.
    Comments appear in the disassembly view next to the instruction.
    
    Parameters:
        addr: Address to set the comment at (hex format, e.g. "0x1400010a0")
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
        addr: Address to query (hex format, e.g. "0x1400010a0")
    
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


def _filter_register_dump(dump: dict, mode: str = "gpr") -> dict:
    if mode == "all":
        return dump
    if mode == "gpr":
        return {k: v for k, v in dump.items() if k in _GPR_KEYS}
    if mode == "gpr+flags":
        out = {k: v for k, v in dump.items() if k in _GPR_KEYS}
        if "flags" in dump:
            out["flags"] = dump["flags"]
        return out
    return dump


@mcp.tool()
def GetRegisterDump(filter: str = "gpr", tid: str = "") -> dict:
    """
    Get CPU registers.

    Parameters:
        filter: What to return - "gpr" (default: rax-r15 + rip only),
                "gpr+flags" (gpr + CPU flags), or "all" (everything including
                segment regs, debug regs, lastError/lastStatus)
        tid: Thread ID to query (default: current thread). Use GetThreadList to find IDs.

    Returns:
        Dictionary with register values
    """
    params = {"tid": tid} if tid else {}
    result = safe_get("RegisterDump", params=params)
    if isinstance(result, dict):
        return _filter_register_dump(result, filter)
    elif isinstance(result, str):
        try:
            return _filter_register_dump(json.loads(result), filter)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def SetHardwareBreakpoint(addr: str, type: str = "execute") -> dict:
    """
    Set a hardware breakpoint at the specified address.
    Hardware breakpoints use CPU debug registers (limited to 4 simultaneous).
    
    Parameters:
        addr: Address to set the breakpoint at (hex format, e.g. "0x1400010a0")
        type: Breakpoint type - "execute" (default), "access" (read/write), or "write" (write only)
    
    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Debug/SetHardwareBreakpoint", {"addr": addr, "type": type})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def DeleteHardwareBreakpoint(addr: str) -> dict:
    """
    Delete a hardware breakpoint at the specified address.
    
    Parameters:
        addr: Address of the hardware breakpoint to delete (hex format)
    
    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Debug/DeleteHardwareBreakpoint", {"addr": addr})
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
    """
    Enumerate all TCP connections of the debugged process.
    Useful for analyzing network activity, identifying C2 connections, etc.
    
    Returns:
        Dictionary with:
        - count: Number of connections
        - connections: List of connection objects with remoteAddress, remotePort,
          localAddress, localPort, and state
    """
    result = safe_get("EnumTcpConnections", timeout=30)
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


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
        addr: Address to check (hex format, e.g. "0x1400010a0")
    
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


@mcp.tool()
def EnumHandles() -> dict:
    """
    Enumerate all open handles in the debugged process.
    Returns handle values, types, access rights, names, and type names.
    Useful for analyzing file handles, registry keys, mutexes, events, etc.
    
    Returns:
        Dictionary with:
        - count: Number of handles
        - handles: List of handle objects with handle (hex), typeNumber,
          grantedAccess (hex), name, and typeName
    """
    result = safe_get("EnumHandles", timeout=60)
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def BreakpointContext(disasm_count: int = 5, callstack_depth: int = 6, tid: str = "") -> dict:
    """
    Get full context after a breakpoint hit in one call.
    Combines GPR registers + call stack + disassembly around RIP.

    Parameters:
        disasm_count: Number of instructions to disassemble starting before RIP (default: 5)
        callstack_depth: Max call stack frames (default: 6, 0=all)
        tid: Thread ID to query (default: current thread). Use GetThreadList to find IDs.

    Returns:
        Dictionary with:
        - registers: GPR values (rax-r15, rip)
        - callstack: Call stack entries (truncated)
        - disasm: Disassembly around RIP
        - rip: Current instruction pointer (convenience)
        - tid: Thread ID queried (if specified)
    """
    params = {"tid": tid} if tid else {}
    regs = safe_get("RegisterDump", params=params)
    if isinstance(regs, str):
        try:
            regs = json.loads(regs)
        except:
            return {"error": "Failed to get registers", "raw": regs}
    if not isinstance(regs, dict):
        return {"error": "Unexpected register response"}

    rip = regs.get("cip", "0")

    gpr = _filter_register_dump(regs, "gpr")

    stack = safe_get("GetCallStack", params=params, timeout=30)
    if isinstance(stack, str):
        try:
            stack = json.loads(stack)
        except:
            stack = {"error": stack}
    stack_entries = []
    if isinstance(stack, dict) and "entries" in stack:
        entries = stack["entries"]
        stack_entries = entries[:callstack_depth] if callstack_depth > 0 else entries

    disasm = safe_get("Disasm/GetInstructionRange", {"addr": rip, "count": str(disasm_count)})
    if isinstance(disasm, str):
        try:
            disasm = json.loads(disasm)
        except:
            disasm = [{"error": disasm}]
    if not isinstance(disasm, list):
        disasm = [disasm]

    result = {
        "rip": rip,
        "registers": gpr,
        "callstack": stack_entries,
        "disasm": disasm,
    }
    if tid:
        result["tid"] = tid
    return result


@mcp.tool()
def RunUntilBreakpoint(target: str, max_attempts: int = 50, log_stacks: bool = True) -> dict:
    """
    Run the debuggee, automatically skipping Themida exceptions until the target
    breakpoint is hit. At each exception stop, reads the call stack for useful
    game-code addresses (logged but not returned unless relevant).

    Sets a software breakpoint on target, then loops: run -> check RIP -> if not
    target, read stack and continue. Stops when RIP matches target or max_attempts
    is reached.

    Parameters:
        target: Target breakpoint address (hex, e.g. "0x140F51EC0")
        max_attempts: Maximum exception skips before giving up (default: 50)
        log_stacks: Log game-code addresses seen on exception stacks (default: True)

    Returns:
        Dictionary with:
        - hit: Whether the breakpoint was hit
        - attempts: Number of exceptions skipped
        - context: BreakpointContext at the hit (if hit=True)
        - stack_addresses: Unique game-code addresses seen on exception stacks
        - error: Error message (if any)
    """
    import time

    target_int = int(target, 16) if isinstance(target, str) else target
    target_hex = f"0x{target_int:X}"

    safe_get("Debugger/Breakpoint/Set", {"addr": target_hex})

    game_code_addrs = set()
    attempts = 0

    for attempt in range(max_attempts):
        # Run
        safe_get("Debugger/Continue", timeout=5)
        time.sleep(0.3)  # Give the debuggee time to hit something

        # Check RIP
        regs = safe_get("RegisterDump")
        if isinstance(regs, str):
            try:
                regs = json.loads(regs)
            except:
                continue
        if not isinstance(regs, dict):
            continue

        rip_str = regs.get("cip", "0")
        try:
            rip_int = int(rip_str, 16) if isinstance(rip_str, str) else rip_str
        except:
            continue

        attempts = attempt + 1

        # Check if we hit our target
        if rip_int == target_int:
            # Hit! Get full context
            ctx = BreakpointContext(disasm_count=3, callstack_depth=8)
            return {
                "hit": True,
                "attempts": attempts,
                "context": ctx,
                "stack_addresses": sorted([f"0x{a:X}" for a in game_code_addrs]),
            }

        # Not our BP — read stack for interesting addresses
        if log_stacks:
            stack = safe_get("GetCallStack", timeout=10)
            if isinstance(stack, str):
                try:
                    stack = json.loads(stack)
                except:
                    stack = {}
            if isinstance(stack, dict) and "entries" in stack:
                for entry in stack["entries"]:
                    for key in ("from", "to"):
                        val = entry.get(key, "0")
                        try:
                            addr_int = int(val, 16) if isinstance(val, str) else val
                        except:
                            continue
                        # Game code range: 0x140000000 - 0x160000000
                        if 0x140000000 <= addr_int <= 0x160000000:
                            game_code_addrs.add(addr_int)

    return {
        "hit": False,
        "attempts": attempts,
        "context": None,
        "stack_addresses": sorted([f"0x{a:X}" for a in game_code_addrs]),
        "error": f"Breakpoint at {target_hex} not hit after {max_attempts} attempts",
    }


@mcp.tool()
def MemoryReadValues(addr: str, count: int = 1, type: str = "qword") -> dict:
    """
    Read memory and interpret as typed values (pointers, integers).
    Much more useful than raw hex for RE work.

    Parameters:
        addr: Start address (hex format, e.g. "0x1000")
        count: Number of values to read (default: 1)
        type: Value type - "qword" (8 bytes, default), "dword" (4 bytes),
              "word" (2 bytes), "byte" (1 byte)

    Returns:
        Dictionary with:
        - addr: Start address
        - type: Value type used
        - values: List of {"offset": hex_offset, "value": hex_value} entries
    """
    type_sizes = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
    sz = type_sizes.get(type, 8)
    total_bytes = sz * count

    result = safe_get("Memory/Read", {"addr": addr, "size": str(total_bytes)})
    if isinstance(result, dict):
        if "result" in result:
            hex_str = result["result"]
        elif "error" in result:
            return result
        else:
            return {"error": "Unexpected response", "raw": result}
    elif isinstance(result, str):
        hex_str = result
    else:
        return {"error": "Unexpected response format"}

    try:
        raw = _parse_hex_bytes(hex_str)
    except ValueError:
        return {"error": "Failed to parse hex", "raw": hex_str[:100]}

    values = []
    for i in range(count):
        chunk = raw[i * sz:(i + 1) * sz]
        if len(chunk) < sz:
            break
        val = int.from_bytes(chunk, "little")
        values.append({"offset": hex(i * sz), "value": hex(val)})

    return {"addr": addr, "type": type, "values": values}


@mcp.tool()
def FollowPointerChain(base: str, offsets: str) -> dict:
    """
    Follow a pointer chain from a base address through a series of offsets.
    Example: base="0x1400000", offsets="0x68,0x20,0xD0" follows:
      [[[0x1400000]+0x68]+0x20]+0xD0

    At each step, reads a qword pointer and adds the next offset.
    The last offset is NOT dereferenced (returns the final address + value).

    Parameters:
        base: Starting address (hex format, e.g. "0x38c3eab0000")
        offsets: Comma-separated hex offsets (e.g. "0x68,0x20,0xD0")

    Returns:
        Dictionary with:
        - hops: List of {"addr": address_read_from, "value": value_at_addr} for each step
        - final_addr: The final computed address
        - final_value: The qword value at the final address
        - error: Error message if chain broke at some point
    """
    try:
        current = int(base, 16) if isinstance(base, str) else base
    except ValueError:
        return {"error": f"Invalid base address: {base}"}

    offset_list = []
    for o in offsets.split(","):
        o = o.strip()
        if not o:
            continue
        try:
            offset_list.append(int(o, 16))
        except ValueError:
            return {"error": f"Invalid offset: {o}"}

    if not offset_list:
        return {"error": "No offsets provided"}

    hops = []

    # For all offsets except the last: read pointer, add next offset
    for i, off in enumerate(offset_list):
        target = current + off
        result = safe_get("Memory/Read", {"addr": hex(target), "size": "8"})

        hex_str = ""
        if isinstance(result, dict) and "result" in result:
            hex_str = result["result"]
        elif isinstance(result, str):
            hex_str = result
        else:
            return {"hops": hops, "error": f"Failed to read at {hex(target)}", "raw": result}

        try:
            raw = _parse_hex_bytes(hex_str)
            val = int.from_bytes(raw[:8], "little")
        except (ValueError, IndexError):
            return {"hops": hops, "error": f"Failed to parse value at {hex(target)}"}

        hops.append({"addr": hex(target), "value": hex(val)})

        if i < len(offset_list) - 1:
            # Dereference: follow the pointer
            current = val
        else:
            # Last offset: return the final address and value
            return {
                "hops": hops,
                "final_addr": hex(target),
                "final_value": hex(val),
            }

    return {"hops": hops, "error": "Unexpected end of chain"}


@mcp.tool()
def DisasmGetInstructionRangeEx(addr: str, count: int = 10, show_bytes: bool = False) -> list:
    """
    Disassemble instructions with optional raw bytes (for AOB pattern creation).

    Parameters:
        addr: Memory address (hex format, e.g. "0x1000")
        count: Number of instructions (default: 10, max: 100)
        show_bytes: Include raw bytes for each instruction (default: False)

    Returns:
        List of instruction dicts. When show_bytes=True, each includes a "bytes" field.
    """
    result = safe_get("Disasm/GetInstructionRange", {"addr": addr, "count": str(count)})
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return [{"error": "Failed to parse", "raw": result}]
    if not isinstance(result, list):
        return [{"error": "Unexpected format"}]

    if not show_bytes:
        return result

    # Bulk read: calculate total byte range from first to last instruction
    if len(result) >= 2:
        first = result[0]
        last = result[-1]
        try:
            start_addr = int(first["address"], 16)
            end_addr = int(last["address"], 16) + last.get("size", 1)
            total_size = end_addr - start_addr
            mem = safe_get("Memory/Read", {"addr": first["address"], "size": str(total_size)})
            bulk_hex = ""
            if isinstance(mem, dict) and "result" in mem:
                bulk_hex = mem["result"]
            elif isinstance(mem, str):
                bulk_hex = mem
            if bulk_hex:
                bulk_bytes = _parse_hex_bytes(bulk_hex)
                for insn in result:
                    insn_offset = int(insn["address"], 16) - start_addr
                    insn_size = insn.get("size", 0)
                    if insn_size > 0 and insn_offset >= 0 and insn_offset + insn_size <= len(bulk_bytes):
                        chunk = bulk_bytes[insn_offset:insn_offset + insn_size]
                        insn["bytes"] = " ".join(f"{b:02X}" for b in chunk)
                return result
        except (KeyError, ValueError, TypeError):
            pass  # Fall through to per-instruction reads

    # Fallback: per-instruction reads (single instruction or bulk failed)
    for insn in result:
        insn_addr = insn.get("address", "")
        insn_size = insn.get("size", 0)
        if insn_addr and insn_size > 0:
            mem = safe_get("Memory/Read", {"addr": insn_addr, "size": str(insn_size)})
            hex_str = mem["result"] if isinstance(mem, dict) and "result" in mem else (mem if isinstance(mem, str) else "")
            if hex_str:
                insn["bytes"] = _format_hex_bytes(hex_str)

    return result


import argparse

def main_cli():
    parser = argparse.ArgumentParser(description="x64dbg MCP CLI wrapper")

    parser.add_argument("tool", help="Tool/function name (e.g. ExecCommand, RegisterGet, MemoryRead)")
    parser.add_argument("args", nargs="*", help="Arguments for the tool")
    parser.add_argument("--x64dbg-url", dest="x64dbg_url", default=os.getenv("X64DBG_URL"), help="x64dbg HTTP server URL")

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    # Map CLI call → actual MCP tool function
    if opts.tool in globals():
        func = globals()[opts.tool]
        if callable(func):
            try:
                # Try to unpack args dynamically
                result = func(*opts.args)
                print(json.dumps(result, indent=2))
            except TypeError as e:
                print(f"Error calling {opts.tool}: {e}")
        else:
            print(f"{opts.tool} is not callable")
    else:
        print(f"Unknown tool: {opts.tool}")


def claude_cli():
    parser = argparse.ArgumentParser(description="Chat with Claude using x64dbg MCP tools")
    parser.add_argument("prompt", nargs=argparse.REMAINDER, help="Initial user prompt. If empty, read from stdin")
    parser.add_argument("--model", dest="model", default=os.getenv("ANTHROPIC_MODEL", "claude-3-7-sonnet-2025-06-20"), help="Claude model")
    parser.add_argument("--api-key", dest="api_key", default=os.getenv("ANTHROPIC_API_KEY"), help="Anthropic API key")
    parser.add_argument("--system", dest="system", default="You can control x64dbg via MCP tools.", help="System prompt")
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=100, help="Max tool-use iterations")
    parser.add_argument("--x64dbg-url", dest="x64dbg_url", default=os.getenv("X64DBG_URL"), help="x64dbg HTTP server URL")
    parser.add_argument("--no-tools", dest="no_tools", action="store_true", help="Disable tool-use (text-only)")

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    # Resolve prompt
    user_prompt = " ".join(opts.prompt).strip()
    if not user_prompt:
        user_prompt = sys.stdin.read().strip()
    if not user_prompt:
        print("No prompt provided.")
        return

    try:
        import anthropic
    except Exception as e:
        print("Anthropic SDK not installed. Run: pip install anthropic")
        print(str(e))
        return

    if not opts.api_key:
        print("Missing Anthropic API key. Set ANTHROPIC_API_KEY or pass --api-key.")
        return

    client = anthropic.Anthropic(api_key=opts.api_key)

    tools_spec: List[Dict[str, Any]] = []
    if not opts.no_tools:
        tools_spec = [
            {
                "name": "mcp_list_tools",
                "description": "List available MCP tool functions and their parameters.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "mcp_call_tool",
                "description": "Invoke an MCP tool by name with arguments.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "args": {"type": "object"}
                    },
                    "required": ["tool"],
                },
            },
        ]

    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": user_prompt}
    ]

    step = 0
    while True:
        step += 1
        response = client.messages.create(
            model=opts.model,
            system=opts.system,
            messages=messages,
            tools=tools_spec if not opts.no_tools else None,
            max_tokens=1024,
        )

        # Print any assistant text
        assistant_text_chunks: List[str] = []
        tool_uses: List[Dict[str, Any]] = []
        for block in response.content:
            b = _block_to_dict(block)
            if b.get("type") == "text":
                assistant_text_chunks.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tool_uses.append(b)

        if assistant_text_chunks:
            print("\n".join(assistant_text_chunks))

        if not tool_uses or opts.no_tools:
            break

        # Prepare tool results as a new user message
        tool_result_blocks: List[Dict[str, Any]] = []
        for tu in tool_uses:
            name = tu.get("name")
            tu_id = tu.get("id")
            input_obj = tu.get("input", {}) or {}
            result: Any
            if name == "mcp_list_tools":
                result = {"tools": _list_tools_description()}
            elif name == "mcp_call_tool":
                tool_name = input_obj.get("tool")
                args = input_obj.get("args", {}) or {}
                result = _invoke_tool_by_name(tool_name, args)
            else:
                result = {"error": f"Unknown tool: {name}"}

            # Ensure serializable content (string)
            try:
                result_text = json.dumps(result)
            except Exception:
                result_text = str(result)

            tool_result_blocks.append({
                "type": "tool_result",
                "tool_use_id": tu_id,
                "content": result_text,
            })

        # Normalize assistant content to plain dicts
        assistant_blocks = [_block_to_dict(b) for b in response.content]
        messages.append({"role": "assistant", "content": assistant_blocks})
        messages.append({"role": "user", "content": tool_result_blocks})

        if step >= opts.max_steps:
            break

if __name__ == "__main__":
    # Support multiple modes:
    #  - "serve" or "--serve": run MCP server
    #  - "claude" subcommand: run Claude Messages chat loop
    #  - default: tool invocation CLI
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--serve", "serve"):
            mcp.run()
        elif sys.argv[1] == "claude":
            # Shift off the subcommand and re-dispatch
            sys.argv.pop(1)
            claude_cli()
        else:
            main_cli()
    else:
        mcp.run()
