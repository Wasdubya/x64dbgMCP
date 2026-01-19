import sys
import os
import inspect
import json
import warnings
from typing import Any, Dict, List, Callable, Union, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from mcp.server.fastmcp import FastMCP

DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"

# Timeout configurations for different operation types
TIMEOUT_FAST = 5        # Simple queries (register read, flag check)
TIMEOUT_NORMAL = 30     # Normal operations (memory read, disassembly)
TIMEOUT_DEBUG = 120     # Debug control operations (run, step, breakpoint hit)

# Connection pool configuration
_http_session: Optional[requests.Session] = None

def _create_session() -> requests.Session:
    """Create HTTP session with connection pooling and retry logic"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def _get_session() -> requests.Session:
    """Get or create HTTP session with connection pooling"""
    global _http_session
    if _http_session is None:
        _http_session = _create_session()
    return _http_session

# =============================================================================
# INPUT VALIDATION
# =============================================================================

import re

def _validate_hex_address(addr: str) -> bool:
    """Validate hex address format"""
    if not addr:
        return False
    return bool(re.match(r'^(0x)?[0-9a-fA-F]+$', addr))

def _validate_register(reg: str) -> bool:
    """Validate register name"""
    valid_regs = {
        'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
        'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip',
        'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
        'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh',
        'sil', 'dil', 'bpl', 'spl',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b',
        'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w',
        'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
        'cs', 'ds', 'es', 'fs', 'gs', 'ss',
        'dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7',
        'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7',
        'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
    }
    return reg.lower() in valid_regs

def _validate_flag(flag: str) -> bool:
    """Validate CPU flag name"""
    valid_flags = {'zf', 'of', 'cf', 'pf', 'sf', 'tf', 'af', 'df', 'if'}
    return flag.lower() in valid_flags

def _sanitize_command(cmd: str) -> str:
    """Sanitize command to prevent injection"""
    dangerous = [';', '|', '&', '`', '$', '\n', '\r']
    for char in dangerous:
        cmd = cmd.replace(char, '')
    return cmd.strip()

# =============================================================================
# UNIFIED RESPONSE PARSING
# =============================================================================

def _parse_response(result: Any, error_msg: str = "Failed to parse response") -> Any:
    """
    Unified JSON response parser.
    Eliminates duplicated parsing logic throughout the codebase.
    """
    if isinstance(result, (dict, list)):
        return result
    if isinstance(result, str):
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": error_msg, "raw": result}
    return {"error": "Unexpected response format", "type": type(result).__name__}

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

def safe_get(endpoint: str, params: dict = None, timeout: int = TIMEOUT_NORMAL):
    """
    Perform a GET request with optional query parameters.
    Returns parsed JSON if possible, otherwise text content.
    Uses connection pooling for better performance.
    """
    if params is None:
        params = {}

    url = f"{x64dbg_server_url}{endpoint}"

    try:
        response = _get_session().get(url, params=params, timeout=timeout)
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

def safe_post(endpoint: str, data: Union[dict, str], timeout: int = TIMEOUT_NORMAL):
    """
    Perform a POST request with data.
    Returns parsed JSON if possible, otherwise text content.
    Uses connection pooling for better performance.
    """
    try:
        url = f"{x64dbg_server_url}{endpoint}"
        if isinstance(data, dict):
            response = _get_session().post(url, data=data, timeout=timeout)
        else:
            response = _get_session().post(url, data=data.encode("utf-8"), timeout=timeout)
        
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
# TOOL REGISTRY INTROSPECTION (for CLI/Claude tool-use)
# =============================================================================

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

# =============================================================================
# Claude block normalization helpers
# =============================================================================

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
# CONNECTION HEALTH CHECK
# =============================================================================

@mcp.tool()
def Ping() -> dict:
    """
    Check x64dbg server connectivity and measure latency

    Returns:
        Dictionary with status, latency_ms, and response
    """
    import time
    try:
        start = time.time()
        result = safe_get("IsDebugActive", timeout=TIMEOUT_FAST)
        latency = (time.time() - start) * 1000
        return {
            "status": "connected",
            "latency_ms": round(latency, 2),
            "server": x64dbg_server_url,
            "response": result
        }
    except Exception as e:
        return {"status": "disconnected", "error": str(e)}

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
    if isinstance(result, dict) and "isRunning" in result:
        return result["isRunning"] is True
    if isinstance(result, str):
        try:
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
            parsed = json.loads(result)
            return parsed.get("isDebugging", False) is True
        except Exception:
            return False
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
    return safe_get("Debug/Run", timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugPause() -> str:
    """
    Pause execution of the debugged process using Script API

    Returns:
        Status message
    """
    return safe_get("Debug/Pause", timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugStop() -> str:
    """
    Stop debugging using Script API

    Returns:
        Status message
    """
    return safe_get("Debug/Stop", timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugStepIn() -> str:
    """
    Step into the next instruction using Script API

    Returns:
        Status message
    """
    return safe_get("Debug/StepIn", timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugStepOver() -> str:
    """
    Step over the next instruction using Script API

    Returns:
        Status message
    """
    return safe_get("Debug/StepOver", timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugStepOut() -> str:
    """
    Step out of the current function using Script API

    Returns:
        Status message
    """
    return safe_get("Debug/StepOut", timeout=TIMEOUT_DEBUG)

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
def DebugSetHardwareBreakpoint(addr: str, bp_type: str = "x", size: str = "1") -> str:
    """
    Set hardware breakpoint at address

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        bp_type: Breakpoint type - 'r' (read/write), 'w' (write), 'x' (execute)
        size: Size in bytes - 1, 2, 4, or 8

    Returns:
        Status message
    """
    return ExecCommand(f"bph {addr}, {bp_type}, {size}")

@mcp.tool()
def DebugDeleteHardwareBreakpoint(addr: str = "") -> str:
    """
    Delete hardware breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bphc {addr}" if addr else "bphc")

@mcp.tool()
def DebugEnableHardwareBreakpoint(addr: str = "") -> str:
    """
    Enable hardware breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bphe {addr}" if addr else "bphe")

@mcp.tool()
def DebugDisableHardwareBreakpoint(addr: str = "") -> str:
    """
    Disable hardware breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bphd {addr}" if addr else "bphd")

@mcp.tool()
def DebugSetMemoryBreakpoint(addr: str, bp_type: str = "a") -> str:
    """
    Set memory breakpoint on page

    Parameters:
        addr: Memory address (in hex format)
        bp_type: 'a' (access), 'r' (read), 'w' (write), 'x' (execute)

    Returns:
        Status message
    """
    return ExecCommand(f"bpm {addr}, 0, {bp_type}")

@mcp.tool()
def DebugSetMemoryBreakpointRange(start: str, size: str, bp_type: str = "a") -> str:
    """
    Set memory breakpoint on address range

    Parameters:
        start: Start address (in hex format)
        size: Size of range in bytes
        bp_type: 'a' (access), 'r' (read), 'w' (write), 'x' (execute)

    Returns:
        Status message
    """
    return ExecCommand(f"bpmr {start}, {size}, {bp_type}")

@mcp.tool()
def DebugDeleteMemoryBreakpoint(addr: str = "") -> str:
    """
    Delete memory breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bpmc {addr}" if addr else "bpmc")

@mcp.tool()
def DebugEnableMemoryBreakpoint(addr: str = "") -> str:
    """
    Enable memory breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bpme {addr}" if addr else "bpme")

@mcp.tool()
def DebugDisableMemoryBreakpoint(addr: str = "") -> str:
    """
    Disable memory breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bpmd {addr}" if addr else "bpmd")

@mcp.tool()
def DebugGetBreakpointList() -> str:
    """
    Get list of all breakpoints

    Returns:
        Breakpoint list information
    """
    return ExecCommand("bplist")

@mcp.tool()
def DebugSetBreakpointCondition(addr: str, condition: str) -> str:
    """
    Set condition for breakpoint

    Parameters:
        addr: Breakpoint address
        condition: Condition expression (e.g. "eax==1", "ecx>0x100")

    Returns:
        Status message
    """
    return ExecCommand(f"bpcond {addr}, {condition}")

@mcp.tool()
def DebugSetBreakpointCommand(addr: str, command: str) -> str:
    """
    Set command to execute when breakpoint hits

    Parameters:
        addr: Breakpoint address
        command: Command to execute

    Returns:
        Status message
    """
    return ExecCommand(f"bpcmd {addr}, {command}")

@mcp.tool()
def DebugSetBreakpointLog(addr: str, text: str) -> str:
    """
    Set log message for breakpoint

    Parameters:
        addr: Breakpoint address
        text: Log message (can include {eax}, {rip} etc.)

    Returns:
        Status message
    """
    return ExecCommand(f'bplog {addr}, "{text}"')

@mcp.tool()
def DebugEnableBreakpoint(addr: str = "") -> str:
    """
    Enable software breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bpe {addr}" if addr else "bpe")

@mcp.tool()
def DebugDisableBreakpoint(addr: str = "") -> str:
    """
    Disable software breakpoint (all if addr is empty)

    Parameters:
        addr: Memory address or empty for all

    Returns:
        Status message
    """
    return ExecCommand(f"bpd {addr}" if addr else "bpd")

# =============================================================================
# TRACING API
# =============================================================================

@mcp.tool()
def TraceInto(count: str = "1") -> str:
    """
    Trace into for N instructions

    Parameters:
        count: Number of instructions to trace (default: 1)

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"sti {count}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def TraceOver(count: str = "1") -> str:
    """
    Trace over for N instructions

    Parameters:
        count: Number of instructions to trace (default: 1)

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"sto {count}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def TraceIntoConditional(condition: str, max_count: str = "50000") -> str:
    """
    Trace into until condition is met

    Parameters:
        condition: Condition expression (e.g. "eax==0", "rip>0x401000")
        max_count: Maximum instructions to trace (default: 50000)

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"ticnd {condition}, {max_count}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def TraceOverConditional(condition: str, max_count: str = "50000") -> str:
    """
    Trace over until condition is met

    Parameters:
        condition: Condition expression (e.g. "eax==0", "rip>0x401000")
        max_count: Maximum instructions to trace (default: 50000)

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"tocnd {condition}, {max_count}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def RunToUserCode() -> str:
    """
    Run until user code is reached (skip system DLLs)

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": "rtu"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def RunToParty(party: str = "0") -> str:
    """
    Run until code of specified party is reached

    Parameters:
        party: 0 = user, 1 = system

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"RunToParty {party}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def TraceSetLog(text: str, condition: str = "") -> str:
    """
    Set trace log message

    Parameters:
        text: Log format string (can include {eax}, {rip} etc.)
        condition: Optional condition for logging

    Returns:
        Status message
    """
    if condition:
        return ExecCommand(f'TraceSetLog "{text}", "{condition}"')
    return ExecCommand(f'TraceSetLog "{text}"')

@mcp.tool()
def TraceSetCommand(command: str, condition: str = "") -> str:
    """
    Set command to execute during tracing

    Parameters:
        command: Command to execute
        condition: Optional condition

    Returns:
        Status message
    """
    if condition:
        return ExecCommand(f'TraceSetCommand "{command}", "{condition}"')
    return ExecCommand(f'TraceSetCommand "{command}"')

@mcp.tool()
def StartTraceRecording(filepath: str = "") -> str:
    """
    Start trace recording to file

    Parameters:
        filepath: Output file path (optional)

    Returns:
        Status message
    """
    if filepath:
        return ExecCommand(f'opentrace "{filepath}"')
    return ExecCommand("opentrace")

@mcp.tool()
def StopTraceRecording() -> str:
    """
    Stop trace recording

    Returns:
        Status message
    """
    return ExecCommand("tc")

# =============================================================================
# THREAD API
# =============================================================================

@mcp.tool()
def ThreadGetList() -> list:
    """
    Get list of all threads in debugged process

    Returns:
        List of thread information
    """
    result = safe_get("ThreadList")
    if isinstance(result, list):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return [{"error": "Failed to parse thread list", "raw": result}]
    return [{"error": "Unexpected response format"}]

@mcp.tool()
def ThreadSwitch(tid: str) -> str:
    """
    Switch debugger focus to specified thread

    Parameters:
        tid: Thread ID

    Returns:
        Status message
    """
    return ExecCommand(f"switchthread {tid}")

@mcp.tool()
def ThreadSuspend(tid: str) -> str:
    """
    Suspend specific thread

    Parameters:
        tid: Thread ID

    Returns:
        Status message
    """
    return ExecCommand(f"suspendthread {tid}")

@mcp.tool()
def ThreadResume(tid: str) -> str:
    """
    Resume specific thread

    Parameters:
        tid: Thread ID

    Returns:
        Status message
    """
    return ExecCommand(f"resumethread {tid}")

@mcp.tool()
def ThreadSuspendAll() -> str:
    """
    Suspend all threads except current

    Returns:
        Status message
    """
    return ExecCommand("suspendallthreads")

@mcp.tool()
def ThreadResumeAll() -> str:
    """
    Resume all suspended threads

    Returns:
        Status message
    """
    return ExecCommand("resumeallthreads")

@mcp.tool()
def ThreadSetName(tid: str, name: str) -> str:
    """
    Set thread name/label

    Parameters:
        tid: Thread ID
        name: Name to set

    Returns:
        Status message
    """
    return ExecCommand(f'setthreadname {tid}, "{name}"')

@mcp.tool()
def ThreadSetPriority(tid: str, priority: str) -> str:
    """
    Set thread priority

    Parameters:
        tid: Thread ID
        priority: Priority value

    Returns:
        Status message
    """
    return ExecCommand(f"setprioritythread {tid}, {priority}")

@mcp.tool()
def ThreadKill(tid: str, exit_code: str = "0") -> str:
    """
    Kill/terminate thread

    Parameters:
        tid: Thread ID
        exit_code: Exit code (default 0)

    Returns:
        Status message
    """
    return ExecCommand(f"killthread {tid}, {exit_code}")

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
# SEARCHING API
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
    return safe_get("Pattern/FindMem", {"start": start, "size": size, "pattern": pattern})

@mcp.tool()
def FindPattern(addr: str, pattern: str, size: str = "") -> str:
    """
    Find byte pattern starting at address

    Parameters:
        addr: Start address
        pattern: Byte pattern to find
        size: Optional size limit

    Returns:
        Found address or error
    """
    if size:
        return ExecCommand(f"find {addr}, {pattern}, {size}")
    return ExecCommand(f"find {addr}, {pattern}")

@mcp.tool()
def FindAllPattern(addr: str, pattern: str, size: str = "") -> str:
    """
    Find all occurrences of pattern

    Parameters:
        addr: Start address
        pattern: Byte pattern to find
        size: Optional size limit

    Returns:
        Search results
    """
    if size:
        return ExecCommand(f"findall {addr}, {pattern}, {size}")
    return ExecCommand(f"findall {addr}, {pattern}")

@mcp.tool()
def FindAllMemory(pattern: str, region: str = "module") -> str:
    """
    Find pattern in all memory regions

    Parameters:
        pattern: Byte pattern to find
        region: 'user', 'system', or 'module'

    Returns:
        Search results
    """
    return ExecCommand(f"findallmem 0, {pattern}, {region}")

@mcp.tool()
def FindAssembly(addr: str, instruction: str, size: str = "") -> str:
    """
    Find assembly instruction

    Parameters:
        addr: Start address
        instruction: Assembly instruction to find
        size: Optional size limit

    Returns:
        Found address or error
    """
    if size:
        return ExecCommand(f'findasm {addr}, "{instruction}", {size}')
    return ExecCommand(f'findasm {addr}, "{instruction}"')

@mcp.tool()
def FindReferences(addr: str) -> str:
    """
    Find all references to address

    Parameters:
        addr: Target address

    Returns:
        Reference list
    """
    return ExecCommand(f"reffind {addr}")

@mcp.tool()
def FindReferenceRange(start: str, end: str) -> str:
    """
    Find references in address range

    Parameters:
        start: Start address
        end: End address

    Returns:
        Reference list
    """
    return ExecCommand(f"reffindrange {start}, {end}")

@mcp.tool()
def FindStrings(addr: str, size: str = "") -> str:
    """
    Find string references in module

    Parameters:
        addr: Module base address
        size: Optional size limit

    Returns:
        String reference list
    """
    if size:
        return ExecCommand(f"refstr {addr}, {size}")
    return ExecCommand(f"refstr {addr}")

@mcp.tool()
def FindFunctionPointers(addr: str) -> str:
    """
    Find function pointers

    Parameters:
        addr: Start address

    Returns:
        Function pointer list
    """
    return ExecCommand(f"reffuncptr {addr}")

@mcp.tool()
def FindModuleCalls(addr: str) -> str:
    """
    Find calls to different modules

    Parameters:
        addr: Module base address

    Returns:
        Call list
    """
    return ExecCommand(f"modcallfind {addr}")

@mcp.tool()
def FindGUID(addr: str) -> str:
    """
    Find GUID references

    Parameters:
        addr: Start address

    Returns:
        GUID list
    """
    return ExecCommand(f"guidfind {addr}")

# =============================================================================
# ANNOTATION API (Labels, Comments, Bookmarks)
# =============================================================================

@mcp.tool()
def LabelSet(addr: str, text: str) -> str:
    """
    Set label at address

    Parameters:
        addr: Memory address
        text: Label text

    Returns:
        Status message
    """
    return ExecCommand(f'lbl {addr}, "{text}"')

@mcp.tool()
def LabelDelete(addr: str) -> str:
    """
    Delete label at address

    Parameters:
        addr: Memory address

    Returns:
        Status message
    """
    return ExecCommand(f"lbldel {addr}")

@mcp.tool()
def LabelList() -> str:
    """
    Get all labels

    Returns:
        Label list
    """
    return ExecCommand("labellist")

@mcp.tool()
def LabelClear() -> str:
    """
    Clear all labels

    Returns:
        Status message
    """
    return ExecCommand("labelclear")

@mcp.tool()
def CommentSet(addr: str, text: str) -> str:
    """
    Set comment at address

    Parameters:
        addr: Memory address
        text: Comment text

    Returns:
        Status message
    """
    return ExecCommand(f'cmt {addr}, "{text}"')

@mcp.tool()
def CommentDelete(addr: str) -> str:
    """
    Delete comment at address

    Parameters:
        addr: Memory address

    Returns:
        Status message
    """
    return ExecCommand(f"cmtdel {addr}")

@mcp.tool()
def CommentList() -> str:
    """
    Get all comments

    Returns:
        Comment list
    """
    return ExecCommand("commentlist")

@mcp.tool()
def CommentClear() -> str:
    """
    Clear all comments

    Returns:
        Status message
    """
    return ExecCommand("commentclear")

@mcp.tool()
def BookmarkSet(addr: str) -> str:
    """
    Set bookmark at address

    Parameters:
        addr: Memory address

    Returns:
        Status message
    """
    return ExecCommand(f"bookmarkset {addr}")

@mcp.tool()
def BookmarkDelete(addr: str) -> str:
    """
    Delete bookmark at address

    Parameters:
        addr: Memory address

    Returns:
        Status message
    """
    return ExecCommand(f"bookmarkdel {addr}")

@mcp.tool()
def BookmarkList() -> str:
    """
    Get all bookmarks

    Returns:
        Bookmark list
    """
    return ExecCommand("bookmarklist")

@mcp.tool()
def BookmarkClear() -> str:
    """
    Clear all bookmarks

    Returns:
        Status message
    """
    return ExecCommand("bookmarkclear")

# =============================================================================
# MEMORY ADVANCED OPERATIONS
# =============================================================================

@mcp.tool()
def MemoryAlloc(size: str) -> str:
    """
    Allocate memory in target process

    Parameters:
        size: Size in bytes to allocate

    Returns:
        Allocated address or error
    """
    return ExecCommand(f"alloc {size}")

@mcp.tool()
def MemoryFree(addr: str) -> str:
    """
    Free allocated memory

    Parameters:
        addr: Address to free

    Returns:
        Status message
    """
    return ExecCommand(f"free {addr}")

@mcp.tool()
def MemoryFill(addr: str, size: str, value: str) -> str:
    """
    Fill memory with value

    Parameters:
        addr: Start address
        size: Size in bytes
        value: Byte value to fill (e.g. "00", "CC", "90")

    Returns:
        Status message
    """
    return ExecCommand(f"memset {addr}, {value}, {size}")

@mcp.tool()
def MemoryCopy(dest: str, src: str, size: str) -> str:
    """
    Copy memory within target process

    Parameters:
        dest: Destination address
        src: Source address
        size: Size in bytes

    Returns:
        Status message
    """
    return ExecCommand(f"memcpy {dest}, {src}, {size}")

@mcp.tool()
def MemoryGetPageRights(addr: str) -> str:
    """
    Get memory page protection rights

    Parameters:
        addr: Memory address

    Returns:
        Protection rights string
    """
    return ExecCommand(f"getpagerights {addr}")

@mcp.tool()
def MemorySetPageRights(addr: str, rights: str) -> str:
    """
    Set memory page protection rights

    Parameters:
        addr: Memory address
        rights: Protection string (e.g. "ExecuteReadWrite", "ReadOnly")

    Returns:
        Status message
    """
    return ExecCommand(f"setpagerights {addr}, {rights}")

@mcp.tool()
def MemorySaveToFile(addr: str, size: str, filepath: str) -> str:
    """
    Save memory region to file

    Parameters:
        addr: Start address
        size: Size in bytes
        filepath: Output file path

    Returns:
        Status message
    """
    return ExecCommand(f'savedata "{filepath}", {addr}, {size}')

@mcp.tool()
def CreateMinidump(filepath: str) -> str:
    """
    Create minidump of current process state

    Parameters:
        filepath: Output file path

    Returns:
        Status message
    """
    return ExecCommand(f'minidump "{filepath}"')

# =============================================================================
# ANALYSIS API
# =============================================================================

@mcp.tool()
def Analyze(addr: str = "") -> str:
    """
    Perform linear code analysis

    Parameters:
        addr: Start address (optional, uses current selection if empty)

    Returns:
        Status message
    """
    if addr:
        return ExecCommand(f"analyse {addr}")
    return ExecCommand("analyse")

@mcp.tool()
def AnalyzeRecursive(entry: str) -> str:
    """
    Perform recursive analysis from entry point

    Parameters:
        entry: Entry point address

    Returns:
        Status message
    """
    return ExecCommand(f"analrecur {entry}")

@mcp.tool()
def AnalyzeXrefs() -> str:
    """
    Analyze cross-references

    Returns:
        Status message
    """
    return ExecCommand("analxrefs")

@mcp.tool()
def AnalyzeControlFlow() -> str:
    """
    Perform control flow analysis

    Returns:
        Status message
    """
    return ExecCommand("cfanalyse")

@mcp.tool()
def AnalyzeAdvanced() -> str:
    """
    Perform advanced analysis

    Returns:
        Status message
    """
    return ExecCommand("analyseadv")

@mcp.tool()
def AnalyzeException() -> str:
    """
    Perform exception directory analysis

    Returns:
        Status message
    """
    return ExecCommand("exanalyse")

@mcp.tool()
def GetExceptionHandlers() -> str:
    """
    List SEH/VEH exception handlers

    Returns:
        Handler list
    """
    return ExecCommand("exhandlers")

@mcp.tool()
def GetExceptionInfo() -> str:
    """
    Get last exception information

    Returns:
        Exception details
    """
    return ExecCommand("exinfo")

@mcp.tool()
def GetImageInfo(addr: str) -> str:
    """
    Get PE image information

    Parameters:
        addr: Image base address

    Returns:
        Image information
    """
    return ExecCommand(f"imageinfo {addr}")

@mcp.tool()
def GetRelocSize(addr: str) -> str:
    """
    Get relocation table size

    Parameters:
        addr: Image base address

    Returns:
        Relocation size
    """
    return ExecCommand(f"getrelocsize {addr}")

# =============================================================================
# PROCESS CONTROL EXTENDED
# =============================================================================

@mcp.tool()
def DebugInit(filepath: str, args: str = "", workdir: str = "") -> str:
    """
    Start debugging a new process

    Parameters:
        filepath: Executable path
        args: Command line arguments (optional)
        workdir: Working directory (optional)

    Returns:
        Status message
    """
    cmd = f'init "{filepath}"'
    if args:
        cmd += f', "{args}"'
    if workdir:
        cmd += f', "{workdir}"'
    return safe_get("ExecCommand", {"cmd": cmd}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugAttach(pid: str) -> str:
    """
    Attach to running process by PID

    Parameters:
        pid: Process ID

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"attach {pid}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugDetach() -> str:
    """
    Detach from current process

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": "detach"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugRestart() -> str:
    """
    Restart debugging session

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": "restart"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugSkip(count: str = "1") -> str:
    """
    Skip instruction without executing

    Parameters:
        count: Number of instructions to skip (default: 1)

    Returns:
        Status message
    """
    return ExecCommand(f"skip {count}")

@mcp.tool()
def DebugRunToAddress(addr: str) -> str:
    """
    Run until specified address is reached

    Parameters:
        addr: Target address

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": f"run {addr}"}, timeout=TIMEOUT_DEBUG)

@mcp.tool()
def DebugWait() -> str:
    """
    Wait for debug event

    Returns:
        Status message
    """
    return safe_get("ExecCommand", {"cmd": "wait"}, timeout=TIMEOUT_DEBUG)

# =============================================================================
# STATE SNAPSHOT & RESTORE
# =============================================================================

@mcp.tool()
def SaveDebugState(filepath: str = "") -> dict:
    """
    Save current debug state (registers, flags, stack snapshot)

    Parameters:
        filepath: Optional file path to persist state

    Returns:
        Dictionary containing saved state
    """
    state = {}

    # Save all general purpose registers
    regs_64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip',
               'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    regs_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip']

    state['registers'] = {}
    for reg in regs_64:
        result = safe_get("Register/Get", {"register": reg}, timeout=TIMEOUT_FAST)
        if isinstance(result, str) and not result.startswith("Error"):
            state['registers'][reg] = result

    # Save flags
    state['flags'] = {}
    for flag in ['ZF', 'OF', 'CF', 'PF', 'SF', 'TF', 'AF', 'DF', 'IF']:
        result = safe_get("Flag/Get", {"flag": flag}, timeout=TIMEOUT_FAST)
        if isinstance(result, str):
            state['flags'][flag] = result.lower() == "true"

    # Save stack snapshot (top 16 values)
    state['stack'] = []
    for i in range(16):
        result = safe_get("Stack/Peek", {"offset": str(i * 8)}, timeout=TIMEOUT_FAST)
        if isinstance(result, str) and not result.startswith("Error"):
            state['stack'].append(result)

    # Optionally save to file
    if filepath:
        try:
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2)
            state['saved_to'] = filepath
        except Exception as e:
            state['save_error'] = str(e)

    return state

@mcp.tool()
def RestoreDebugState(state: str = "", filepath: str = "") -> dict:
    """
    Restore debug state from saved state or file

    Parameters:
        state: JSON string of saved state (from SaveDebugState)
        filepath: Path to state file (alternative to state parameter)

    Returns:
        Dictionary with restore results
    """
    results = {'restored': [], 'errors': []}

    # Load state
    state_data = None
    if filepath:
        try:
            with open(filepath, 'r') as f:
                state_data = json.load(f)
        except Exception as e:
            return {'error': f'Failed to load state file: {e}'}
    elif state:
        try:
            state_data = json.loads(state)
        except json.JSONDecodeError as e:
            return {'error': f'Invalid state JSON: {e}'}
    else:
        return {'error': 'Must provide either state JSON or filepath'}

    # Restore registers
    if 'registers' in state_data:
        for reg, value in state_data['registers'].items():
            result = safe_get("Register/Set", {"register": reg, "value": value})
            if isinstance(result, str) and "Error" in result:
                results['errors'].append(f'{reg}: {result}')
            else:
                results['restored'].append(reg)

    # Restore flags
    if 'flags' in state_data:
        for flag, value in state_data['flags'].items():
            result = safe_get("Flag/Set", {"flag": flag, "value": "true" if value else "false"})
            if isinstance(result, str) and "Error" in result:
                results['errors'].append(f'{flag}: {result}')
            else:
                results['restored'].append(flag)

    return results

# =============================================================================
# INTELLIGENT STEPPING
# =============================================================================

@mcp.tool()
def StepUntilInstruction(mnemonic: str, max_steps: int = 1000) -> dict:
    """
    Step until specific instruction mnemonic is reached

    Parameters:
        mnemonic: Instruction mnemonic to find (e.g. "ret", "call", "jmp")
        max_steps: Maximum steps before giving up (default: 1000)

    Returns:
        Dictionary with result info
    """
    mnemonic_lower = mnemonic.lower()

    for i in range(max_steps):
        # Get current instruction
        result = safe_get("Disasm/GetInstructionAtRIP", timeout=TIMEOUT_FAST)
        if isinstance(result, dict):
            instr = result.get('instruction', '').lower()
            if instr.startswith(mnemonic_lower):
                return {
                    'found': True,
                    'steps': i,
                    'instruction': result,
                    'address': result.get('address', 'unknown')
                }
        elif isinstance(result, str):
            try:
                parsed = json.loads(result)
                instr = parsed.get('instruction', '').lower()
                if instr.startswith(mnemonic_lower):
                    return {
                        'found': True,
                        'steps': i,
                        'instruction': parsed,
                        'address': parsed.get('address', 'unknown')
                    }
            except:
                pass

        # Step into
        step_result = safe_get("Debug/StepIn", timeout=TIMEOUT_DEBUG)
        if isinstance(step_result, str) and "Error" in step_result:
            return {'found': False, 'error': step_result, 'steps': i}

    return {'found': False, 'reason': 'max_steps_exceeded', 'steps': max_steps}

@mcp.tool()
def StepUntilAddress(target_addr: str, max_steps: int = 10000) -> dict:
    """
    Step until specific address is reached

    Parameters:
        target_addr: Target address to reach
        max_steps: Maximum steps before giving up

    Returns:
        Dictionary with result info
    """
    # Normalize target address
    target = target_addr.lower().replace('0x', '')

    for i in range(max_steps):
        # Get current RIP
        result = safe_get("Register/Get", {"register": "rip"}, timeout=TIMEOUT_FAST)
        if isinstance(result, str):
            current = result.lower().replace('0x', '')
            if current == target:
                return {'reached': True, 'steps': i, 'address': result}

        # Step
        step_result = safe_get("Debug/StepIn", timeout=TIMEOUT_DEBUG)
        if isinstance(step_result, str) and "Error" in step_result:
            return {'reached': False, 'error': step_result, 'steps': i}

    return {'reached': False, 'reason': 'max_steps_exceeded', 'steps': max_steps}

@mcp.tool()
def StepUntilCondition(condition: str, max_steps: int = 10000) -> dict:
    """
    Step until condition expression is true

    Parameters:
        condition: Condition expression (e.g. "eax==0", "rip>0x401000")
        max_steps: Maximum steps before giving up

    Returns:
        Dictionary with result info
    """
    for i in range(max_steps):
        # Evaluate condition using x64dbg expression parser
        result = safe_get("Misc/ParseExpression", {"expression": condition}, timeout=TIMEOUT_FAST)
        if isinstance(result, str):
            # Non-zero means condition is true
            try:
                val = int(result, 16) if result.startswith('0x') else int(result)
                if val != 0:
                    rip = safe_get("Register/Get", {"register": "rip"}, timeout=TIMEOUT_FAST)
                    return {'met': True, 'steps': i, 'address': rip}
            except:
                pass

        # Step
        step_result = safe_get("Debug/StepIn", timeout=TIMEOUT_DEBUG)
        if isinstance(step_result, str) and "Error" in step_result:
            return {'met': False, 'error': step_result, 'steps': i}

    return {'met': False, 'reason': 'max_steps_exceeded', 'steps': max_steps}

# =============================================================================
# BATCH OPERATIONS
# =============================================================================

@mcp.tool()
def BatchCommands(commands: str, stop_on_error: bool = False) -> list:
    """
    Execute multiple commands in sequence

    Parameters:
        commands: Newline or semicolon separated list of commands
        stop_on_error: Stop execution if a command fails

    Returns:
        List of results for each command
    """
    # Parse commands
    cmd_list = []
    for line in commands.replace(';', '\n').split('\n'):
        cmd = line.strip()
        if cmd and not cmd.startswith('#'):
            cmd_list.append(cmd)

    results = []
    for cmd in cmd_list:
        result = ExecCommand(cmd)
        entry = {'command': cmd, 'result': result}

        if stop_on_error and isinstance(result, str) and 'error' in result.lower():
            entry['stopped'] = True
            results.append(entry)
            break

        results.append(entry)

    return results

@mcp.tool()
def BatchSetBreakpoints(addresses: str) -> list:
    """
    Set breakpoints at multiple addresses

    Parameters:
        addresses: Comma or newline separated list of addresses

    Returns:
        List of results
    """
    addr_list = [a.strip() for a in addresses.replace(',', '\n').split('\n') if a.strip()]
    results = []

    for addr in addr_list:
        result = DebugSetBreakpoint(addr)
        results.append({'address': addr, 'result': result})

    return results

@mcp.tool()
def BatchDeleteBreakpoints(addresses: str = "") -> list:
    """
    Delete breakpoints at multiple addresses (or all if empty)

    Parameters:
        addresses: Comma separated addresses, or empty for all

    Returns:
        List of results
    """
    if not addresses.strip():
        result = ExecCommand("bpc")
        return [{'action': 'delete_all', 'result': result}]

    addr_list = [a.strip() for a in addresses.replace(',', '\n').split('\n') if a.strip()]
    results = []

    for addr in addr_list:
        result = DebugDeleteBreakpoint(addr)
        results.append({'address': addr, 'result': result})

    return results

@mcp.tool()
def BatchReadMemory(regions: str) -> list:
    """
    Read multiple memory regions

    Parameters:
        regions: Format "addr:size" per line (e.g. "0x401000:0x100\\n0x402000:0x50")

    Returns:
        List of memory read results
    """
    results = []

    for line in regions.strip().split('\n'):
        line = line.strip()
        if not line or ':' not in line:
            continue

        parts = line.split(':')
        if len(parts) == 2:
            addr, size = parts[0].strip(), parts[1].strip()
            data = MemoryRead(addr, size)
            results.append({'address': addr, 'size': size, 'data': data})

    return results

@mcp.tool()
def BatchDisassemble(addresses: str, count: int = 5) -> list:
    """
    Disassemble at multiple addresses

    Parameters:
        addresses: Comma or newline separated addresses
        count: Instructions per address (default: 5)

    Returns:
        List of disassembly results
    """
    addr_list = [a.strip() for a in addresses.replace(',', '\n').split('\n') if a.strip()]
    results = []

    for addr in addr_list:
        disasm = DisasmGetInstructionRange(addr, count)
        results.append({'address': addr, 'instructions': disasm})

    return results

# =============================================================================
# SYMBOL MANAGEMENT
# =============================================================================

@mcp.tool()
def SymbolDownload(module: str = "") -> str:
    """
    Download PDB symbols for module

    Parameters:
        module: Module name (optional, downloads all if empty)

    Returns:
        Status message
    """
    if module:
        return ExecCommand(f"symdownload {module}")
    return ExecCommand("symdownload")

@mcp.tool()
def SymbolLoad(module: str, pdb_path: str) -> str:
    """
    Load PDB file for module

    Parameters:
        module: Module name
        pdb_path: Path to PDB file

    Returns:
        Status message
    """
    return ExecCommand(f'loadsymbol {module}, "{pdb_path}"')

@mcp.tool()
def SymbolUnload(module: str) -> str:
    """
    Unload symbols for module

    Parameters:
        module: Module name

    Returns:
        Status message
    """
    return ExecCommand(f"unloadsymbol {module}")

@mcp.tool()
def SymbolGetAddress(module: str, symbol: str) -> str:
    """
    Get address of symbol

    Parameters:
        module: Module name
        symbol: Symbol name

    Returns:
        Symbol address
    """
    return MiscParseExpression(f"{module}.{symbol}")

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
# LEGACY COMPATIBILITY FUNCTIONS (DEPRECATED)
# These functions are kept for backward compatibility but are deprecated.
# Use the new API functions instead.
# =============================================================================

def _deprecation_warning(old_name: str, new_name: str):
    """Issue deprecation warning for legacy functions"""
    warnings.warn(
        f"{old_name} is deprecated, use {new_name} instead",
        DeprecationWarning,
        stacklevel=3
    )

@mcp.tool()
def SetRegister(name: str, value: str) -> str:
    """
    [DEPRECATED] Set register value using command (legacy compatibility)
    Use RegisterSet instead.

    Parameters:
        name: Register name (e.g. "eax", "rip")
        value: Value to set (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    _deprecation_warning("SetRegister", "RegisterSet")
    return RegisterSet(name, value)

@mcp.tool()
def MemRead(addr: str, size: str) -> str:
    """
    [DEPRECATED] Read memory at address (legacy compatibility)
    Use MemoryRead instead.

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        size: Number of bytes to read

    Returns:
        Hexadecimal string representing the memory contents
    """
    _deprecation_warning("MemRead", "MemoryRead")
    return MemoryRead(addr, size)

@mcp.tool()
def MemWrite(addr: str, data: str) -> str:
    """
    [DEPRECATED] Write memory at address (legacy compatibility)
    Use MemoryWrite instead.

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        data: Hexadecimal string representing the data to write

    Returns:
        Status message
    """
    _deprecation_warning("MemWrite", "MemoryWrite")
    return MemoryWrite(addr, data)

@mcp.tool()
def SetBreakpoint(addr: str) -> str:
    """
    [DEPRECATED] Set breakpoint at address (legacy compatibility)
    Use DebugSetBreakpoint instead.

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    _deprecation_warning("SetBreakpoint", "DebugSetBreakpoint")
    return DebugSetBreakpoint(addr)

@mcp.tool()
def DeleteBreakpoint(addr: str) -> str:
    """
    [DEPRECATED] Delete breakpoint at address (legacy compatibility)
    Use DebugDeleteBreakpoint instead.

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    _deprecation_warning("DeleteBreakpoint", "DebugDeleteBreakpoint")
    return DebugDeleteBreakpoint(addr)

@mcp.tool()
def Run() -> str:
    """
    [DEPRECATED] Resume execution of the debugged process (legacy compatibility)
    Use DebugRun instead.

    Returns:
        Status message
    """
    _deprecation_warning("Run", "DebugRun")
    return DebugRun()

@mcp.tool()
def Pause() -> str:
    """
    [DEPRECATED] Pause execution of the debugged process (legacy compatibility)
    Use DebugPause instead.

    Returns:
        Status message
    """
    _deprecation_warning("Pause", "DebugPause")
    return DebugPause()

@mcp.tool()
def StepIn() -> str:
    """
    [DEPRECATED] Step into the next instruction (legacy compatibility)
    Use DebugStepIn instead.

    Returns:
        Status message
    """
    _deprecation_warning("StepIn", "DebugStepIn")
    return DebugStepIn()

@mcp.tool()
def StepOver() -> str:
    """
    [DEPRECATED] Step over the next instruction (legacy compatibility)
    Use DebugStepOver instead.

    Returns:
        Status message
    """
    _deprecation_warning("StepOver", "DebugStepOver")
    return DebugStepOver()

@mcp.tool()
def StepOut() -> str:
    """
    [DEPRECATED] Step out of the current function (legacy compatibility)
    Use DebugStepOut instead.

    Returns:
        Status message
    """
    _deprecation_warning("StepOut", "DebugStepOut")
    return DebugStepOut()

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
    result = safe_get("Disasm/StepInWithDisasm", timeout=TIMEOUT_DEBUG)
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
