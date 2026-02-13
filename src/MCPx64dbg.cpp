#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

// Include Windows headers before socket headers
#include <Windows.h>
// Include x64dbg SDK
#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_register.h"
#include "pluginsdk/_scriptapi_debug.h"
#include "pluginsdk/_scriptapi_assembler.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_label.h"
#include "pluginsdk/_scriptapi_bookmark.h"
#include "pluginsdk/_scriptapi_function.h"
#include "pluginsdk/_scriptapi_argument.h"
#include "pluginsdk/_scriptapi_symbol.h"
#include "pluginsdk/_scriptapi_stack.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "pluginsdk/_scriptapi_flag.h"
#include "pluginsdk/_scriptapi_gui.h"
#include "pluginsdk/_scriptapi_misc.h"
#include <iomanip>  // For std::setw and std::setfill

// Socket includes - after Windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

// Standard library includes
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <mutex>
#include <thread>
#include <algorithm>
#include <memory>
#include <fstream>
#include <cctype>
#include <functional>
// Link with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")

// Link against correct x64dbg library depending on architecture
#ifdef _WIN64
#pragma comment(lib, "x64dbg.lib")
#else
#pragma comment(lib, "x32dbg.lib")
#endif

// Architecture-aware formatting and register macros
#ifdef _WIN64
#define FMT_DUINT_HEX "0x%llx"
#define FMT_DUINT_DEC "%llu"
#define DUINT_CAST_PRINTF(v) (unsigned long long)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned long long)(v)
#define REG_IP Script::Register::RIP
#else
#define FMT_DUINT_HEX "0x%08X"
#define FMT_DUINT_DEC "%u"
#define DUINT_CAST_PRINTF(v) (unsigned int)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned int)(v)
#define REG_IP Script::Register::EIP
#endif

// Plugin information
#define PLUGIN_NAME "x64dbg HTTP Server"
#define PLUGIN_VERSION 1

// Default settings
#define DEFAULT_PORT 8888
#define MAX_REQUEST_SIZE 8192

// Global variables
int g_pluginHandle;
HANDLE g_httpServerThread = NULL;
bool g_httpServerRunning = false;
int g_httpPort = DEFAULT_PORT;
std::mutex g_httpMutex;
SOCKET g_serverSocket = INVALID_SOCKET;

// Forward declarations
bool startHttpServer();
void stopHttpServer();
DWORD WINAPI HttpServerThread(LPVOID lpParam);
std::string readHttpRequest(SOCKET clientSocket);
void sendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody);
void parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body);
std::unordered_map<std::string, std::string> parseQueryParams(const std::string& query);
std::string urlDecode(const std::string& str);

// Command callback declarations
bool cbEnableHttpServer(int argc, char* argv[]);
bool cbSetHttpPort(int argc, char* argv[]);
void registerCommands();

//=============================================================================
// Plugin Interface Implementation
//============================================================================


// Initialize the plugin
bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;
    
    _plugin_logputs("x64dbg HTTP Server plugin loading...");
    
    // Register commands
    registerCommands();

    // Start the HTTP server
    if (startHttpServer()) {
        _plugin_logprintf("x64dbg HTTP Server started on port %d\n", g_httpPort);
    } else {
        _plugin_logputs("Failed to start HTTP server!");
    }
    
    _plugin_logputs("x64dbg HTTP Server plugin loaded!");
    return true;
}

// Stop the plugin
void pluginStop() {
    _plugin_logputs("Stopping x64dbg HTTP Server...");
    stopHttpServer();
    _plugin_logputs("x64dbg HTTP Server stopped.");
}

// Plugin setup
bool pluginSetup() {
    return true;
}

// Plugin exports
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    return pluginInit(initStruct);
}

extern "C" __declspec(dllexport) void plugstop() {
    pluginStop();
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    pluginSetup();
}

//=============================================================================
// HTTP Server Implementation
//=============================================================================

// Start the HTTP server
bool startHttpServer() {
    std::lock_guard<std::mutex> lock(g_httpMutex);
    
    // Stop existing server if running
    if (g_httpServerRunning) {
        stopHttpServer();
    }
    
    // Create and start the server thread
    g_httpServerThread = CreateThread(NULL, 0, HttpServerThread, NULL, 0, NULL);
    if (g_httpServerThread == NULL) {
        _plugin_logputs("Failed to create HTTP server thread");
        return false;
    }
    
    g_httpServerRunning = true;
    return true;
}

// Stop the HTTP server
void stopHttpServer() {
    std::lock_guard<std::mutex> lock(g_httpMutex);
    
    if (g_httpServerRunning) {
        g_httpServerRunning = false;
        
        // Close the server socket to unblock any accept calls
        if (g_serverSocket != INVALID_SOCKET) {
            closesocket(g_serverSocket);
            g_serverSocket = INVALID_SOCKET;
        }
        
        // Wait for the thread to exit
        if (g_httpServerThread != NULL) {
            WaitForSingleObject(g_httpServerThread, 1000);
            CloseHandle(g_httpServerThread);
            g_httpServerThread = NULL;
        }
    }
}

// URL decode function
std::string urlDecode(const std::string& str) {
    std::string decoded;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            std::istringstream is(str.substr(i + 1, 2));
            if (is >> std::hex >> value) {
                decoded += static_cast<char>(value);
                i += 2;
            } else {
                decoded += str[i];
            }
        } else if (str[i] == '+') {
            decoded += ' ';
        } else {
            decoded += str[i];
        }
    }
    return decoded;
}

// HTTP server thread function using standard Winsock
DWORD WINAPI HttpServerThread(LPVOID lpParam) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        _plugin_logprintf("WSAStartup failed with error: %d\n", result);
        return 1;
    }
    
    // Create a socket for the server
    g_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_serverSocket == INVALID_SOCKET) {
        _plugin_logprintf("Failed to create socket, error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Setup the server address structure
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // localhost only
    serverAddr.sin_port = htons((u_short)g_httpPort);
    
    // Bind the socket
    if (bind(g_serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        _plugin_logprintf("Bind failed with error: %d\n", WSAGetLastError());
        closesocket(g_serverSocket);
        WSACleanup();
        return 1;
    }
    
    // Listen for incoming connections
    if (listen(g_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        _plugin_logprintf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(g_serverSocket);
        WSACleanup();
        return 1;
    }
    
    _plugin_logprintf("HTTP server started at http://localhost:%d/\n", g_httpPort);
    
    // Set socket to non-blocking mode
    u_long mode = 1;
    ioctlsocket(g_serverSocket, FIONBIO, &mode);
    
    // Main server loop
    while (g_httpServerRunning) {
        // Accept a client connection
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(g_serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == INVALID_SOCKET) {
            // Check if we need to exit
            if (!g_httpServerRunning) {
                break;
            }
            
            // Non-blocking socket may return WOULD_BLOCK when no connections are pending
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                _plugin_logprintf("Accept failed with error: %d\n", WSAGetLastError());
            }
            
            Sleep(100); // Avoid tight loop
            continue;
        }
        
        // Read the HTTP request
        std::string requestData = readHttpRequest(clientSocket);
        
        if (!requestData.empty()) {
            // Parse the HTTP request
            std::string method, path, query, body;
            parseHttpRequest(requestData, method, path, query, body);
            
            _plugin_logprintf("HTTP Request: %s %s\n", method.c_str(), path.c_str());
            
            // Parse query parameters
            std::unordered_map<std::string, std::string> queryParams = parseQueryParams(query);
            
            // Handle different endpoints
            try {
                // Unified command execution endpoint
                if (path == "/ExecCommand") {
                    std::string cmd = queryParams["cmd"];
                    if (cmd.empty() && !body.empty()) {
                        cmd = body;
                    }
                     else {
                        cmd = urlDecode(cmd);  
                    }
                    
                    if (cmd.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing command parameter");
                        continue;
                    }
                    
                    // Generate unique log file path
                    char tempPath[MAX_PATH];
                    GetTempPathA(MAX_PATH, tempPath);
                    std::string logFile = std::string(tempPath) + "x64dbg_cmd_" + 
                        std::to_string(GetTickCount64()) + ".log";
                    
                    // Clear the log first
                    GuiLogRedirect(logFile.c_str());
                    // Execute the command
                    bool success = DbgCmdExecDirect(cmd.c_str());
                    GuiFlushLog();
                    Sleep(300);
                    GuiLogRedirectStop();
                    // Wait for command to complete
                    Sleep(100);
                
                    
                    // Read the saved log
                    std::string output;
                    std::ifstream file(logFile);
                    if (file) {
                        std::stringstream buffer;
                        buffer << file.rdbuf();
                        output = buffer.str();
                    }
                 
                    
                    std::string response = output.empty() 
                        ? (success ? "Command executed (no output)" : "Command failed")
                        : output;
                    DeleteFileA(logFile.c_str());
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", response);
                }
                                else if (path == "/IsDebugActive") {
                    bool isDebugging = DbgIsDebugging();
                    bool isRunning = isDebugging && DbgIsRunning();
                    _plugin_logprintf("DbgIsRunning() called, result: %s (debugging=%s)\n",
                        isRunning ? "true" : "false",
                        isDebugging ? "true" : "false");
                    std::stringstream ss;
                    ss << "{\"isRunning\":" << (isRunning ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Is_Debugging") {
                    bool isDebugging = DbgIsDebugging();
                    _plugin_logprintf("DbgIsDebugging() called, result: %s\n", isDebugging ? "true" : "false");
                    std::stringstream ss;
                    ss << "{\"isDebugging\":" << (isDebugging ? "true" : "false") << "}";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                // =============================================================================
                // REGISTER API ENDPOINTS
                // =============================================================================
                else if (path == "/Register/Get") {
                    std::string regName = queryParams["register"];
                    if (regName.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing register parameter");
                        continue;
                    }
                    
                    // Convert register name to enum (simplified mapping)
                    Script::Register::RegisterEnum reg;
                    if (regName == "EAX" || regName == "eax") reg = Script::Register::EAX;
                    else if (regName == "EBX" || regName == "ebx") reg = Script::Register::EBX;
                    else if (regName == "ECX" || regName == "ecx") reg = Script::Register::ECX;
                    else if (regName == "EDX" || regName == "edx") reg = Script::Register::EDX;
                    else if (regName == "ESI" || regName == "esi") reg = Script::Register::ESI;
                    else if (regName == "EDI" || regName == "edi") reg = Script::Register::EDI;
                    else if (regName == "EBP" || regName == "ebp") reg = Script::Register::EBP;
                    else if (regName == "ESP" || regName == "esp") reg = Script::Register::ESP;
                    else if (regName == "EIP" || regName == "eip") reg = Script::Register::EIP;
#ifdef _WIN64
                    else if (regName == "RAX" || regName == "rax") reg = Script::Register::RAX;
                    else if (regName == "RBX" || regName == "rbx") reg = Script::Register::RBX;
                    else if (regName == "RCX" || regName == "rcx") reg = Script::Register::RCX;
                    else if (regName == "RDX" || regName == "rdx") reg = Script::Register::RDX;
                    else if (regName == "RSI" || regName == "rsi") reg = Script::Register::RSI;
                    else if (regName == "RDI" || regName == "rdi") reg = Script::Register::RDI;
                    else if (regName == "RBP" || regName == "rbp") reg = Script::Register::RBP;
                    else if (regName == "RSP" || regName == "rsp") reg = Script::Register::RSP;
                    else if (regName == "RIP" || regName == "rip") {
#ifdef _WIN64
                        reg = Script::Register::RIP;
#else
                        // On x86, map RIP queries to EIP for compatibility
                        reg = Script::Register::EIP;
#endif
                    }
                    else if (regName == "R8" || regName == "r8") reg = Script::Register::R8;
                    else if (regName == "R9" || regName == "r9") reg = Script::Register::R9;
                    else if (regName == "R10" || regName == "r10") reg = Script::Register::R10;
                    else if (regName == "R11" || regName == "r11") reg = Script::Register::R11;
                    else if (regName == "R12" || regName == "r12") reg = Script::Register::R12;
                    else if (regName == "R13" || regName == "r13") reg = Script::Register::R13;
                    else if (regName == "R14" || regName == "r14") reg = Script::Register::R14;
                    else if (regName == "R15" || regName == "r15") reg = Script::Register::R15;
#endif
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown register");
                        continue;
                    }
                    
                    duint value = Script::Register::Get(reg);
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Register/Set") {
                    std::string regName = queryParams["register"];
                    std::string valueStr = queryParams["value"];
                    if (regName.empty() || valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing register or value parameter");
                        continue;
                    }
                    
                    // Convert register name to enum (same mapping as above)
                    Script::Register::RegisterEnum reg;
                    if (regName == "EAX" || regName == "eax") reg = Script::Register::EAX;
                    else if (regName == "EBX" || regName == "ebx") reg = Script::Register::EBX;
                    else if (regName == "ECX" || regName == "ecx") reg = Script::Register::ECX;
                    else if (regName == "EDX" || regName == "edx") reg = Script::Register::EDX;
                    else if (regName == "ESI" || regName == "esi") reg = Script::Register::ESI;
                    else if (regName == "EDI" || regName == "edi") reg = Script::Register::EDI;
                    else if (regName == "EBP" || regName == "ebp") reg = Script::Register::EBP;
                    else if (regName == "ESP" || regName == "esp") reg = Script::Register::ESP;
                    else if (regName == "EIP" || regName == "eip") reg = Script::Register::EIP;
#ifdef _WIN64
                    else if (regName == "RAX" || regName == "rax") reg = Script::Register::RAX;
                    else if (regName == "RBX" || regName == "rbx") reg = Script::Register::RBX;
                    else if (regName == "RCX" || regName == "rcx") reg = Script::Register::RCX;
                    else if (regName == "RDX" || regName == "rdx") reg = Script::Register::RDX;
                    else if (regName == "RSI" || regName == "rsi") reg = Script::Register::RSI;
                    else if (regName == "RDI" || regName == "rdi") reg = Script::Register::RDI;
                    else if (regName == "RBP" || regName == "rbp") reg = Script::Register::RBP;
                    else if (regName == "RSP" || regName == "rsp") reg = Script::Register::RSP;
                    else if (regName == "RIP" || regName == "rip") {
#ifdef _WIN64
                        reg = Script::Register::RIP;
#else
                        reg = Script::Register::EIP;
#endif
                    }
                    else if (regName == "R8" || regName == "r8") reg = Script::Register::R8;
                    else if (regName == "R9" || regName == "r9") reg = Script::Register::R9;
                    else if (regName == "R10" || regName == "r10") reg = Script::Register::R10;
                    else if (regName == "R11" || regName == "r11") reg = Script::Register::R11;
                    else if (regName == "R12" || regName == "r12") reg = Script::Register::R12;
                    else if (regName == "R13" || regName == "r13") reg = Script::Register::R13;
                    else if (regName == "R14" || regName == "r14") reg = Script::Register::R14;
                    else if (regName == "R15" || regName == "r15") reg = Script::Register::R15;
#endif
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown register");
                        continue;
                    }
                    
                    duint value = 0;
                    try {
                        if (valueStr.substr(0, 2) == "0x") {
                            value = std::stoull(valueStr.substr(2), nullptr, 16);
                        } else {
                            value = std::stoull(valueStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid value format");
                        continue;
                    }
                    
                    bool success = Script::Register::Set(reg, value);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Register set successfully" : "Failed to set register");
                }
                else if (path == "/Memory/Read") {
                    std::string addrStr = queryParams["addr"];
                    std::string sizeStr = queryParams["size"];
                    
                    if (addrStr.empty() || sizeStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or size");
                        continue;
                    }
                    
                    duint addr = 0;
                    duint size = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                        size = std::stoull(sizeStr, nullptr, 10);
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or size format");
                        continue;
                    }
                    
                    if (size > 1024 * 1024) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Size too large");
                        continue;
                    }
                    
                    std::vector<unsigned char> buffer(size);
                    duint sizeRead = 0;
                    
                    if (!Script::Memory::Read(addr, buffer.data(), size, &sizeRead)) {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to read memory");
                        continue;
                    }
                    
                    std::stringstream ss;
                    for (duint i = 0; i < sizeRead; i++) {
                        ss << std::setw(2) << std::setfill('0') << std::hex << (int)buffer[i];
                    }
                    
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Memory/Write") {
                    std::string addrStr = queryParams["addr"];
                    std::string dataStr = !body.empty() ? body : queryParams["data"];
                    
                    if (addrStr.empty() || dataStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or data");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    std::vector<unsigned char> buffer;
                    for (size_t i = 0; i < dataStr.length(); i += 2) {
                        if (i + 1 >= dataStr.length()) break;
                        std::string byteString = dataStr.substr(i, 2);
                        try {
                            unsigned char byte = (unsigned char)std::stoi(byteString, nullptr, 16);
                            buffer.push_back(byte);
                        } catch (const std::exception& e) {
                            sendHttpResponse(clientSocket, 400, "text/plain", "Invalid data format");
                            continue;
                        }
                    }
                    
                    duint sizeWritten = 0;
                    bool success = Script::Memory::Write(addr, buffer.data(), buffer.size(), &sizeWritten);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Memory written successfully" : "Failed to write memory");
                }
                else if (path == "/Memory/IsValidPtr") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool isValid = Script::Memory::IsValidPtr(addr);
                    sendHttpResponse(clientSocket, 200, "text/plain", isValid ? "true" : "false");
                }
                else if (path == "/Memory/GetProtect") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    unsigned int protect = Script::Memory::GetProtect(addr);
                    std::stringstream ss;
                    ss << "0x" << std::hex << protect;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                
                // =============================================================================
                // DEBUG API ENDPOINTS
                // =============================================================================
                else if (path == "/Debug/Run") {
                    std::thread([]() {
                        Script::Debug::Run();
                    }).detach();
                    sendHttpResponse(clientSocket, 200, "text/plain", "Debug run queued");
                }
                else if (path == "/Debug/Pause") {
                    std::thread([]() {
                        Script::Debug::Pause();
                    }).detach();
                    sendHttpResponse(clientSocket, 200, "text/plain", "Debug pause queued");
                }
                else if (path == "/Debug/Stop") {
                    std::thread([]() {
                        Script::Debug::Stop();
                    }).detach();
                    sendHttpResponse(clientSocket, 200, "text/plain", "Debug stop queued");
                }
                else if (path == "/Debug/StepIn") {
                    Script::Debug::StepIn();
                    sendHttpResponse(clientSocket, 200, "text/plain", "Step in executed");
                }
                else if (path == "/Debug/StepOver") {
                    Script::Debug::StepOver();
                    sendHttpResponse(clientSocket, 200, "text/plain", "Step over executed");
                }
                else if (path == "/Debug/StepOut") {
                    Script::Debug::StepOut();
                    sendHttpResponse(clientSocket, 200, "text/plain", "Step out executed");
                }
                else if (path == "/Debug/SetBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Debug::SetBreakpoint(addr);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Breakpoint set successfully" : "Failed to set breakpoint");
                }
                else if (path == "/Debug/DeleteBreakpoint") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Debug::DeleteBreakpoint(addr);
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Breakpoint deleted successfully" : "Failed to delete breakpoint");
                }
                
                else if (path == "/Assembler/Assemble") {
                    std::string addrStr = queryParams["addr"];
                    std::string instruction = queryParams["instruction"];
                    if (instruction.empty() && !body.empty()) {
                        instruction = body;
                    }
                    
                    if (addrStr.empty() || instruction.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or instruction parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    unsigned char dest[16];
                    int size = 16;
                    bool success = Script::Assembler::Assemble(addr, dest, &size, instruction.c_str());
                    
                    if (success) {
                        std::stringstream ss;
                        ss << "{\"success\":true,\"size\":" << size << ",\"bytes\":\"";
                        for (int i = 0; i < size; i++) {
                            ss << std::setw(2) << std::setfill('0') << std::hex << (int)dest[i];
                        }
                        ss << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to assemble instruction");
                    }
                }
                else if (path == "/Assembler/AssembleMem") {
                    std::string addrStr = queryParams["addr"];
                    std::string instruction = queryParams["instruction"];
                    if (instruction.empty() && !body.empty()) {
                        instruction = body;
                    }
                    
                    if (addrStr.empty() || instruction.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address or instruction parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    bool success = Script::Assembler::AssembleMem(addr, instruction.c_str());
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Instruction assembled in memory successfully" : "Failed to assemble instruction in memory");
                }
                else if (path == "/Stack/Pop") {
                    duint value = Script::Stack::Pop();
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Stack/Push") {
                    std::string valueStr = queryParams["value"];
                    if (valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing value parameter");
                        continue;
                    }
                    
                    duint value = 0;
                    try {
                        if (valueStr.substr(0, 2) == "0x") {
                            value = std::stoull(valueStr.substr(2), nullptr, 16);
                        } else {
                            value = std::stoull(valueStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid value format");
                        continue;
                    }
                    
                    duint prevTop = Script::Stack::Push(value);
                    std::stringstream ss;
                    ss << "0x" << std::hex << prevTop;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Stack/Peek") {
                    std::string offsetStr = queryParams["offset"];
                    int offset = 0;
                    if (!offsetStr.empty()) {
                        try {
                            offset = std::stoi(offsetStr);
                        } catch (const std::exception& e) {
                            sendHttpResponse(clientSocket, 400, "text/plain", "Invalid offset format");
                            continue;
                        }
                    }
                    
                    duint value = Script::Stack::Peek(offset);
                    std::stringstream ss;
                    ss << "0x" << std::hex << value;
                    sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                }
                else if (path == "/Disasm/GetInstruction") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    
                    // Use the correct DISASM_INSTR structure
                    DISASM_INSTR instr;
                    DbgDisasmAt(addr, &instr);
                    
                    // Create JSON response with available instruction details
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"address\":\"0x" << std::hex << addr << "\",";
                    ss << "\"instruction\":\"" << instr.instruction << "\",";
                    ss << "\"size\":" << std::dec << instr.instr_size;
                    ss << "}";
                    
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Disasm/GetInstructionRange") {
                    std::string addrStr = queryParams["addr"];
                    std::string countStr = queryParams["count"];
                    
                    if (addrStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing address parameter");
                        continue;
                    }
                    
                    duint addr = 0;
                    int count = 1;
                    
                    try {
                        if (addrStr.substr(0, 2) == "0x") {
                            addr = std::stoull(addrStr.substr(2), nullptr, 16);
                        } else {
                            addr = std::stoull(addrStr, nullptr, 16);
                        }
                        
                        if (!countStr.empty()) {
                            count = std::stoi(countStr);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address or count format");
                        continue;
                    }
                    
                    if (count <= 0 || count > 100) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Count must be between 1 and 100");
                        continue;
                    }
                    
                    // Get multiple instructions
                    std::stringstream ss;
                    ss << "[";
                    
                    duint currentAddr = addr;
                    for (int i = 0; i < count; i++) {
                        DISASM_INSTR instr;
                        DbgDisasmAt(currentAddr, &instr);
                        
                        if (instr.instr_size > 0) {
                            if (i > 0) ss << ",";
                            
                            ss << "{";
                            ss << "\"address\":\"0x" << std::hex << currentAddr << "\",";
                            ss << "\"instruction\":\"" << instr.instruction << "\",";
                            ss << "\"size\":" << std::dec << instr.instr_size;
                            ss << "}";
                            
                            currentAddr += instr.instr_size;
                        } else {
                            break;
                        }
                    }
                    
                    ss << "]";
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                else if (path == "/Disasm/StepInWithDisasm") {
                    // Step in first
                    Script::Debug::StepIn();
                    
                    // Then get current instruction
                    duint rip = Script::Register::Get(REG_IP);
                    
                    DISASM_INSTR instr;
                    DbgDisasmAt(rip, &instr);
                    
                    // Create JSON response
                    std::stringstream ss;
                    ss << "{";
                    ss << "\"step_result\":\"Step in executed\",";
                    ss << "\"rip\":\"0x" << std::hex << rip << "\",";
                    ss << "\"instruction\":\"" << instr.instruction << "\",";
                    ss << "\"size\":" << std::dec << instr.instr_size;
                    ss << "}";
                    
                    sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                }
                // =============================================================================
                // FLAG API ENDPOINTS
                // =============================================================================
                else if (path == "/Flag/Get") {
                    std::string flagName = queryParams["flag"];
                    if (flagName.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing flag parameter");
                        continue;
                    }
                    
                    bool value = false;
                    if (flagName == "ZF" || flagName == "zf") value = Script::Flag::GetZF();
                    else if (flagName == "OF" || flagName == "of") value = Script::Flag::GetOF();
                    else if (flagName == "CF" || flagName == "cf") value = Script::Flag::GetCF();
                    else if (flagName == "PF" || flagName == "pf") value = Script::Flag::GetPF();
                    else if (flagName == "SF" || flagName == "sf") value = Script::Flag::GetSF();
                    else if (flagName == "TF" || flagName == "tf") value = Script::Flag::GetTF();
                    else if (flagName == "AF" || flagName == "af") value = Script::Flag::GetAF();
                    else if (flagName == "DF" || flagName == "df") value = Script::Flag::GetDF();
                    else if (flagName == "IF" || flagName == "if") value = Script::Flag::GetIF();
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown flag");
                        continue;
                    }
                    
                    sendHttpResponse(clientSocket, 200, "text/plain", value ? "true" : "false");
                }
                else if (path == "/Flag/Set") {
                    std::string flagName = queryParams["flag"];
                    std::string valueStr = queryParams["value"];
                    if (flagName.empty() || valueStr.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing flag or value parameter");
                        continue;
                    }
                    
                    bool value = (valueStr == "true" || valueStr == "1");
                    bool success = false;
                    
                    if (flagName == "ZF" || flagName == "zf") success = Script::Flag::SetZF(value);
                    else if (flagName == "OF" || flagName == "of") success = Script::Flag::SetOF(value);
                    else if (flagName == "CF" || flagName == "cf") success = Script::Flag::SetCF(value);
                    else if (flagName == "PF" || flagName == "pf") success = Script::Flag::SetPF(value);
                    else if (flagName == "SF" || flagName == "sf") success = Script::Flag::SetSF(value);
                    else if (flagName == "TF" || flagName == "tf") success = Script::Flag::SetTF(value);
                    else if (flagName == "AF" || flagName == "af") success = Script::Flag::SetAF(value);
                    else if (flagName == "DF" || flagName == "df") success = Script::Flag::SetDF(value);
                    else if (flagName == "IF" || flagName == "if") success = Script::Flag::SetIF(value);
                    else {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Unknown flag");
                        continue;
                    }
                    
                    sendHttpResponse(clientSocket, success ? 200 : 500, "text/plain", 
                        success ? "Flag set successfully" : "Failed to set flag");
                }
                
                // =============================================================================
                // PATTERN API ENDPOINTS
                // =============================================================================
                else if (path == "/Pattern/FindMem") {
                    std::string startStr = queryParams["start"];
                    std::string sizeStr = queryParams["size"];
                    std::string pattern = queryParams["pattern"];
                    std::string Pattern = urlDecode(pattern);
                    if (startStr.empty() || sizeStr.empty() || pattern.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing start, size, or pattern parameter");
                        continue;
                    }
                    
                    duint start = 0, size = 0;

                    Pattern.erase(std::remove_if(pattern.begin(), pattern.end(), 
                                  [](unsigned char c) { return std::isspace(c); }), 
                    Pattern.end());

                    try {
                        if (startStr.substr(0, 2) == "0x") {
                            start = std::stoull(startStr.substr(2), nullptr, 16);
                        } else {
                            start = std::stoull(startStr, nullptr, 16);
                        }
                        if (sizeStr.substr(0, 2) == "0x") {
                            size = std::stoull(sizeStr.substr(2), nullptr, 16);
                        } else {
                            size = std::stoull(sizeStr, nullptr, 16);
                        }
                    } catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid start or size format");
                        continue;
                    }
                    
                    duint result = Script::Pattern::FindMem(start, size, Pattern.c_str());
                    if (result != 0) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << result;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 404, "text/plain", "Pattern not found");
                    }
                }
                
                else if (path == "/Misc/ParseExpression") {
                    std::string expression = queryParams["expression"];
                    if (expression.empty() && !body.empty()) {
                        expression = body;
                    }
                    
                    if (expression.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing expression parameter");
                        continue;
                    }
                    
                    duint value = 0;
                    bool success = Script::Misc::ParseExpression(expression.c_str(), &value);
                    
                    if (success) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << value;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to parse expression");
                    }
                }
                else if (path == "/Misc/RemoteGetProcAddress") {
                    std::string module = queryParams["module"];
                    std::string api = queryParams["api"];
                    
                    if (module.empty() || api.empty()) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Missing module or api parameter");
                        continue;
                    }
                    
                    duint addr = Script::Misc::RemoteGetProcAddress(module.c_str(), api.c_str());
                    if (addr != 0) {
                        std::stringstream ss;
                        ss << "0x" << std::hex << addr;
                        sendHttpResponse(clientSocket, 200, "text/plain", ss.str());
                    } else {
                        sendHttpResponse(clientSocket, 404, "text/plain", "Function not found");
                    }
                }
                else if (path == "/MemoryBase") {
                    std::string addrStr = queryParams["addr"];
                    if (addrStr.empty() && !body.empty()) {
                        addrStr = body;
                    }
                    _plugin_logprintf("MemoryBase endpoint called with addr: %s\n", addrStr.c_str());
                    // Convert string address to duint
                    duint addr = 0;
                    try {
                        addr = std::stoull(addrStr, nullptr, 16); // Parse as hex
                    }
                    catch (const std::exception& e) {
                        sendHttpResponse(clientSocket, 400, "text/plain", "Invalid address format");
                        continue;
                    }
                    _plugin_logprintf("Converted address: " FMT_DUINT_HEX "\n", DUINT_CAST_PRINTF(addr));
                    
                    // Get the base address and size
                    duint size = 0;
                    duint baseAddr = DbgMemFindBaseAddr(addr, &size);
                    _plugin_logprintf("Base address found: " FMT_DUINT_HEX ", size: " FMT_DUINT_DEC "\n", DUINT_CAST_PRINTF(baseAddr), DUSIZE_CAST_PRINTF(size));
                    if (baseAddr == 0) {
                        sendHttpResponse(clientSocket, 404, "text/plain", "No module found for this address");
                    }
                    else {
                        // Format the response as JSON
                        std::stringstream ss;
                        ss << "{\"base_address\":\"0x" << std::hex << baseAddr << "\",\"size\":\"0x" << std::hex << size << "\"}";
                        sendHttpResponse(clientSocket, 200, "application/json", ss.str());
                    }
                }
                else if (path == "/GetModuleList") {
                    // Create a list to store the module information
                    ListInfo moduleList;
                    
                    // Get the list of modules
                    bool success = Script::Module::GetList(&moduleList);
                    
                    if (!success) {
                        sendHttpResponse(clientSocket, 500, "text/plain", "Failed to get module list");
                    }
                    else {
                        // Create a JSON array to hold the module information
                        std::stringstream jsonResponse;
                        jsonResponse << "[";
                        
                        // Iterate through each module in the list
                        size_t count = moduleList.count;
                        Script::Module::ModuleInfo* modules = (Script::Module::ModuleInfo*)moduleList.data;
                        
                        for (size_t i = 0; i < count; i++) {
                            if (i > 0) jsonResponse << ",";
                            
                            // Add module info as JSON object
                            jsonResponse << "{";
                            jsonResponse << "\"name\":\"" << modules[i].name << "\",";
                            jsonResponse << "\"base\":\"0x" << std::hex << modules[i].base << "\",";
                            jsonResponse << "\"size\":\"0x" << std::hex << modules[i].size << "\",";
                            jsonResponse << "\"entry\":\"0x" << std::hex << modules[i].entry << "\",";
                            jsonResponse << "\"sectionCount\":" << std::dec << modules[i].sectionCount << ",";
                            jsonResponse << "\"path\":\"" << modules[i].path << "\"";
                            jsonResponse << "}";
                        }
                        
                        jsonResponse << "]";
                        
                        // Free the list
                        BridgeFree(moduleList.data);
                        
                        // Send the response
                        sendHttpResponse(clientSocket, 200, "application/json", jsonResponse.str());
                    }
                }
                // Memory Access Functions (Legacy endpoints for compatibility)
                
            }
            catch (const std::exception& e) {
                // Exception in handling request
                sendHttpResponse(clientSocket, 500, "text/plain", std::string("Internal Server Error: ") + e.what());
            }
        }
        
        // Close the client socket
        closesocket(clientSocket);
    }

    // Clean up
    if (g_serverSocket != INVALID_SOCKET) {
        closesocket(g_serverSocket);
        g_serverSocket = INVALID_SOCKET;
    }

    WSACleanup();
    return 0;
}

// Function to read the HTTP request
std::string readHttpRequest(SOCKET clientSocket) {
    std::string request;
    char buffer[MAX_REQUEST_SIZE];
    int bytesReceived;
    
    // Set socket to blocking mode to receive full request
    u_long mode = 0;
    ioctlsocket(clientSocket, FIONBIO, &mode);

    // Avoid hanging the single HTTP thread forever on slow/half-open clients.
    DWORD timeoutMs = 1200;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));

    while (true) {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            break;
        }
        buffer[bytesReceived] = '\0';
        request.append(buffer, bytesReceived);
        // We only need headers + tiny query/body for MCP endpoints.
        if (request.find("\r\n\r\n") != std::string::npos || bytesReceived < (int)sizeof(buffer) - 1) {
            break;
        }
        if (request.size() >= MAX_REQUEST_SIZE) {
            break;
        }
    }
    
    return request;
}

// Function to parse an HTTP request
void parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body) {
    // Parse the request line
    size_t firstLineEnd = request.find("\r\n");
    if (firstLineEnd == std::string::npos) {
        return;
    }
    
    std::string requestLine = request.substr(0, firstLineEnd);
    
    // Extract method and URL
    size_t methodEnd = requestLine.find(' ');
    if (methodEnd == std::string::npos) {
        return;
    }
    
    method = requestLine.substr(0, methodEnd);
    
    size_t urlEnd = requestLine.find(' ', methodEnd + 1);
    if (urlEnd == std::string::npos) {
        return;
    }
    
    std::string url = requestLine.substr(methodEnd + 1, urlEnd - methodEnd - 1);
    
    // Split URL into path and query
    size_t queryStart = url.find('?');
    if (queryStart != std::string::npos) {
        path = url.substr(0, queryStart);
        query = url.substr(queryStart + 1);
    } else {
        path = url;
        query = "";
    }
    
    // Find the end of headers and start of body
    size_t headersEnd = request.find("\r\n\r\n");
    if (headersEnd == std::string::npos) {
        return;
    }
    
    // Extract body
    body = request.substr(headersEnd + 4);
}

// Function to send HTTP response
void sendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody) {
    // Prepare status line
    std::string statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 404: statusText = "Not Found"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown";
    }
    
    // Build the response
    std::stringstream response;
    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << responseBody.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << responseBody;
    
    // Send the response
    std::string responseStr = response.str();
    send(clientSocket, responseStr.c_str(), (int)responseStr.length(), 0);
}

// Parse query parameters from URL
std::unordered_map<std::string, std::string> parseQueryParams(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    
    size_t pos = 0;
    size_t nextPos;
    
    while (pos < query.length()) {
        nextPos = query.find('&', pos);
        if (nextPos == std::string::npos) {
            nextPos = query.length();
        }
        
        std::string pair = query.substr(pos, nextPos - pos);
        size_t equalPos = pair.find('=');
        
        if (equalPos != std::string::npos) {
            std::string key = pair.substr(0, equalPos);
            std::string value = pair.substr(equalPos + 1);
            params[key] = value;
        }
        
        pos = nextPos + 1;
    }
    
    return params;
}

// Command callback for toggling HTTP server
bool cbEnableHttpServer(int argc, char* argv[]) {
    if (g_httpServerRunning) {
        _plugin_logputs("Stopping HTTP server...");
        stopHttpServer();
        _plugin_logputs("HTTP server stopped");
    } else {
        _plugin_logputs("Starting HTTP server...");
        if (startHttpServer()) {
            _plugin_logprintf("HTTP server started on port %d\n", g_httpPort);
        } else {
            _plugin_logputs("Failed to start HTTP server");
        }
    }
    return true;
}

// Command callback for changing HTTP server port
bool cbSetHttpPort(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("Usage: httpport [port_number]");
        return false;
    }
    
    int port;
    try {
        port = std::stoi(argv[1]);
    }
    catch (const std::exception&) {
        _plugin_logputs("Invalid port number");
        return false;
    }
    
    if (port <= 0 || port > 65535) {
        _plugin_logputs("Port number must be between 1 and 65535");
        return false;
    }
    
    g_httpPort = port;
    
    if (g_httpServerRunning) {
        _plugin_logputs("Restarting HTTP server with new port...");
        stopHttpServer();
        if (startHttpServer()) {
            _plugin_logprintf("HTTP server restarted on port %d\n", g_httpPort);
        } else {
            _plugin_logputs("Failed to restart HTTP server");
        }
    } else {
        _plugin_logprintf("HTTP port set to %d\n", g_httpPort);
    }
    
    return true;
}

// Register plugin commands
void registerCommands() {
    _plugin_registercommand(g_pluginHandle, "httpserver", cbEnableHttpServer, 
                           "Toggle HTTP server on/off");
    _plugin_registercommand(g_pluginHandle, "httpport", cbSetHttpPort, 
                           "Set HTTP server port");
}
