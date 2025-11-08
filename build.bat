@echo off
REM ============================================================================
REM x32dbg MCP Plugin - Simple Build Script
REM ============================================================================
REM This script automatically detects Visual Studio and builds the .dp32 plugin
REM Just double-click this file to compile!
REM ============================================================================

echo.
echo ========================================
echo   x32dbg MCP Plugin Builder
echo ========================================
echo.

REM Check if cmake is available
where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake not found in PATH!
    echo.
    echo Please install CMake from: https://cmake.org/download/
    echo Or install it via Visual Studio Installer
    echo.
    pause
    exit /b 1
)

echo [*] CMake found: OK
echo.

REM Try to find Visual Studio automatically
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] Visual Studio not found!
    echo.
    echo Please install Visual Studio 2019 or later with C++ support
    echo Download from: https://visualstudio.microsoft.com/downloads/
    echo.
    pause
    exit /b 1
)

echo [*] Visual Studio found: OK
echo.

REM Clean old build
if exist "build32" (
    echo [*] Cleaning old build directory...
    rmdir /s /q build32
)

REM Create build directory
echo [*] Creating build directory...
mkdir build32

REM Configure CMake for 32-bit build
echo.
echo [*] Configuring CMake for x32 (Win32) build...
echo.
cmake -S . -B build32 -A Win32 -DBUILD_BOTH_ARCHES=OFF
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] CMake configuration failed!
    pause
    exit /b 1
)

REM Build the plugin
echo.
echo [*] Building plugin (Release mode)...
echo.
cmake --build build32 --config Release
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

REM Copy to convenient location
echo.
echo [*] Copying plugin to root /build/ directory...
if not exist "build" mkdir build
copy /Y "build32\Release\MCPx64dbg.dp32" "build\MCPx64dbg.dp32" >nul

echo.
echo ========================================
echo   BUILD SUCCESSFUL!
echo ========================================
echo.
echo Plugin location: %CD%\build\MCPx64dbg.dp32
echo.
echo To install:
echo 1. Copy MCPx64dbg.dp32 to: x32dbg\plugins\
echo 2. Restart x32dbg
echo 3. Check logs (ALT+L) to verify plugin loaded
echo.
echo ========================================
echo.
pause
