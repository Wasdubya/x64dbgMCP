cmake_minimum_required(VERSION 3.15)
project(MCPx64dbg)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optionally build both 32-bit and 64-bit plugins via a superbuild
option(BUILD_BOTH_ARCHES "Build both 32-bit and 64-bit plugins from this CMake project" ON)

# If requested and supported by MSVC, drive two sub-builds that produce dp32 and dp64
if(BUILD_BOTH_ARCHES AND MSVC)
    include(ExternalProject)
    message(STATUS "Configuring superbuild to produce both dp32 and dp64")

    # 32-bit sub-build
    ExternalProject_Add(plugin32
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        BINARY_DIR ${CMAKE_BINARY_DIR}/build32
        CMAKE_ARGS -G "${CMAKE_GENERATOR}" -DCMAKE_GENERATOR_PLATFORM=Win32 -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:>,${CMAKE_BUILD_TYPE},Release> -DBUILD_BOTH_ARCHES=OFF
        INSTALL_COMMAND ""
    )

    # 64-bit sub-build
    ExternalProject_Add(plugin64
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        BINARY_DIR ${CMAKE_BINARY_DIR}/build64
        CMAKE_ARGS -G "${CMAKE_GENERATOR}" -DCMAKE_GENERATOR_PLATFORM=x64 -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:>,${CMAKE_BUILD_TYPE},Release> -DBUILD_BOTH_ARCHES=OFF
        INSTALL_COMMAND ""
    )

    add_custom_target(all_plugins DEPENDS plugin32 plugin64)

    message(STATUS "Use 'cmake --build . --target all_plugins' to build both dp32 and dp64")

    # Stop processing the single-arch build logic in superbuild mode
    return()
endif()

# Detect target architecture from the generator/toolchain (authoritative) for single-arch builds
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_EXT ".dp64")
    set(ARCH_BITS 64)
    set(ARCH_SUFFIX "_x64")
else()
    set(PLUGIN_EXT ".dp32")
    set(ARCH_BITS 32)
    set(ARCH_SUFFIX "_x86")
endif()

# Set paths to x64dbg SDK
set(X64DBG_SDK_PATH "${CMAKE_SOURCE_DIR}/deps/x64dbg_sdk")

# Include directories
include_directories(
    ${X64DBG_SDK_PATH}
    ${X64DBG_SDK_PATH}/pluginsdk
    ${X64DBG_SDK_PATH}/pluginsdk/nlohmann  # Add nlohmann include path
    ${CMAKE_SOURCE_DIR}/include
)

# Add source files
file(GLOB SOURCES "src/*.cpp")

# Create shared library (plugin)
add_library(${PROJECT_NAME} SHARED ${SOURCES})

# Set output name
set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${PROJECT_NAME}"
    SUFFIX "${PLUGIN_EXT}"
)

# Define macro for architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN64)
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN32)
endif()

# Add path to library files
link_directories(${X64DBG_SDK_PATH}/pluginsdk)

# Check if libraries exist and adjust architecture suffix if needed
if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/TitanEngine/TitanEngine${ARCH_SUFFIX}.lib")
    message(STATUS "TitanEngine${ARCH_SUFFIX}.lib not found, trying TitanEngine.lib")
    set(TITAN_ENGINE_LIB "${X64DBG_SDK_PATH}/pluginsdk/TitanEngine/TitanEngine.lib")
else()
    set(TITAN_ENGINE_LIB "${X64DBG_SDK_PATH}/pluginsdk/TitanEngine/TitanEngine${ARCH_SUFFIX}.lib")
endif()

if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/DeviceNameResolver/DeviceNameResolver${ARCH_SUFFIX}.lib")
    message(STATUS "DeviceNameResolver${ARCH_SUFFIX}.lib not found, trying DeviceNameResolver.lib")
    set(DEVICE_RESOLVER_LIB "${X64DBG_SDK_PATH}/pluginsdk/DeviceNameResolver/DeviceNameResolver.lib")
else()
    set(DEVICE_RESOLVER_LIB "${X64DBG_SDK_PATH}/pluginsdk/DeviceNameResolver/DeviceNameResolver${ARCH_SUFFIX}.lib")
endif()

if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/jansson/jansson${ARCH_SUFFIX}.lib")
    message(STATUS "jansson${ARCH_SUFFIX}.lib not found, trying jansson.lib")
    set(JANSSON_LIB "${X64DBG_SDK_PATH}/pluginsdk/jansson/jansson.lib")
else()
    set(JANSSON_LIB "${X64DBG_SDK_PATH}/pluginsdk/jansson/jansson${ARCH_SUFFIX}.lib")
endif()

if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/lz4/lz4${ARCH_SUFFIX}.lib")
    message(STATUS "lz4${ARCH_SUFFIX}.lib not found, trying lz4.lib")
    set(LZ4_LIB "${X64DBG_SDK_PATH}/pluginsdk/lz4/lz4.lib")
else()
    set(LZ4_LIB "${X64DBG_SDK_PATH}/pluginsdk/lz4/lz4${ARCH_SUFFIX}.lib")
endif()

if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/XEDParse/XEDParse${ARCH_SUFFIX}.lib")
    message(STATUS "XEDParse${ARCH_SUFFIX}.lib not found, trying XEDParse.lib")
    set(XEDPARSE_LIB "${X64DBG_SDK_PATH}/pluginsdk/XEDParse/XEDParse.lib")
else()
    set(XEDPARSE_LIB "${X64DBG_SDK_PATH}/pluginsdk/XEDParse/XEDParse${ARCH_SUFFIX}.lib")
endif()

# Link x64dbg libraries and dependencies
target_link_libraries(${PROJECT_NAME}
        ws2_32                         # For winsock2
        winhttp                        # WinHTTP library
        ${TITAN_ENGINE_LIB}
        ${DEVICE_RESOLVER_LIB}
        ${JANSSON_LIB}
        ${LZ4_LIB}
        ${XEDPARSE_LIB}
)

if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_libraries(${PROJECT_NAME}
            ${X64DBG_SDK_PATH}/pluginsdk/x32dbg.lib
            ${X64DBG_SDK_PATH}/pluginsdk/x32bridge.lib
    )
elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(${PROJECT_NAME}
            ${X64DBG_SDK_PATH}/pluginsdk/x64dbg.lib
            ${X64DBG_SDK_PATH}/pluginsdk/x64bridge.lib
    )
endif()
# Just show information about where the plugin is built
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "=== Plugin build complete ==="
    COMMAND ${CMAKE_COMMAND} -E echo "Plugin built at: ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${PROJECT_NAME}${PLUGIN_EXT}"
    COMMAND ${CMAKE_COMMAND} -E echo "Install manually to: $ENV{ProgramFiles}/x64dbg/release/x${ARCH_BITS}/plugins/${PROJECT_NAME}${PLUGIN_EXT}"
    COMMAND ${CMAKE_COMMAND} -E echo "================================="
)