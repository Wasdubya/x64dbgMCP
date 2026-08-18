cmake_minimum_required(VERSION 3.15)
project(MCPx64dbg)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_BOTH_ARCHES "Build both 32-bit and 64-bit plugins from this CMake project" ON)
option(X64DBG_DOWNLOAD_SDK "Download x64dbg-pluginsdk.zip when debugger import libs are missing or stub-sized" OFF)

set(X64DBG_SDK_PINNED_URL
    "https://github.com/x64dbg/x64dbg/releases/download/2025.08.19/x64dbg-pluginsdk.zip")

if(BUILD_BOTH_ARCHES AND MSVC)
    include(ExternalProject)
    message(STATUS "Configuring superbuild to produce both dp32 and dp64")

    ExternalProject_Add(plugin32
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        BINARY_DIR ${CMAKE_BINARY_DIR}/build32
        CMAKE_ARGS -G "${CMAKE_GENERATOR}" -DCMAKE_GENERATOR_PLATFORM=Win32
            -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:>,${CMAKE_BUILD_TYPE},Release>
            -DBUILD_BOTH_ARCHES=OFF
            -DX64DBG_DOWNLOAD_SDK=${X64DBG_DOWNLOAD_SDK}
        INSTALL_COMMAND ""
        BUILD_ALWAYS TRUE
    )

    ExternalProject_Add(plugin64
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        BINARY_DIR ${CMAKE_BINARY_DIR}/build64
        CMAKE_ARGS -G "${CMAKE_GENERATOR}" -DCMAKE_GENERATOR_PLATFORM=x64
            -DCMAKE_BUILD_TYPE=$<IF:$<CONFIG:>,${CMAKE_BUILD_TYPE},Release>
            -DBUILD_BOTH_ARCHES=OFF
            -DX64DBG_DOWNLOAD_SDK=${X64DBG_DOWNLOAD_SDK}
        INSTALL_COMMAND ""
        BUILD_ALWAYS TRUE
    )

    add_custom_target(all_plugins DEPENDS plugin32 plugin64)

    message(STATUS "Use 'cmake --build . --target all_plugins' to build both dp32 and dp64")

    return()
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_EXT ".dp64")
    set(ARCH_BITS 64)
    set(ARCH_SUFFIX "_x64")
    set(X64DBG_DBG_IMPORT_LIB "x64dbg.lib")
else()
    set(PLUGIN_EXT ".dp32")
    set(ARCH_BITS 32)
    set(ARCH_SUFFIX "_x86")
    set(X64DBG_DBG_IMPORT_LIB "x32dbg.lib")
endif()

set(X64DBG_DEPS_DIR "${CMAKE_SOURCE_DIR}/deps")
set(_x64dbg_psdk_zip "${CMAKE_BINARY_DIR}/x64dbg-pluginsdk.zip")

# --- Ensure full Plugin SDK (headers + import libs), not runtime stub .lib files (~2 KB). ---
if(NOT EXISTS "${X64DBG_DEPS_DIR}/bridgemain.h")
    if(X64DBG_DOWNLOAD_SDK)
        message(STATUS "Downloading x64dbg Plugin SDK (headers)...")
        file(DOWNLOAD "${X64DBG_SDK_PINNED_URL}" "${_x64dbg_psdk_zip}" SHOW_PROGRESS STATUS _dl)
        if(NOT _dl EQUAL 0)
            message(FATAL_ERROR "Plugin SDK download failed (status: ${_dl})")
        endif()
        file(MAKE_DIRECTORY "${X64DBG_DEPS_DIR}")
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf "${_x64dbg_psdk_zip}"
            WORKING_DIRECTORY "${X64DBG_DEPS_DIR}" RESULT_VARIABLE _ex)
        if(NOT _ex EQUAL 0)
            message(FATAL_ERROR "Plugin SDK extract failed (exit ${_ex})")
        endif()
    endif()
    if(NOT EXISTS "${X64DBG_DEPS_DIR}/bridgemain.h")
        message(FATAL_ERROR
            "Plugin SDK missing: ${X64DBG_DEPS_DIR}/bridgemain.h\n"
            "  Extract x64dbg-pluginsdk.zip into deps/, or reconfigure with -DX64DBG_DOWNLOAD_SDK=ON")
    endif()
endif()

set(_dbg_lib "${X64DBG_DEPS_DIR}/${X64DBG_DBG_IMPORT_LIB}")
set(_need_sdk_fetch FALSE)
if(NOT EXISTS "${_dbg_lib}")
    set(_need_sdk_fetch TRUE)
else()
    file(SIZE "${_dbg_lib}" _dbg_lib_sz)
    # Official imports are ~90–120 KB each; runtime / stub copies are only a few KB.
    if(_dbg_lib_sz LESS 20000)
        set(_need_sdk_fetch TRUE)
    endif()
endif()

if(_need_sdk_fetch)
    if(X64DBG_DOWNLOAD_SDK)
        message(STATUS "Downloading x64dbg Plugin SDK (full ${_dbg_lib})...")
        file(DOWNLOAD "${X64DBG_SDK_PINNED_URL}" "${_x64dbg_psdk_zip}" SHOW_PROGRESS STATUS _dl2)
        if(NOT _dl2 EQUAL 0)
            message(FATAL_ERROR "Plugin SDK download failed (status: ${_dl2})")
        endif()
        file(MAKE_DIRECTORY "${X64DBG_DEPS_DIR}")
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf "${_x64dbg_psdk_zip}"
            WORKING_DIRECTORY "${X64DBG_DEPS_DIR}" RESULT_VARIABLE _ex2)
        if(NOT _ex2 EQUAL 0)
            message(FATAL_ERROR "Plugin SDK extract failed (exit ${_ex2})")
        endif()
    endif()
    if(NOT EXISTS "${_dbg_lib}")
        message(FATAL_ERROR
            "Missing ${_dbg_lib}\n"
            "  Use the full x64dbg-pluginsdk.zip from a release (not runtime DLL folders).\n"
            "  Or: cmake -S . -B build -DX64DBG_DOWNLOAD_SDK=ON")
    endif()
    file(SIZE "${_dbg_lib}" _dbg_lib_sz2)
    if(_dbg_lib_sz2 LESS 20000)
        message(FATAL_ERROR
            "${_dbg_lib} is only ${_dbg_lib_sz2} bytes (stub). Need the real import library from\n"
            "  x64dbg-pluginsdk.zip (~90–120 KB). Replace deps/x32dbg.lib and x64dbg.lib, or use:\n"
            "  cmake -S . -B build -DX64DBG_DOWNLOAD_SDK=ON")
    endif()
endif()

include_directories(
    ${X64DBG_DEPS_DIR}
    ${CMAKE_SOURCE_DIR}/include
)
if(EXISTS "${X64DBG_DEPS_DIR}/nlohmann")
    include_directories(${X64DBG_DEPS_DIR}/nlohmann)
endif()

file(GLOB SOURCES "src/*.cpp")
add_library(${PROJECT_NAME} SHARED ${SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${PROJECT_NAME}"
    SUFFIX "${PLUGIN_EXT}"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN64)
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN32)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    file(GLOB_RECURSE X64DBG_SDK_IMPORT_LIBS CONFIGURE_DEPENDS
        "${X64DBG_DEPS_DIR}/*_x64.lib"
        "${X64DBG_DEPS_DIR}/x64*.lib"
    )
else()
    file(GLOB_RECURSE X64DBG_SDK_IMPORT_LIBS CONFIGURE_DEPENDS
        "${X64DBG_DEPS_DIR}/*_x86.lib"
        "${X64DBG_DEPS_DIR}/x32*.lib"
    )
endif()
if(NOT X64DBG_SDK_IMPORT_LIBS)
    message(FATAL_ERROR
        "No SDK .lib files matched for this architecture under ${X64DBG_DEPS_DIR}\n"
        "  Re-extract x64dbg-pluginsdk.zip or use -DX64DBG_DOWNLOAD_SDK=ON")
endif()

target_link_directories(${PROJECT_NAME} PRIVATE ${X64DBG_DEPS_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 winhttp ${X64DBG_SDK_IMPORT_LIBS})

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "=== Plugin build complete ==="
    COMMAND ${CMAKE_COMMAND} -E echo "Plugin built at: ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${PROJECT_NAME}${PLUGIN_EXT}"
    COMMAND ${CMAKE_COMMAND} -E echo "Install manually to: $ENV{ProgramFiles}/x64dbg/release/x${ARCH_BITS}/plugins/${PROJECT_NAME}${PLUGIN_EXT}"
    COMMAND ${CMAKE_COMMAND} -E echo "================================="
)
