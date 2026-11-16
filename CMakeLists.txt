cmake_minimum_required(VERSION 3.16)

project(Deadeye
    VERSION 1.0.7
    DESCRIPTION "Defensive Windows Process Memory Triage Scanner & Inspection Tool"
    LANGUAGES CXX RC
)

# C++ Standard Requirements
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output binaries to bin/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Compiler warnings and options
if(MSVC)
    add_compile_options(
        /W4
        /EHsc
        /utf-8
    )
    add_definitions(
        -D_CRT_SECURE_NO_WARNINGS
        -DNOMINMAX
        -DWIN32_LEAN_AND_MEAN
    )
else()
    add_compile_options(
        -Wall
        -Wextra
        -pedantic
        -Wno-unused-parameter
    )
    if(MINGW)
        # Produce standalone binaries without external runtime DLL dependencies
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
endif()

# Global include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/resources
)

# -----------------------------------------------------------------------------
# Main Application Target: deadeye (Win32 GUI Subsystem)
# -----------------------------------------------------------------------------
set(DEADEYE_SOURCES
    src/main.cpp
    src/core/behavior.cpp
    src/core/json_export.cpp
    src/core/live_source.cpp
    src/core/memsource.cpp
    src/core/pattern.cpp
    src/core/pe_source.cpp
    src/core/snapshot.cpp
    src/core/timeline.cpp
    src/core/triage.cpp
    src/core/util.cpp
    src/gui/app.cpp
    src/gui/attach_dialog.cpp
    src/gui/controls.cpp
    src/gui/hexview.cpp
    src/gui/menu.cpp
    src/gui/pe_options_dialog.cpp
    src/gui/search_dialog.cpp
    src/gui/strings_dialog.cpp
    src/gui/views.cpp
    src/resources/deadeye.rc
)

add_executable(deadeye WIN32 ${DEADEYE_SOURCES})

# Under MSVC, disable default manifest generation because deadeye.rc embeds deadeye.manifest
if(MSVC)
    target_link_options(deadeye PRIVATE "/MANIFEST:NO")
endif()

target_link_libraries(deadeye PRIVATE
    advapi32
    comctl32
    comdlg32
    gdi32
    user32
    dwmapi
)

# -----------------------------------------------------------------------------
# Test Target (Synthetic memory triage target)
# -----------------------------------------------------------------------------
add_executable(test_target tests/test_target.cpp)
target_link_libraries(test_target PRIVATE
    advapi32
    user32
)

# -----------------------------------------------------------------------------
# Unit Test Runners & CTest
# -----------------------------------------------------------------------------
enable_testing()

# 1. Timeline Unit Tests
add_executable(test_timeline
    tests/test_timeline.cpp
    src/core/timeline.cpp
    src/core/util.cpp
)
target_link_libraries(test_timeline PRIVATE advapi32 user32)
add_test(NAME test_timeline COMMAND test_timeline)

# 2. Memory Diffing Unit Tests
add_executable(test_diff
    tests/test_diff.cpp
    src/core/snapshot.cpp
    src/core/util.cpp
    src/core/memsource.cpp
    src/core/pattern.cpp
)
target_link_libraries(test_diff PRIVATE advapi32 user32)
add_test(NAME test_diff COMMAND test_diff)

# 3. Memory Pattern Search Unit Tests
add_executable(test_pattern
    tests/test_pattern.cpp
    src/core/pattern.cpp
    src/core/util.cpp
    src/core/memsource.cpp
    src/core/snapshot.cpp
)
target_link_libraries(test_pattern PRIVATE advapi32 user32)
add_test(NAME test_pattern COMMAND test_pattern)
