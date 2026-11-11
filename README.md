# Deadeye 

**Deadeye** is a unified, lightweight, high-performance Windows process memory pattern scanner, interactive hex viewer, and real-time memory diff timeline built in modern C++ and native Win32.

Designed for defensive reverse engineering, malware analysis, and detection engineering, Deadeye lets you inspect memory layouts, search for signatures with wildcards, flag suspicious `PRIVATE RWX` regions, and monitor live memory changes in real-time without pausing or attaching a debugger to the target.

---



---

## Features

- **Dual-Mode Single Binary**: Automatically launches in interactive GUI mode when double-clicked, or runs as a headless CLI scanner when passed arguments in a terminal.
- **Real-Time Memory Heartbeat**: Periodic (1s) live diff monitoring that flags modified rows and shows exact previous byte values as memory changes in running targets.
- **Visual Memory Diff Timeline**: Capture point-in-time snapshots of any region (`[+ Snap]`) and compare `Live vs Snapshot` or `Snapshot vs Snapshot` with byte-aligned `old:` sub-rows.
- **YARA-Like Pattern Scanner**: Fast sliding-window pattern scanner supporting hex bytes and `??` wildcards (e.g., `4D 5A ?? 00 03`).
- **Suspicious Code Indicator (`[!]`)**: Automatically flags `MEM_PRIVATE` pages with `PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_WRITECOPY` protection (common indicators of injected shellcode or unpacked payloads).
- **Interactive Two-Pane Hex Viewer**:
  - **Left Pane**: Memory Map displaying all committed pages (`Address | Size | Type | Protection | Snapshots | Hits`).
  - **Right Pane**: Fast, responsive 64 KB paged hex+ASCII viewer with hit markers (`>>>`), diff markers (`CHG`), and combo markers (`!>>`).
- **Zero Heavy Dependencies**: Pure C++ and Win32 API (`user32`, `gdi32`, `kernel32`). No heavy frameworks or runtimes needed.

---

## Building

### Requirements
- **OS**: Windows 10 or 11 (x64)
- **Compiler**: MinGW-w64 (`g++`) or MSVC (`cl`)

### Build with MinGW-w64 (GCC)
```powershell
# Create build directory
if (-not (Test-Path build)) { New-Item -ItemType Directory -Path build }

# Compile unified Deadeye (CLI + GUI)
g++ -std=c++17 -m64 -Wall -Wextra -O2 src/main.cpp -o build/deadeye.exe -lgdi32 -luser32

# Compile the test target
g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 src/test_target.cpp -o build/test_target.exe
```

### Build with MSVC (Visual Studio x64 Native Tools)
```bat
if not exist build mkdir build
cl /std:c++17 /EHsc /W4 /O2 src/main.cpp /Fe:build/deadeye.exe /link /SUBSYSTEM:CONSOLE user32.lib gdi32.lib
cl /std:c++17 /EHsc /W4 /O2 src/test_target.cpp /Fe:build/test_target.exe
```

---

## Quick Start

### 1. Interactive GUI Mode
Double-click `build/deadeye.exe` or run:
```powershell
.\build\deadeye.exe
```
- By default, it inspects `self` and displays its memory map immediately.
- Enter any process PID and click **Load** to inspect another application.
- Click **`+ Snap`** to capture a baseline snapshot.
- Check **`Heartbeat (1s)`** to watch memory changes pulse in real time with aligned `old:` byte annotations.
- Optionally enter a hex pattern (e.g. `4D 5A 90 00` or `DE AD ?? EF`) and click **Search** to highlight matches.

### 2. Headless CLI Scanner Mode
When passed command-line arguments, Deadeye runs directly in your terminal:
```powershell
# Scan another process
.\build\deadeye.exe <pid> "4D 5A ?? 00 03"

# Scan the scanner's own process
.\build\deadeye.exe self "4D 5A 90 00"
```

#### Exit Codes
| Code | Meaning |
|:---:|---|
| `0` | Hits found |
| `1` | No hits found |
| `2` | Bad CLI arguments or invalid pattern |
| `3` | `OpenProcess` failure (access denied / invalid PID) |

---

## Testing with `test_target`

1. Start the included test target in a terminal:
   ```powershell
   .\build\test_target.exe
   ```
   It prints its PID, addresses of both heap and `VirtualAlloc` RWX buffers, and waits for commands.

2. In another terminal, run the CLI scanner:
   ```powershell
   .\build\deadeye.exe <PID> "DE AD ?? EF 13 37 ?? FE"
   ```
   Output:
   ```text
   [Deadeye] Scanning PID 2380 for 8-byte pattern...
       HIT addr=0x2311C588AB0 region_base=0x2311C580000 region_size=0x34000 type=PRIVATE protect=PAGE_READWRITE
   [!] HIT addr=0x2311C7E0000 region_base=0x2311C7E0000 region_size=0x1000 type=PRIVATE protect=PAGE_EXECUTE_READWRITE

   --- Deadeye Summary ---
   Regions scanned: 123
   Bytes scanned:   15618048
   Total hits:      2
   ```

3. Or load the PID in `deadeye.exe` GUI, select the `RWX!` region, check **Heartbeat (1s)**, and press `m` in `test_target.exe` to see live memory mutation diffs!
