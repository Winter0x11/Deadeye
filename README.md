# Deadeye

**Deadeye** is a high-performance Windows process memory triage scanner, interactive hex viewer, and real-time diff timeline built in modern C++17 and native Win32.

Designed for defensive reverse engineering, malware analysis, and detection engineering, Deadeye brings color-coded visual triage directly to your desktop. It automatically flags suspicious memory conditions (such as private RWX regions, write-then-flip executable memory, reflective DLL/PE headers in private heap/stack pages, and unlinked modules), monitors live memory mutations in real time without pausing or attaching a debugger, and exports valid JSON reports for automation.

---

## Defensive Triage Heuristics & Additive Scoring

Deadeye inspects target processes in a background worker thread and computes an **additive threat severity score** for every committed memory region based on weighted heuristics:

| Detection Rule | Additive Weight | Description |
|:---|:---:|:---|
| `INJECTED_PE` | **+50** | Valid DOS (`MZ`) and NT (`PE\0\0`) headers detected within `MEM_PRIVATE` pages (indicative of reflective DLL loading, process hollowing, or unhooking stubs). |
| `UNLINKED_MODULE` | **+45** | Committed `MEM_IMAGE` allocation whose base address is missing from the 64-bit PEB loader list (`InLoadOrderModuleList`), indicating module unlinking/DKOM evasion. *(Reported as unsupported on 32-bit WOW64 targets instead of guessing).* |
| `PRIVATE_RWX` | **+40** | Region marked `MEM_PRIVATE` with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY` protection. |
| `WRITE_THEN_FLIP` | **+35** | `AllocationProtect` was non-executable writable (`PAGE_READWRITE` / `PAGE_WRITECOPY`), but current `Protect` is executable (`PAGE_EXECUTE` / `PAGE_EXECUTE_READ`). Common malware staging pattern. |
| `UNBACKED_EXEC` | **+25** | Executable memory not backed by a verified disk image (`MEM_MAPPED` or `MEM_PRIVATE` with execution rights). |

### Severity Bands
- **CRITICAL (`CRIT`)**: Score &ge; **80**
- **HIGH (`HIGH`)**: Score &ge; **50**
- **MEDIUM (`MED`)**: Score &ge; **25**
- **LOW (`LOW`)**: Score &ge; **10**
- **CLEAN (`CLEAN`)**: Score = **0**

---

## Features

- **Pure Windows Subsystem Application**: Built strictly as a native GUI binary (`/SUBSYSTEM:WINDOWS`, `-mwindows`). No console flashing on launch, no command-line baggage.
- **Modern Fluent UI Engine**:
  - **Sleek Rounded Pushbuttons**: Custom double-buffered button engine with smooth rounded borders (6px radius) and seamless parent corner blending.
  - **Interactive Hover & Click States**: Real-time cursor state changes (`IDC_HAND`), mouse tracking (`TrackMouseEvent` / `WM_MOUSELEAVE`), tactile 1px pressed offsets, and high-visibility keyboard focus rings.
  - **Visual CTA Hierarchy**: Cobalt Azure Primary button for **Triage**, Emerald Green Accent for **Export JSON**, and clean modern Card buttons for search and navigation.
  - **High-DPI & Common Controls v6**: Embedded application manifest with Microsoft Common-Controls 6.0.0.0 dependency and PerMonitorV2 DPI awareness for crystal-clear typography on high-resolution displays.
- **UI-Independent Core Engine**: All memory walks, pattern scanning, and defensive triage evaluations take a process handle and return plain structs (`TriageReport`, `TriageFinding`, `RegionInfo`), keeping core logic fully decoupled from presentation.
- **Two Flexible View Modes**:
  - **Triage Findings**: Displays all evaluated regions sorted strictly by threat severity descending (`[SEV SCORE] FLAGS ADDRESS SIZE TYPE PROT`).
  - **Memory Map**: Full linear address walk showing all committed pages with hit badges, snapshot counters, and detection flags.
- **Threat Filters**:
  - **Min Severity**: Filter by `All (0+)`, `Low (10+)`, `Med (25+)`, `High (50+)`, or `Crit (80+)`.
  - **Hide Clean**: Instantly collapse benign regions to focus exclusively on anomalies.
  - **Hits Only**: Show only regions containing pattern match hits.
- **Finding Details Line**: Displays the exact point-scored breakdown and reasons for the selected finding (e.g. `Details [CRIT 110]: Injected PE/Reflective DLL (+50) | Write-then-flip (+35) | Unbacked Exec (+25)`).
- **Export Valid JSON**: Export full findings to a file chosen via standard Windows Save Dialog (`GetSaveFileNameA`), including `base`, `size`, `alloc_base`, `type`, `protect`, `alloc_protect`, `flags`, `severity_score`, `severity_label`, and `reasons`.
- **Real-Time Memory Heartbeat (1s)**: Periodic live diff monitoring that highlights modified bytes with aligned `old:` sub-rows without scrolling resets or flicker.
- **Visual Memory Diff Timeline**: Capture point-in-time snapshots (`[+ Snap]`) and compare `Live vs Snapshot` or `Snapshot vs Snapshot`.
- **SIMD-Accelerated Pattern Search**: Fast sliding-window pattern scanner using `memchr` anchor acceleration, wildcard support (`??`), all-wildcard rejection, and per-region hit caps (10,000).
- **Robust Page-Wise Read Fallback**: Never silently abandons regions on partial read errors; automatically falls back to 4 KB page-by-page reads to scan past guard pages and decommitted blocks.
- **Automatic `SeDebugPrivilege` Acquisition**: Attempts token privilege adjustment on startup so elevated processes can inspect system services and protected targets.
- **Zero Third-Party Dependencies**: Pure C++17 and standard Win32 API (`user32`, `gdi32`, `advapi32`, `comctl32`, `comdlg32`).

---

## Building

### Repository
```powershell
git clone https://github.com/Winter0x11/Deadeye.git
cd Deadeye
```

### Requirements
- **OS**: Windows 10 or 11 (x64)
- **Compiler**: MinGW-w64 (`g++` & `windres`) or MSVC (`cl.exe`)

### Build with MinGW-w64 (GCC)
```powershell
# Create build directory
if (-not (Test-Path build)) { New-Item -ItemType Directory -Path build }

# Compile Windows resources & Common-Controls v6 / DPI manifest
windres src/deadeye.rc -O coff -o build/deadeye_res.o

# Compile Deadeye GUI (pure Windows subsystem, zero warnings)
g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 src/main.cpp build/deadeye_res.o -o build/deadeye.exe -mwindows -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32

# Compile the test target
g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 src/test_target.cpp -o build/test_target.exe
```

### Build with MSVC (Visual Studio Developer Command Prompt)
```bat
if not exist build mkdir build

REM Compile Deadeye GUI (/W4, pure Windows subsystem, zero warnings)
cl /std:c++17 /EHsc /W4 /O2 src/main.cpp /Fe:build/deadeye.exe /Fo:build/ /link /SUBSYSTEM:WINDOWS

REM Compile the test target
cl /std:c++17 /EHsc /W4 /O2 src/test_target.cpp /Fe:build/test_target.exe /Fo:build/
```

---

## Manual Test Checklist

Use the included `test_target.exe` tool to verify each defensive triage condition inside Deadeye:

| Test Mode | Test Command | Simulated Condition | Expected Triage Flags | Expected Severity | Visual Highlight Color |
|:---:|:---|:---|:---|:---:|:---|
| **1** | `.\build\test_target.exe 1` | `VirtualAlloc(PAGE_EXECUTE_READWRITE)` | `PRIVATE_RWX`, `UNBACKED_EXEC` | **65 (HIGH)** | Salmon / Red alert (`#FFC0C0`) |
| **2** | `.\build\test_target.exe 2` | `VirtualAlloc(PAGE_READWRITE)` &rarr; `VirtualProtect(PAGE_EXECUTE_READ)` | `WRITE_THEN_FLIP`, `UNBACKED_EXEC` | **60 (HIGH)** | Peach / Orange (`#FFE0B9`) |
| **3** | `.\build\test_target.exe 3` | Private memory containing `MZ` & `PE\0\0` headers | `INJECTED_PE`, `WRITE_THEN_FLIP`, `UNBACKED_EXEC` | **110 (CRIT)** | Alert Red (`#FFB4B4`) |
| **4** | `.\build\test_target.exe 4` | `LoadLibraryA("version.dll")` & unlinked from PEB `InLoadOrderModuleList` | `UNLINKED_MODULE` | **45 (MED)** | Packed Purple (`#E8D0FF`) |
| **All** | `.\build\test_target.exe all` | Simulates all 4 conditions simultaneously | Multiple rows matching above | **45 to 110** | Multi-colored threat palette |

### Verification Steps:
1. Launch `test_target.exe`:
   ```powershell
   .\build\test_target.exe all
   ```
   Note the printed target PID (e.g. `9244`).
2. Launch `deadeye.exe`:
   ```powershell
   .\build\deadeye.exe
   ```
3. In Deadeye:
   - Enter the target PID in the `PID:` box and click **Triage**.
   - Verify that the left pane populates with the findings list sorted by threat severity.
   - Verify that the injected PE finding is at the top with `[CRIT 110]` highlighted in red/purple.
   - Click each row and verify that the hex viewer jumps directly to the corresponding base address.
   - Verify that the **Details** line at the bottom displays the exact additive scoring explanation for each finding.
   - Select the `RWX` row, check **Heartbeat (1s)**, and press `m` in `test_target.exe` to observe live memory diffs annotated in real time.
   - Click **Export JSON**, save to a file, and verify the structured JSON output.
