# Deadeye

**Deadeye** is an advanced Windows process memory triage scanner, detection-engineering toolkit, and behavioral memory tracker built in modern C++17 and native Win32.

Designed for reverse engineers, threat hunters, and detection engineers, Deadeye bridges the gap between memory triage and production detection engineering: inspect live processes or offline PE layouts as mapped in memory, track behavioral memory transitions over time (sleep-masking, XOR key rotation, decrypt-on-wake), extract C2 strings revealed after decryption, generate auto-wildcarded YARA rules from hex selections, and validate them against running processes with instant false-positive tests—strictly read-only, with zero third-party dependencies.

---

## Key Detection & Analysis Capabilities

### 1. Behavior Tracker & Time-Series Memory Analysis (Live Sources, `Ctrl+3`)
On a configurable interval (250ms to 5s, default 1000ms, with a non-blocking 50ms time budget per tick), Deadeye's background worker thread samples a watch set of suspicious regions into a 120-sample ring buffer, evaluating dynamic payload lifecycle behaviors:
- **Sleep-Mask Suspect (`SLEEP_MASK_SUSPECT`, +40 pts)**: Detects memory regions whose protection or entropy oscillates across sleep cycles (e.g. `PAGE_EXECUTE_READ` active $\leftrightarrow$ `PAGE_NOACCESS` or `PAGE_READWRITE` dormant $\ge 3$ full cycles). Calculates period estimate, min/max entropy, and protection sequence.
- **Key-Rotation Suspect (`KEY_ROTATION_SUSPECT`, +35 pts)**: Identifies encrypted regions whose content mutates while remaining high-entropy ($H \ge 6.8$). Automatically analyzes XOR delta images ($D[i] = A[i] \oplus B[i]$) for repeating periods $P \in [1, 64]$ and outputs candidate delta key bytes.
- **Decrypt-on-Wake (`DECRYPT_ON_WAKE`, +35 pts)**: Catches payloads decrypting in place: flags regions where Shannon entropy drops sharply (e.g. $7.9 \to 3.2$) and newly exposed strings appear compared to baseline.
- **Watch Set Management**: Automatically tracks regions with triage score $\ge 25$ or high entropy; user can pin/unpin any region (`Ctrl+P`) or toggle "Watch all private executable" regions.

> [!IMPORTANT]
> **Polling Limitations & Sampling Honesty**: Deadeye operates strictly in user mode via standard Win32 `ReadProcessMemory` and `VirtualQueryEx`. It **never** injects DLLs, installs page guard hooks, or suspends threads. Periodic polling (default 1000ms) may miss transient sub-second memory transitions executed and reverted in <100ms. Detections combine time-series evidence with static indicators to maintain maximum signal-to-noise ratio.

### 2. Shannon Entropy Profiling & Visualization
- **Page-Wise Entropy**: Calculates Shannon entropy (bits/byte) per 4 KB page across memory regions (pages < 512 bytes reported as `n/a`). Large regions are evenly sampled (up to 64 pages) to prevent UI stutter.
- **Compact ASCII Profile**: Visualizes page-level entropy density directly in the memory map and details line using compact glyphs (`._-=#`).
- **Static Entropy Rules**:
  - `HIGH_ENTROPY_EXEC` (+35 pts): Executable region or page with entropy $\ge 7.20$ (packed/encrypted code).
  - `HIGH_ENTROPY_PRIVATE` (+20 pts): `MEM_PRIVATE` non-executable buffer $\ge 16\text{ KB}$ with entropy $\ge 7.40$ (encrypted payload blob or stager). *Note: Does not flag `MEM_IMAGE` data sections by entropy alone (compressed resources are normal).*

### 3. String Extraction & "New Since Baseline" Tracking (`Ctrl+4`)
- **ASCII & UTF-16LE Extraction**: Scans regions for printable strings (configurable min length, default 6) with safety caps (20,000 total strings, 5,000 per region, 256 chars per line).
- **String Baseline Diffing (`Ctrl+B`)**: Captures a hash set of strings per region. Switching on the "New since baseline" filter (`F6`) reveals URLs, IPs, domains, and configuration blocks decrypted by malware after execution.
- **Classification Hints**: Automated heuristic tagging for `[URL] (hint)`, `[IP] (hint)`, `[DOMAIN] (hint)`, `[PATH] (hint)`, and `[REG] (hint)`.
- **Direct Navigation**: Clicking any extracted string automatically jumps the hex view directly to its virtual address.

### 4. Hex Selection to YARA Rule with Live False-Positive Testing (`Ctrl+Y`)
Select any byte sequence in the hex viewer to generate an optimized YARA signature with compiler-aware wildcarding:
- **Intelligent Relocation Wildcarding**: Automatically masks volatile addresses and offsets:
  - Relative CALL / JMP displacements (`E8 ?? ?? ?? ??`, `E9 ?? ?? ?? ??`)
  - Conditional near jumps (`0F 80..8F ?? ?? ?? ??`)
  - x64 RIP-relative displacements (ModR/M `[rip + disp32]`)
  - 64-bit immediate constants and address relocations (`48 B8..BF ??..??`)
- **Built-in False-Positive Validator**: Scans the executable memory of every active running process on the host using SIMD-accelerated pattern matching. Reports matching PIDs and process names so you can refine rules before deployment.

### 5. Process Attachment Dialog (Debugger-Style Process / Window Picker, `Ctrl+A`)
Attach to any running process or desktop application just like a native debugger:
- **Intuitive Windowed Priority**: Processes with visible top-level windows (Notepad, Chrome, Spotify, test targets) are automatically elevated to the top of the list with their active window titles displayed.
- **Rich Multi-Column Process List**:
  - **Process Name**: Executable binary name (e.g. `notepad.exe`, `explorer.exe`).
  - **PID**: Formatted with both decimal and hex identifiers (e.g. `1234 (0x04D2)`).
  - **Window Title**: Visible application title bar text for rapid recognition.
  - **Arch**: Architecture detection (`x64` vs `x86`) via `IsWow64Process`.
  - **Executable Path**: Full filesystem image path.
- **Interactive Multi-Field Search**: Real-time filtering matching case-insensitive process names, window titles, decimal PIDs, or hex PIDs (e.g. `0x4D2` or `4D2`).
- **One-Click Window Filter**: Checkbox toggle `[x] Processes with visible windows only` to instantly narrow the view to active desktop software.
- **Interactive Column Sorting**: Click any column header to sort ascending or descending by Process Name, PID, Window Title, Architecture, or Path.
- **Keyboard-Driven Workflow**: Press `Ctrl+A` anywhere in the app to open, type to search, hit Down arrow to enter the list, and press Enter or double-click to attach immediately. Press `F5` to refresh active processes on demand.
- **Strictly Read-Only**: Enumerates processes and metadata using `PROCESS_QUERY_LIMITED_INFORMATION`. Never writes memory, suspends threads, or injects modules.

### 6. MemorySource Abstraction & Offline Mapped PE Inspection (`Ctrl+O`)
- Open raw PE files (`.exe`, `.dll`, `.sys`) laid out in virtual memory exactly as the Windows loader maps them:
  - Headers mapped at base, sections aligned to `SectionAlignment`, zero-filled padding, unmapped gaps marked unreadable.
  - Section characteristics translated to synthetic protections (`PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`).
  - Base relocation engine: applies `IMAGE_REL_BASED_HIGHLOW` and `DIR64` when mapped base differs from `ImageBase`.
  - PE Summary panel: machine, subsystem, ImageBase, Entry Point RVA, section count, overlay size, and flags if EP is outside executable sections.

### 7. Process-Wide Memory Diff & Timeline Diffing (`Ctrl+5`)
- Capture full virtual address space snapshots before and after running samples:
  - `[+NEW   ]`: Newly allocated/committed memory (injected payloads, shellcode buffers).
  - `[!PROT  ]`: Protection transitions (`RW` flipped to `RX` or `RWX`).
  - `[~MODIF ]`: Existing regions whose content was mutated or decrypted in place.
  - `[-FREED ]`: Deallocated or unmapped regions.
- Save and load diff sessions to JSON for offline comparison across sandbox runs.

---

## Defensive Triage Heuristics & Additive Scoring

Deadeye inspects memory sources in a background worker thread and computes an **additive threat severity score** for every region:

| Detection Rule | Additive Weight | Category | Description |
|:---|:---:|:---:|:---|
| `SLEEP_OBFUSCATION` | **+65** | Heartbeat Timeline | Region protection/entropy oscillates across heartbeat ticks. |
| `INJECTED_PE` | **+50** | Live Triage | Valid DOS (`MZ`) and NT (`PE\0\0`) headers detected within `MEM_PRIVATE` pages. |
| `BEHAVIOR_UNPACK` | **+50** | Heartbeat Timeline | Region flipped from non-executable to executable with byte mutations or entropy drop. |
| `UNLINKED_MODULE` | **+45** | Live Triage | Committed `MEM_IMAGE` allocation missing from the PEB `InLoadOrderModuleList`. |
| `PRIVATE_RWX` | **+40** | Live Triage | Region marked `MEM_PRIVATE` with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY`. |
| `SLEEP_MASK_SUSPECT` | **+40** | Behavior Tracker | Time-series oscillation between low/high entropy or exec/non-exec across $\ge 3$ cycles. |
| `KEY_ROTATION_SUSPECT` | **+35** | Behavior Tracker | High-entropy payload with mutating content hash and repeating XOR delta key period $P \in [1, 64]$. |
| `DECRYPT_ON_WAKE` | **+35** | Behavior Tracker | Sharp entropy drop ($>1.2$) with newly revealed strings appearing vs baseline. |
| `HIGH_ENTROPY_EXEC` | **+35** | Entropy Triage | Executable region/page with Shannon entropy $\ge 7.20$ (packed/encrypted code). |
| `WRITE_THEN_FLIP` | **+35** | Live Triage | `AllocationProtect` was writable (`PAGE_READWRITE`), current `Protect` is executable (`PAGE_EXECUTE_READ`). |
| `HIGH_ENTROPY_PRIVATE` | **+20** | Entropy Triage | `MEM_PRIVATE` non-executable buffer $\ge 16\text{ KB}$ with Shannon entropy $\ge 7.40$. |
| `UNBACKED_EXEC` | **+25** | Live Triage | Executable memory not backed by a verified disk image. |
| `STATIC_WX_SECTION` | **+50** | Offline Mapped PE | Section marked with both Writable and Executable rights (W+X). |
| `STATIC_EP_OUTSIDE_EXEC`| **+45** | Offline Mapped PE | Entry point RVA is located outside all executable sections. |
| `STATIC_EXEC_HIGH_ENTROPY`| **+40** | Offline Mapped PE | Executable section with Shannon entropy $\ge 7.20$. |
| `STATIC_NONTRIVIAL_OVERLAY`| **+25** | Offline Mapped PE | Non-trivial overlay data (> 512 bytes) appended past raw section data. |

### Severity Bands
- **CRITICAL (`CRIT`)**: Score &ge; **80**
- **HIGH (`HIGH`)**: Score &ge; **50**
- **MEDIUM (`MED`)**: Score &ge; **25**
- **LOW (`LOW`)**: Score &ge; **10**
- **CLEAN (`CLEAN`)**: Score = **0**

---

## Strict Read-Only Guarantee

Deadeye is built exclusively for defensive analysis, triage, and detection engineering:
- **No Memory Writes**: Target process memory is never modified.
- **No DLL Injection**: No modules or hooks are loaded into target processes.
- **No Thread Suspension**: Targets continue running undisturbed; Deadeye never suspends or freezes target threads.
- **Zero Offensive Capabilities**: No exploitation, shellcode injection, or evasion features.

---

## UI Views & Navigation Shortcuts

| Shortcut | View / Action | Description |
|:---|:---|:---|
| `Ctrl+A` | **Attach to Process** | Opens debugger-style process & window picker with instant search and priority window sorting. |
| `Ctrl+1` | **Triage Findings View** | Lists all evaluated regions sorted strictly by threat severity descending. |
| `Ctrl+2` | **Memory Map View** | Linear address walk showing all committed pages with entropy and hit badges. |
| `Ctrl+3` | **Behavior Tracker View** | Monitored regions showing samples, cycles, changed %, and detection flags. |
| `Ctrl+4` | **Strings View** | Extracted strings with encoding, length, classification tag, and jump-to-hex. |
| `Ctrl+5` | **Process Diff View** | State diff view highlighting `[+NEW]`, `[!PROT]`, `[~MODIF]`, and `[-FREED]` regions. |
| `Ctrl+P` | **Pin / Unpin Region** | Adds or removes selected region from the active behavior tracking watch set. |
| `Ctrl+B` | **Set String Baseline** | Records string content hash baseline for decrypt-on-wake detection. |
| `F6` | **Toggle New Strings** | Filters Strings View to show only strings that appeared after baseline. |
| `F7` | **Extract Strings** | Extracts ASCII and UTF-16LE strings from the selected memory region. |
| `Ctrl+Y` | **Generate YARA Rule** | Opens YARA rule generator with auto-wildcarding and false-positive tester. |
| `Ctrl+S` | **Export Triage JSON** | Exports full JSON report including entropy profiles, findings, and behavior array. |
| `Ctrl+O` | **Open Memory Source** | Select a live process or pick a PE file (`.exe`/`.dll`/`.sys`) to inspect as mapped memory. |
| `F5` | **Refresh Memory Walk** | Reloads target process virtual memory allocations. |

---

## Verification & Test Target (`tests/test_target.cpp`)

A standalone simulation binary `build/test_target.exe` is provided to test and verify every Deadeye detection rule under controlled conditions.

### Available Test Modes

| Mode | Key | Behavior | Expected Deadeye Detection |
|:---:|:---:|:---|:---|
| **1** | `1` | **Dynamic Unpack Transition**: Decrypts payload into memory, embeds C2 URLs/IPs/paths, flips `PAGE_READWRITE` $\to$ `PAGE_EXECUTE_READ`. | `BEHAVIOR_UNPACK` (+50), `WRITE_THEN_FLIP` (+35); strings revealed in `Ctrl+4`. |
| **2** | `2` | **Sleep Obfuscation Cycle**: Alternates between encrypted at rest (`PAGE_READWRITE`) and decrypted active (`PAGE_EXECUTE_READ`). | `SLEEP_OBFUSCATION` (+65) in timeline. |
| **3** | `3` | **Dynamic Allocation / Deallocation**: Allocates or frees a 64 KB RWX buffer. | Process Diff shows `[+NEW]` or `[-FREED]`. |
| **4** | `4` | **Live Mutating Beacon**: Updates sequence numbers and randomizes buffer bytes. | Process Diff shows `[~MODIF]`. |
| **5** | `5` | **High Entropy Executable Buffer**: Allocates a 64 KB `PAGE_EXECUTE_READ` buffer with Shannon entropy $\approx 7.95$. | `HIGH_ENTROPY_EXEC` (+35), ASCII profile `#####...`. |
| **6** | `6` | **Sleep-Mask with Rotating XOR Key**: Payload cycles through `PAGE_NOACCESS` and `PAGE_EXECUTE_READ`, rotating an 8-byte XOR key. | `SLEEP_MASK_SUSPECT` (+40), `KEY_ROTATION_SUSPECT` (+35) with candidate XOR delta key period 8. |
| **7** | `7` | **Decrypt-On-Wake**: Encrypted buffer ($H \approx 7.90$) decrypts to cleartext C2 strings ($H \approx 3.20$). | `DECRYPT_ON_WAKE` (+35); newly decrypted strings highlighted in `Ctrl+4`. |

### False-Positive Testing Guide
To verify that Deadeye's behavioral rules and entropy heuristics do not fire falsely on clean software:
1. Launch a major web browser (Google Chrome, Microsoft Edge, or Mozilla Firefox) and open multiple tabs.
2. Launch a .NET application (e.g. PowerShell or a Visual Studio / C# app with active JIT memory).
3. Attach Deadeye to the browser process and the .NET process with the Behavior Tracker active for 60 seconds.
4. **Verification**: Confirm that benign JIT code regions and normal stack allocations do not trigger `SLEEP_MASK_SUSPECT` or `KEY_ROTATION_SUSPECT`.

---

## Building from Source

Deadeye features a modular C++17 architecture and compiles cleanly with **zero warnings** on both MinGW-w64 GCC (`-Wall -Wextra -pedantic`) and Microsoft Visual C++ (`/W4`).

### Automated Multi-Toolchain Build (`build.ps1`)
Use the automated PowerShell build script to compile both or individual toolchains:
```powershell
# Build both MinGW and MSVC release binaries + test targets
.\build.ps1

# Or target a specific toolchain
.\build.ps1 -Toolchain mingw
.\build.ps1 -Toolchain msvc
```

### Manual Build with MinGW-w64 (GCC)
```powershell
# Create build directory
if (-not (Test-Path build)) { New-Item -ItemType Directory -Path build }

# Compile resources & manifest
windres -I src/resources -i src/resources/deadeye.rc -O coff -o build/deadeye_res.o

# Compile fully static standalone binary across modular translation units
$srcs = Get-ChildItem -Path src -Filter *.cpp -Recurse | Select-Object -ExpandProperty FullName
g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 -static -static-libgcc -static-libstdc++ -Isrc $srcs build/deadeye_res.o -o build/deadeye.exe -mwindows -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32

# Compile test target
g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 tests/test_target.cpp -o build/test_target.exe
```

### Manual Build with Microsoft Visual C++ (MSVC)
```cmd
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
rc /nologo /i src\resources /fo build\deadeye_msvc_res.res src\resources\deadeye.rc
cl /std:c++17 /EHsc /W4 /O2 /Isrc /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /utf-8 src\main.cpp src\core\*.cpp src\gui\*.cpp build\deadeye_msvc_res.res /Fe:build\deadeye_msvc.exe /link /SUBSYSTEM:WINDOWS advapi32.lib comctl32.lib comdlg32.lib user32.lib gdi32.lib
cl /std:c++17 /EHsc /W4 /O2 /D_CRT_SECURE_NO_WARNINGS tests\test_target.cpp /Fe:build\test_target_msvc.exe
```

---

## Pre-Built Releases

Standalone 64-bit releases:
- **Release Bundle**: `Deadeye-v1.0.3-windows-x64.zip` containing `deadeye.exe`, `test_target.exe`, and documentation.
