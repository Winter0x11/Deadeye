# Deadeye

**Deadeye** is an advanced Windows process memory triage scanner, detection-engineering toolkit, and behavioral diff timeline built in modern C++17 and native Win32.

Designed for reverse engineers, threat hunters, and detection engineers, Deadeye bridges the gap between memory analysis and rule deployment: generate auto-wildcarded YARA rules from hex selections, instantly validate them against clean running processes to verify zero false positives, diff entire process address spaces before and after running malware, and monitor unpacking transitions in real time without pausing or attaching a debugger.

---

## Key Detection & Analysis Capabilities

### 1. Hex Selection to YARA Rule with Live False-Positive Testing
Select any sequence of bytes in the hex viewer (or press `Ctrl+Y`) to generate an optimized YARA signature with architecture-aware wildcarding:
- **Intelligent Relocation Wildcarding**: Automatically replaces volatile bytes that change across compilations:
  - Relative CALL / JMP displacements (`E8 ?? ?? ?? ??`, `E9 ?? ?? ?? ??`)
  - Conditional near jumps (`0F 80..8F ?? ?? ?? ??`)
  - x64 RIP-relative displacements (ModR/M `[rip + disp32]` with disp32 masked)
  - 64-bit immediate constants and address relocations (`48 B8..BF ??..??`)
- **Built-in False-Positive Validator**: Click **Run False-Positive Test** directly inside Deadeye. It scans the executable memory of every active running process on the host machine using SIMD-accelerated pattern matching. If a signature matches benign software (e.g. `svchost.exe`, `explorer.exe`), it reports the exact PID, process name, and match address so you can refine your rule before deployment.

### 2. Process-Wide Memory Diff & Offline Analysis Sessions
Deadeye captures the full virtual address space (region map, memory states, page protections, Shannon entropy, and FNV-1a content hashes) before and after running a suspicious sample:
- **Comprehensive State Diffs**: Highlights regions that:
  - `[+NEW   ]`: Newly allocated / committed memory (e.g. injected payloads, shellcode buffers).
  - `[!PROT  ]`: Protection transitions (e.g. `RW` flipped to `RX` or `RWX`).
  - `[~MODIF ]`: Existing regions whose content was mutated or decrypted in place.
  - `[-FREED ]`: Deallocated or unmapped regions.
- **Offline Session Files**: Save snapshot sessions to standard JSON (`.json`) files so team members can inspect and diff process states offline or across triage sandboxes.

### 3. Behavioral Memory Timeline & Unpack Detection
On an optional 1-second heartbeat timer, Deadeye tracks per-region transitions, entropy shifts, and content mutations:
- **Unpack Detection (`BEHAVIOR_UNPACK`, +50 pts)**: Automatically detects when a non-executable region (`RW` / `RO`) flips to executable (`RX` / `RWX`) and its content changes or entropy drops (payload unpacked into memory).
- **Sleep Obfuscation Detection (`SLEEP_OBFUSCATION`, +65 pts)**: Identifies regions whose protection or entropy oscillates across ticks (e.g., encrypted at rest during sleep cycles, decrypted while active).
- **"New Strings After Unpack" (`Ctrl+U`)**: Automatically extracts ASCII and UTF-16LE strings revealed following protection flips. Categorizes indicators into badges: `[URL]`, `[IP]`, `[PATH]`, `[CMD]`, `[REG]`, and `[STR]` for immediate extraction of C2 configurations.
- > [!IMPORTANT]
  > **Polling Notice**: Periodic heartbeat polling operates on a 1-second interval. Very fast, sub-second unpack-and-reprotect transitions may execute between polling ticks. Deadeye is designed to provide lightweight, non-invasive observation without the overhead or evasion triggers of kernel drivers or active debugger hooks.

---

## Quick Install (One-Line Command)

Run this command in **PowerShell** (no admin rights or external runtimes required):

```powershell
irm https://raw.githubusercontent.com/Winter0x11/Deadeye/main/install.ps1 | iex
```

> [!NOTE]
> If running from **Command Prompt (CMD)** or the **Windows Run Dialog (`Win + R`)**, prepend `powershell`:
> ```cmd
> powershell -ep bypass -c "irm https://raw.githubusercontent.com/Winter0x11/Deadeye/main/install.ps1 | iex"
> ```

**What this one-liner does automatically:**
1. Resolves the latest release binary from GitHub.
2. Downloads and extracts `deadeye.exe` to `%LOCALAPPDATA%\Deadeye`.
3. Adds Deadeye to your user `PATH` (so you can run `deadeye` from any command prompt).
4. Creates a Windows Start Menu shortcut.
5. Immediately launches Deadeye.

> [!TIP]
> **Zero External Dependencies**: Deadeye is compiled with fully static C++ runtimes (`-static -static-libgcc -static-libstdc++`). It runs out-of-the-box on clean Windows 10 & 11 installations with zero Visual C++ Redistributable or MinGW DLL requirements.

---

## Defensive Triage Heuristics & Additive Scoring

Deadeye inspects target processes in a background worker thread and computes an **additive threat severity score** for every committed memory region:

| Detection Rule | Additive Weight | Description |
|:---|:---:|:---|
| `SLEEP_OBFUSCATION` | **+65** | Region protection/entropy oscillates across heartbeat ticks (payload encrypted at rest, decrypted while active). |
| `INJECTED_PE` | **+50** | Valid DOS (`MZ`) and NT (`PE\0\0`) headers detected within `MEM_PRIVATE` pages (reflective DLL loading, process hollowing, unhooking stubs). |
| `BEHAVIOR_UNPACK` | **+50** | Region flipped from non-executable to executable with byte mutations or entropy drop. |
| `UNLINKED_MODULE` | **+45** | Committed `MEM_IMAGE` allocation missing from the 64-bit PEB loader list (`InLoadOrderModuleList`), indicating DKOM evasion. |
| `PRIVATE_RWX` | **+40** | Region marked `MEM_PRIVATE` with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY` protection. |
| `WRITE_THEN_FLIP` | **+35** | `AllocationProtect` was writable (`PAGE_READWRITE`), current `Protect` is executable (`PAGE_EXECUTE_READ`). Staged payload execution. |
| `UNBACKED_EXEC` | **+25** | Executable memory not backed by a verified disk image (`MEM_MAPPED` or `MEM_PRIVATE` with execution rights). |

### Severity Bands
- **CRITICAL (`CRIT`)**: Score &ge; **80**
- **HIGH (`HIGH`)**: Score &ge; **50**
- **MEDIUM (`MED`)**: Score &ge; **25**
- **LOW (`LOW`)**: Score &ge; **10**
- **CLEAN (`CLEAN`)**: Score = **0**

---

## Features & UI Overview

- **Pure Windows Subsystem Application**: Built strictly as a native GUI binary (`/SUBSYSTEM:WINDOWS`, `-mwindows`). No console flashing on launch, zero command-line baggage.
- **Three Core View Modes**:
  - **Triage Findings (`Ctrl+1`)**: Displays all evaluated regions sorted strictly by threat severity descending (`[SEV SCORE] FLAGS ADDRESS SIZE TYPE PROT`).
  - **Memory Map (`Ctrl+2`)**: Linear address walk showing all committed pages with hit badges, snapshot counters, and detection flags.
  - **Process Diff View (`Ctrl+3`)**: Comprehensive before-and-after difference list highlighting `[+NEW]`, `[!PROT]`, `[~MODIF]`, and `[-FREED]` regions.
- **Menu Bar & Global Accelerators**:
  - **File**: Attach to Self (`Ctrl+Alt+S`), Run Defensive Triage (`Ctrl+T`), Export Triage JSON (`Ctrl+S`), Theme (`Light` / `Dark`), Exit (`Alt+F4`).
  - **Edit**: Copy Region Address (`Ctrl+C`), Copy Hex Dump (`Ctrl+Shift+C`), Find Hex Pattern (`Ctrl+F`), Find Next Hit (`F3`), **Generate YARA Rule (`Ctrl+Y`)**.
  - **View**: Triage Findings (`Ctrl+1`), Memory Map (`Ctrl+2`), Process Diff View (`Ctrl+3`), Hide Clean Regions, Hits Only Filter, Refresh (`F5`).
  - **Diff**: Capture Baseline (`Ctrl+B`), Compare with Current (`Ctrl+D`), Save Diff Session, Load Diff Session, **View Newly Revealed Strings (`Ctrl+U`)**.
  - **Timeline**: Take Snapshot (`Ctrl+N`), Clear All Snapshots, Live Memory Heartbeat, Previous/Next 64 KB Page (`PgUp` / `PgDn`).
  - **Help**: Defensive Heuristics Reference Guide, About Deadeye.
- **Modern Fluent UI Engine**:
  - Smooth rounded buttons with interactive hover/click feedback.
  - Full High-DPI and PerMonitorV2 awareness with embedded Common-Controls v6 manifest.
  - Dual Dark and Light color palettes for both high-contrast lab work and presentation environments.
- **Zero Third-Party Dependencies**: Native C++17 and standard Win32 API (`user32`, `gdi32`, `advapi32`, `comctl32`, `comdlg32`).

---

## Building from Source

### Repository
```powershell
git clone https://github.com/Winter0x11/Deadeye.git
cd Deadeye
```

### Build with MinGW-w64 (GCC)
```powershell
# Create build directory
if (-not (Test-Path build)) { New-Item -ItemType Directory -Path build }

# Compile Windows resources & Common-Controls v6 / DPI manifest
windres -I src -i src/deadeye.rc -o build/deadeye_res.o

# Compile fully static standalone binary (zero external DLL requirements)
g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 -static -static-libgcc -static-libstdc++ src/main.cpp build/deadeye_res.o -o build/deadeye.exe -mwindows -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32
```

---

## Pre-Built Releases & CI/CD

Pre-compiled standalone 64-bit binaries are published on GitHub:
- **Release Bundle**: `Deadeye-v1.0.1-windows-x64.zip` containing `deadeye.exe` and documentation.
- **Automated CI/CD**: Pushing any version tag (e.g. `git tag -a v1.0.1 -m "Release v1.0.1"` followed by `git push origin main --tags`) automatically triggers GitHub Actions to compile, test, package, and publish release assets via [`.github/workflows/release.yml`](.github/workflows/release.yml).
