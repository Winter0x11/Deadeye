# Deadeye

**Windows process memory inspection and analysis.**

## Quick install

Open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/Winter0x11/Deadeye/main/install.ps1 | iex
```

The installer downloads the latest Windows x64 release, installs Deadeye for the current user, adds it to your user PATH, creates a Start Menu shortcut, and launches the application. Administrator access is not normally required.

Want to inspect the installer first? [View install.ps1](https://github.com/Winter0x11/Deadeye/blob/main/install.ps1).

Prefer a manual download? [Get the latest release](https://github.com/Winter0x11/Deadeye/releases/latest).

---

Deadeye is a native C++17 tool for inspecting the virtual memory of running Windows processes and examining PE files as they would appear when mapped into memory. It brings process selection, memory maps, hex inspection, string extraction, memory comparison, and optional behavioral analysis into one desktop application.

It is built for developers, reverse engineers, security researchers, and anyone who needs to understand what a Windows process has in its memory.

---

## What it does

| Area | Capabilities |
|---|---|
| **Process inspection** | Find and attach to running processes; inspect process metadata, architecture, executable path, and window title. |
| **Memory map** | Walk committed virtual memory regions and inspect their addresses, sizes, types, protections, and entropy information. |
| **Memory analysis** | Inspect memory contents, navigate to addresses, and examine bytes in context. |
| **String extraction** | Extract ASCII and UTF-16LE strings, classify common indicators, and navigate from a string to its location in memory. |
| **Memory comparison** | Compare process memory states over time and identify new, modified, freed, or protection-changed regions. Save and load diff sessions. |
| **Behavior tracking** | Sample selected regions over time to observe changes in content, entropy, and memory protection. |
| **Offline PE inspection** | Open EXE, DLL, and SYS files and inspect a virtual layout that models how Windows maps their headers and sections. |

## Inspection workflow

### Processes and memory maps

The process picker supports searching and sorting by process name, PID, window title, architecture, and executable path. Processes with visible windows are prioritized to make desktop applications easier to find.

The memory map provides a view of committed address ranges, including region type, protection, and entropy information. It can be refreshed while inspecting a live process.

### Hex and string inspection

Deadeye includes a hex view for examining memory contents. String extraction supports ASCII and UTF-16LE, with configurable minimum string length and extraction limits. Common URLs, IP addresses, domains, paths, and registry references receive classification hints.

Selecting an extracted string takes you to its location in the memory view.

### Memory diffing

Capture a process memory state, perform an action in the target application, then capture another state to inspect what changed.

The diff view identifies:

- `[+NEW]` — newly allocated or committed regions.
- `[!PROT]` — memory protection changes.
- `[~MODIF]` — existing regions whose contents changed.
- `[-FREED]` — regions that were deallocated or unmapped.

Diff sessions can be saved to and loaded from JSON for later examination.

### Behavioral analysis

The behavior tracker periodically samples watched memory regions. It can help identify patterns such as protection changes, changing high-entropy buffers, and data that becomes more readable over time.

Sampling is performed by a background worker. The interval is configurable from 250 ms to 5 seconds. Because this is polling-based analysis, short-lived changes may occur between samples and go undetected.

### Offline PE inspection

Open an EXE, DLL, or SYS file to inspect its mapped virtual layout. Deadeye maps headers and sections using their virtual alignment, represents gaps as unreadable, and applies supported base relocations when the mapped base differs from the preferred image base.

The PE summary includes machine type, subsystem, image base, entry point RVA, section count, overlay size, and relevant section or entry-point flags.

---

## Analysis signals

Deadeye can attach heuristic findings and an additive score to memory regions. These findings are intended to help prioritize inspection—not to declare that a process is malicious.

Examples of signals include:

| Finding | What it indicates |
|---|---|
| Private executable memory | Executable pages backed by private memory. |
| Unbacked executable memory | Executable memory without a verified backing image. |
| Write-then-execute transition | A region whose allocation protection was writable and whose current protection is executable. |
| High entropy | Data with a high degree of byte-value variation. This can occur in packed or encrypted data, but also in legitimate compressed or application data. |
| Unlinked image mapping | A committed image mapping not found in the enumerated PEB loader list. Enumeration limitations can affect this result. |
| Sleep-mask or key-rotation suspect | Time-series patterns that may be consistent with memory obfuscation. |
| Decrypt-on-wake suspect | A sharp entropy change accompanied by newly visible strings. |
| PE section or entry-point anomalies | Static properties such as writable-and-executable sections or an entry point outside executable sections. |

Scores are additive heuristic weights, not calibrated probabilities. A high score is not proof of malicious activity, and a low score does not establish that a process is safe. Always inspect the underlying evidence and consider the context of the target application.

---

## Read-only operation

Deadeye is designed to inspect target processes without modifying their memory.

- Uses Windows process and virtual-memory query APIs, including `ReadProcessMemory` and `VirtualQueryEx`.
- Does not inject DLLs into target processes.
- Does not suspend or freeze target threads.
- Does not write to target process memory.

Access to some processes or memory regions may be restricted by Windows permissions, process protection, or architecture differences. An unreadable region should be treated as unavailable data, not as evidence of malicious behavior.

---

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+A` | Open the process attachment dialog. |
| `Ctrl+1` | Triage findings. |
| `Ctrl+2` | Memory map. |
| `Ctrl+3` | Behavior tracker. |
| `Ctrl+4` | Strings view. |
| `Ctrl+5` | Process memory diff. |
| `Ctrl+P` | Pin or unpin a region for behavior tracking. |
| `Ctrl+B` | Set a string baseline. |
| `F6` | Toggle the new-since-baseline string filter. |
| `F7` | Extract strings from the selected region. |
| `Ctrl+S` | Export triage results as JSON. |
| `Ctrl+O` | Open a memory source or PE file. |
| `F5` | Refresh the memory map. |

---

## Test target

The repository includes a standalone test program at `tests/test_target.cpp`. It creates controlled memory conditions for exercising Deadeye's inspection and analysis features.

| Mode | Test scenario |
|---|---|
| `1` | Dynamic unpack transition and protection change. |
| `2` | Sleep-obfuscation-style protection cycle. |
| `3` | Dynamic allocation and deallocation. |
| `4` | Mutating memory buffer. |
| `5` | High-entropy executable buffer. |
| `6` | Sleep-mask-style cycle with changing XOR data. |
| `7` | Decrypt-on-wake-style data transition. |

Use the test target only in a controlled environment. These scenarios are synthetic test cases; their detection results do not establish how Deadeye will behave against every real application or sample.

For a basic benign-process sanity check, inspect ordinary applications such as a text editor, browser, or .NET process. Compare observations across different applications and workloads rather than treating any single heuristic result as a definitive false positive or true positive.

---

## Building from source

Deadeye uses C++17 and the native Win32 API.

### Automated build

Run the PowerShell build script from the repository root:

```powershell
# Build the supported toolchains and test targets
.\build.ps1

# Build with one toolchain
.\build.ps1 -Toolchain mingw
.\build.ps1 -Toolchain msvc
```

### MinGW-w64

```powershell
if (-not (Test-Path build)) {
    New-Item -ItemType Directory -Path build
}

windres -I src/resources -i src/resources/deadeye.rc -O coff -o build/deadeye_res.o

$srcs = Get-ChildItem -Path src -Filter *.cpp -Recurse |
    Select-Object -ExpandProperty FullName

g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 -static `
    -static-libgcc -static-libstdc++ -Isrc $srcs build/deadeye_res.o `
    -o build/deadeye.exe -mwindows `
    -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32

g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 `
    tests/test_target.cpp -o build/test_target.exe
```

### Microsoft Visual C++

Run from a Visual Studio Developer Command Prompt:

```cmd
rc /nologo /i src\resources /fo build\deadeye_msvc_res.res src\resources\deadeye.rc

cl /std:c++17 /EHsc /W4 /O2 /Isrc /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /utf-8 ^
  src\main.cpp src\core\*.cpp src\gui\*.cpp build\deadeye_msvc_res.res ^
  /Fe:build\deadeye_msvc.exe /link /SUBSYSTEM:WINDOWS ^
  advapi32.lib comctl32.lib comdlg32.lib user32.lib gdi32.lib

cl /std:c++17 /EHsc /W4 /O2 /D_CRT_SECURE_NO_WARNINGS ^
  tests\test_target.cpp /Fe:build\test_target_msvc.exe
```

---

## Releases

Download pre-built Windows x64 binaries from the [GitHub Releases page](https://github.com/Winter0x11/Deadeye/releases).

Each release includes its versioned ZIP package and executable where provided. Check the release notes for changes and known limitations.

---

## License

See the repository's [LICENSE](LICENSE) file.
