# Deadeye

Windows process memory inspection and analysis.

Deadeye is a native C++ tool for exploring the virtual memory of running Windows processes and inspecting PE files in their mapped layout. It brings process selection, memory maps, hex inspection, string extraction, memory diffing, and behavioral tracking into one desktop application.

## Quick install

Run in PowerShell:

```powershell
irm https://raw.githubusercontent.com/Winter0x11/Deadeye/main/install.ps1 | iex
```

The installer downloads the latest Windows x64 release and installs it for the current user.

Prefer a manual download? Get the [latest release](https://github.com/Winter0x11/Deadeye/releases/latest).

## What it does

- **Process inspection** — Find and attach to running processes; inspect process metadata and architecture.
- **Memory maps** — Explore committed regions, addresses, sizes, types, protections, and entropy.
- **Hex inspection** — Examine process memory and navigate to addresses.
- **String extraction** — Find ASCII and UTF-16LE strings, with basic indicator classification.
- **Memory diffing** — Compare captures to identify new, modified, freed, and protection-changed regions. Save and reopen diff sessions.
- **Behavior tracking** — Sample selected regions over time to observe content, entropy, and protection changes.
- **PE inspection** — Examine EXE, DLL, and SYS files using a virtual layout that models how Windows maps them into memory.

## Typical workflow

Attach to a process, inspect its memory map, and open regions in the hex viewer. Extract strings to find interesting data, or capture memory states before and after an application action and compare the results. The behavior tracker can monitor selected regions over time.

## Read-only by design

Deadeye is designed to inspect target processes without modifying them. It uses Windows process and virtual-memory query APIs, including `ReadProcessMemory` and `VirtualQueryEx`. It does not inject DLLs, suspend target threads, or write to target process memory.

Some processes and memory regions may be inaccessible due to Windows permissions or process protections. Heuristic findings are investigation leads, not proof that a process is malicious or safe.

## Build from source

Requires a Windows development environment and a C++17 compiler.

```powershell
.\build.ps1

# Select a toolchain
.\build.ps1 -Toolchain msvc
.\build.ps1 -Toolchain mingw
```

See the build script and source tree for the full build configuration.

## License

Deadeye is licensed under the [MIT License](LICENSE). See the license text for terms.
