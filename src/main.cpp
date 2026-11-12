// src/main.cpp
// Deadeye - Windows Process Memory Triage Scanner, Hex Viewer & Real-Time Diff Timeline.
// Built for defensive malware analysis and detection engineering.
// Pure Win32 GUI application (/SUBSYSTEM:WINDOWS, -mwindows) with visual triage memory theme.
//
// Build (MinGW-w64, x64):
//   windres src/deadeye.rc -O coff -o build/deadeye_res.o
//   g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 src/main.cpp build/deadeye_res.o -o build/deadeye.exe -mwindows -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32
// Build (MSVC x64):
//   cl /std:c++17 /EHsc /W4 /O2 src/main.cpp /Fe:build/deadeye.exe /link /SUBSYSTEM:WINDOWS advapi32.lib comctl32.lib comdlg32.lib user32.lib gdi32.lib

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef IDI_APP
#define IDI_APP 101
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>

#ifdef _MSC_VER
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#endif

// ============================================================================
// 1. Constants & Core Data Structures
// ============================================================================

// Memory read chunk sizes
static const SIZE_T CLI_CHUNK_SIZE = 1024 * 1024; // 1 MB per chunk read
static const SIZE_T VIEW_PAGE_SIZE = 64 * 1024;   // 64 KB per GUI page
static const size_t MAX_HITS_PER_REGION = 10000;  // Max pattern matches tracked per region

// Triage Severity Scoring Weights & Thresholds
constexpr int WEIGHT_INJECTED_PE = 50;     // MZ/PE header detected in MEM_PRIVATE
constexpr int WEIGHT_UNLINKED_MODULE = 45; // Image region unlinked from PEB loader list
constexpr int WEIGHT_PRIVATE_RWX = 40;     // Private memory with RWX/RXC protection
constexpr int WEIGHT_WRITE_THEN_FLIP = 35; // AllocationProtect writable, Protect executable
constexpr int WEIGHT_UNBACKED_EXEC = 25;   // Executable unbacked by MEM_IMAGE
constexpr int WEIGHT_BEHAVIOR_UNPACK = 50; // Memory flipped to executable with byte changes / entropy shift
constexpr int WEIGHT_SLEEP_OBFUSCATION = 65; // Protection/entropy oscillating across heartbeat ticks

constexpr int SEV_MIN_CRITICAL = 80;
constexpr int SEV_MIN_HIGH = 50;
constexpr int SEV_MIN_MEDIUM = 25;
constexpr int SEV_MIN_LOW = 10;

// Control IDs for GUI child windows
#define ID_EDIT_PID 101
#define ID_BTN_LOAD 102
#define ID_EDIT_PATTERN 103
#define ID_BTN_SEARCH 104
#define ID_BTN_NEXT_HIT 105
#define ID_CHK_HITS_ONLY 106
#define ID_LIST_REGIONS 107
#define ID_EDIT_HEX 108
#define ID_BTN_PREV_PAGE 109
#define ID_BTN_NEXT_PAGE 110
#define ID_BTN_SNAP 111
#define ID_COMBO_DIFF 112
#define ID_BTN_CLEAR_SNAPS 113
#define ID_CHK_HEARTBEAT 114
#define ID_BTN_TRIAGE 115
#define ID_COMBO_VIEW_MODE 116
#define ID_COMBO_MIN_SEV 117
#define ID_CHK_HIDE_CLEAN 118
#define ID_BTN_EXPORT_JSON 119
#define ID_BTN_DIFF_PROC 121
#define ID_BTN_YARA 122
#define IDT_HEARTBEAT 1001

// Menu Item IDs
#define IDM_FILE_TRIAGE 2002
#define IDM_FILE_EXPORT_JSON 2003
#define IDM_FILE_THEME_LIGHT 2004
#define IDM_FILE_THEME_DARK 2005
#define IDM_FILE_EXIT 2006

#define IDM_EDIT_COPY_ADDR 2010
#define IDM_EDIT_COPY_HEX 2011
#define IDM_EDIT_FIND_PATTERN 2012
#define IDM_EDIT_FIND_NEXT 2013
#define IDM_EDIT_GENERATE_YARA 2014

#define IDM_VIEW_TRIAGE_FINDINGS 2020
#define IDM_VIEW_MEMORY_MAP 2021
#define IDM_VIEW_PROCESS_DIFF 2022
#define IDM_VIEW_HIDE_CLEAN 2024
#define IDM_VIEW_HITS_ONLY 2025
#define IDM_VIEW_REFRESH 2026

#define IDM_TIMELINE_SNAP 2030
#define IDM_TIMELINE_CLEAR 2031
#define IDM_TIMELINE_HEARTBEAT 2032
#define IDM_TIMELINE_PREV_PAGE 2033
#define IDM_TIMELINE_NEXT_PAGE 2034

#define IDM_DIFF_CAPTURE_BASELINE 2050
#define IDM_DIFF_CAPTURE_CURRENT 2051
#define IDM_DIFF_SAVE_SESSION 2052
#define IDM_DIFF_LOAD_SESSION 2053
#define IDM_DIFF_VIEW_STRINGS 2055

#define IDM_HELP_HEURISTICS 2040
#define IDM_HELP_ABOUT 2041

// Custom window messages for background worker thread scanning & triage
#define WM_SCAN_PROGRESS (WM_USER + 1)
#define WM_SCAN_COMPLETE (WM_USER + 2)
#define WM_TRIAGE_COMPLETE (WM_USER + 3)

// Compiled byte pattern: mask[i] == 1 means exact byte match, 0 means wildcard (??).
struct Pattern
{
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

// Snapshot of a memory page for timeline diffing.
struct Snapshot
{
    std::vector<uint8_t> data;
    SIZE_T view_offset = 0;
    DWORD timestamp_ms = 0;
    std::string label;
};

struct MemoryTransition
{
    DWORD timestamp_ms = 0;
    DWORD old_protect = 0;
    DWORD new_protect = 0;
    double old_entropy = 0.0;
    double new_entropy = 0.0;
    uint64_t old_hash = 0;
    uint64_t new_hash = 0;
    bool is_unpack = false;
    bool is_sleep_cycle = false;
};

// Metadata, detection heuristics, hit offsets, and snapshot timeline for a memory region.
struct RegionInfo
{
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD type = 0;
    DWORD protect = 0;
    uintptr_t alloc_base = 0;
    DWORD alloc_protect = 0;
    bool is_unbacked_exec = false;
    bool is_pe_in_private = false;
    bool private_rwx = false;
    bool write_then_flip = false;
    bool is_unlinked_image = false;
    std::vector<SIZE_T> hits;
    bool hits_truncated = false;
    std::vector<Snapshot> snapshots;

    // Behavioral Timeline & Detections
    DWORD last_protect = 0;
    double last_entropy = 0.0;
    uint64_t last_hash = 0;
    int flip_count = 0;
    std::vector<DWORD> protect_history;
    std::vector<double> entropy_history;
    std::vector<MemoryTransition> transitions;
    bool behavior_unpack_detected = false;
    bool sleep_obfuscation_detected = false;
};

// Tier 1: Process-Wide Memory Diff Structures
struct ProcessRegionSnapshot
{
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD state = 0;
    DWORD type = 0;
    DWORD protect = 0;
    DWORD alloc_protect = 0;
    uintptr_t alloc_base = 0;
    uint64_t content_hash = 0;
    double entropy = 0.0;
    bool has_pe = false;
    bool is_unbacked = false;
    bool is_rwx = false;
    bool is_write_then_flip = false;
    bool is_readable = false;
};

struct ProcessSnapshotSession
{
    DWORD pid = 0;
    std::string process_name;
    std::string timestamp_str;
    SIZE_T total_committed_bytes = 0;
    std::vector<ProcessRegionSnapshot> regions;
};

enum class ProcessDiffKind
{
    Appeared,       // [NEW]
    Disappeared,    // [REMOVED]
    ProtectionChg,  // [PROT_CHG]
    ContentChg,     // [MODIFIED]
    Unchanged
};

struct ProcessDiffItem
{
    ProcessDiffKind kind = ProcessDiffKind::Unchanged;
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD type = 0;
    DWORD old_protect = 0;
    DWORD new_protect = 0;
    double old_entropy = 0.0;
    double new_entropy = 0.0;
    uint64_t old_hash = 0;
    uint64_t new_hash = 0;
    bool has_pe = false;
    bool is_rwx = false;
    bool is_unbacked = false;
    bool is_unpack = false;
    std::string summary;
};

// Tier 1: String Extraction & Categorization
struct RevealedString
{
    std::string text;
    std::string category; // "[URL] ", "[IP]  ", "[PATH]", "[CMD] ", "[REG] ", "[STR] "
    uintptr_t addr = 0;
};

// Tier 1: YARA Generation & False-Positive Testing
struct YaraWildcardResult
{
    std::string hex_pattern;
    size_t total_bytes = 0;
    size_t wildcard_count = 0;
    std::vector<std::string> wildcards_applied;
};

struct FalsePositiveMatch
{
    DWORD pid = 0;
    std::string process_name;
    uintptr_t match_addr = 0;
};

struct FalsePositiveReport
{
    size_t total_processes_checked = 0;
    size_t total_processes_scanned = 0;
    SIZE_T total_bytes_scanned = 0;
    std::vector<FalsePositiveMatch> matches;
    DWORD elapsed_ms = 0;
};

// Triage finding for an individual region
struct TriageFinding
{
    size_t region_index = 0;
    uintptr_t base = 0;
    SIZE_T size = 0;
    uintptr_t alloc_base = 0;
    DWORD type = 0;
    DWORD protect = 0;
    DWORD alloc_protect = 0;
    int severity_score = 0;
    std::string severity_label;       // "CRIT", "HIGH", "MED", "LOW", "CLEAN"
    std::vector<std::string> flags;   // "INJECTED_PE", "UNLINKED_MODULE", "WRITE_THEN_FLIP", "PRIVATE_RWX", "UNBACKED_EXEC", "BEHAVIOR_UNPACK", "SLEEP_OBFUSCATION"
    std::vector<std::string> reasons; // Detailed explanation strings with point values
};

// Triage report for the entire process
struct TriageReport
{
    DWORD pid = 0;
    bool wow64_unsupported = false;
    std::vector<TriageFinding> findings;
};

// Range of a loaded module enumerated from the PEB loader list.
struct LoadedModuleRange
{
    uintptr_t base = 0;
    SIZE_T size = 0;
    std::wstring name;
};

// Application View Modes
enum class ViewMode
{
    TriageFindings = 0,
    MemoryMap = 1,
    ProcessDiff = 2
};

// Application Color Themes
enum class AppTheme
{
    Light = 0,
    Dark = 1
};

// Visual Theme Colors
struct ThemeColors
{
    COLORREF bg_window;
    COLORREF bg_control;
    COLORREF text_normal;
    COLORREF text_muted;

    // Visual Triage Row Highlighting Palette
    COLORREF row_crit_bg;
    COLORREF row_crit_text;
    COLORREF row_rwx_bg;
    COLORREF row_rwx_text;
    COLORREF row_pe_bg;
    COLORREF row_pe_text;
    COLORREF row_flip_bg;
    COLORREF row_flip_text;
    COLORREF row_unlinked_bg;
    COLORREF row_unlinked_text;
    COLORREF row_unbacked_bg;
    COLORREF row_unbacked_text;
    COLORREF row_priv_bg;
    COLORREF row_priv_text;
    COLORREF row_mapped_bg;
    COLORREF row_mapped_text;
    COLORREF row_image_bg;
    COLORREF row_image_text;

    // Process Diff Row Highlighting Palette
    COLORREF row_diff_new_bg;
    COLORREF row_diff_new_text;
    COLORREF row_diff_chg_bg;
    COLORREF row_diff_chg_text;
    COLORREF row_diff_mod_bg;
    COLORREF row_diff_mod_text;
    COLORREF row_diff_del_bg;
    COLORREF row_diff_del_text;

    COLORREF row_sel_bg;
    COLORREF row_sel_text;
};

// Classic Light Theme
static const ThemeColors g_theme_light = {
    RGB(240, 240, 240), // bg_window
    RGB(255, 255, 255), // bg_control
    RGB(20, 20, 20),    // text_normal
    RGB(100, 100, 100), // text_muted

    RGB(255, 180, 180), RGB(140, 0, 0),  // Crit (Alert Red)
    RGB(255, 192, 192), RGB(150, 0, 0),  // RWX (Salmon / Red Alert)
    RGB(232, 208, 255), RGB(75, 0, 130), // Injected PE (Violet Purple)
    RGB(255, 224, 185), RGB(140, 60, 0), // Write-then-flip (Peach / Orange)
    RGB(232, 208, 255), RGB(75, 0, 130), // Unlinked module (Violet Purple)
    RGB(255, 245, 180), RGB(120, 80, 0), // Unbacked exec (Light gold/yellow)
    RGB(255, 255, 225), RGB(70, 70, 0),  // MEM_PRIVATE clean (Warm Yellow)
    RGB(230, 242, 255), RGB(0, 60, 120), // MEM_MAPPED clean (Sky Blue)
    RGB(255, 255, 255), RGB(20, 20, 20), // MEM_IMAGE clean (Pure white)

    RGB(215, 245, 225), RGB(0, 100, 35),   // Diff New (Mint Green)
    RGB(255, 224, 185), RGB(140, 60, 0),   // Diff Prot Changed (Peach / Orange)
    RGB(255, 248, 195), RGB(120, 80, 0),   // Diff Modified (Amber / Gold)
    RGB(235, 235, 235), RGB(120, 120, 120), // Diff Disappeared (Muted Gray)

    RGB(51, 153, 255), RGB(255, 255, 255) // Selection (Windows blue / white text)
};

// Modern Dark Theme
static const ThemeColors g_theme_dark = {
    RGB(30, 30, 30),    // bg_window
    RGB(37, 37, 38),    // bg_control
    RGB(220, 220, 220), // text_normal
    RGB(140, 140, 140), // text_muted

    RGB(75, 20, 25), RGB(255, 140, 140), // Crit (Dark crimson)
    RGB(70, 25, 25), RGB(255, 150, 150), // RWX (Deep red)
    RGB(55, 25, 65), RGB(220, 160, 255), // Injected PE (Dark violet)
    RGB(65, 45, 20), RGB(255, 190, 120), // Write-then-flip (Dark amber)
    RGB(55, 25, 65), RGB(220, 160, 255), // Unlinked module (Dark violet)
    RGB(60, 55, 20), RGB(255, 230, 130), // Unbacked exec (Dark gold)
    RGB(42, 42, 30), RGB(240, 240, 170), // MEM_PRIVATE (Muted yellow tint)
    RGB(25, 40, 55), RGB(170, 210, 255), // MEM_MAPPED (Muted blue tint)
    RGB(37, 37, 38), RGB(220, 220, 220), // MEM_IMAGE (Neutral dark)

    RGB(20, 55, 30), RGB(150, 255, 180),  // Diff New (Dark Emerald / Mint)
    RGB(65, 45, 20), RGB(255, 190, 120),  // Diff Prot Changed (Dark Amber)
    RGB(60, 55, 20), RGB(255, 230, 130),  // Diff Modified (Dark Gold)
    RGB(35, 35, 35), RGB(130, 130, 130),  // Diff Disappeared (Dim Gray)

    RGB(26, 95, 180), RGB(255, 255, 255) // Selection (Deep slate blue)
};

// ============================================================================
// 2. Formatting & Helper Functions
// ============================================================================

// Formats a Win32 error code into a human-readable string.
std::string format_win32_error(DWORD err)
{
    LPSTR buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageA(flags, nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    if (len == 0 || buf == nullptr)
    {
        return "Unknown error";
    }
    std::string s(buf, len);
    LocalFree(buf);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
    {
        s.pop_back();
    }
    return s;
}

// Formats a 64-bit address as a zero-padded 16-digit hex string.
std::string fmt_addr(uintptr_t v)
{
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

// Formats a 64-bit value as a "0x..." hex string.
std::string to_hex_string(uintptr_t value)
{
    const char *digits = "0123456789ABCDEF";
    if (value == 0)
        return "0x0";
    std::string rev;
    while (value > 0)
    {
        rev.push_back(digits[value & 0xF]);
        value >>= 4;
    }
    std::string out = "0x";
    for (size_t i = rev.size(); i > 0; --i)
    {
        out.push_back(rev[i - 1]);
    }
    return out;
}

// Formats a region size concisely (B, KB, MB) for memory maps.
std::string fmt_size_short(SIZE_T sz)
{
    char buf[32];
    if (sz >= 1024 * 1024)
    {
        std::snprintf(buf, sizeof(buf), "%4lluM", static_cast<unsigned long long>(sz / (1024 * 1024)));
    }
    else if (sz >= 1024)
    {
        std::snprintf(buf, sizeof(buf), "%4lluK", static_cast<unsigned long long>(sz / 1024));
    }
    else
    {
        std::snprintf(buf, sizeof(buf), "%4lluB", static_cast<unsigned long long>(sz));
    }
    return std::string(buf);
}

// Converts a single hex character to its 0..15 value.
bool hex_nibble(char c, uint8_t &out)
{
    if (c >= '0' && c <= '9')
    {
        out = static_cast<uint8_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f')
    {
        out = static_cast<uint8_t>(10 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'F')
    {
        out = static_cast<uint8_t>(10 + (c - 'A'));
        return true;
    }
    return false;
}

// Parses hex strings like "4D 5A ?? 00 03" into bytes and a match mask.
bool parse_pattern(const std::string &input, Pattern &out, std::string &err)
{
    out.bytes.clear();
    out.mask.clear();
    size_t i = 0;

    while (i < input.size())
    {
        while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i])))
            ++i;
        if (i >= input.size())
            break;

        size_t start = i;
        while (i < input.size() && !std::isspace(static_cast<unsigned char>(input[i])))
            ++i;
        std::string tok = input.substr(start, i - start);

        if (tok == "?")
            tok = "??";

        if (tok.size() % 2 != 0)
        {
            err = "Odd-length token '" + tok + "' in pattern.";
            return false;
        }

        for (size_t k = 0; k < tok.size(); k += 2)
        {
            if (tok[k] == '?' && tok[k + 1] == '?')
            {
                out.bytes.push_back(0);
                out.mask.push_back(0);
            }
            else
            {
                uint8_t hi = 0;
                uint8_t lo = 0;
                if (!hex_nibble(tok[k], hi) || !hex_nibble(tok[k + 1], lo))
                {
                    err = "Invalid hex byte '" + tok.substr(k, 2) + "' in token '" + tok + "'.";
                    return false;
                }
                out.bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
                out.mask.push_back(1);
            }
        }
    }

    if (out.bytes.empty())
    {
        err = "Pattern is empty.";
        return false;
    }

    bool has_literal = false;
    for (size_t k = 0; k < out.mask.size(); ++k)
    {
        if (out.mask[k] != 0)
        {
            has_literal = true;
            break;
        }
    }
    if (!has_literal)
    {
        err = "Pattern cannot consist only of wildcards (must contain at least one literal hex byte).";
        return false;
    }
    return true;
}

// Searches buf[0..len) using SIMD-accelerated memchr anchored on the first literal byte.
std::vector<size_t> find_all(const uint8_t *buf, size_t len, const Pattern &p)
{
    std::vector<size_t> hits;
    size_t pl = p.bytes.size();
    if (buf == nullptr || pl == 0 || len < pl)
    {
        return hits;
    }

    size_t first_lit = 0;
    bool has_lit = false;
    for (size_t k = 0; k < pl; ++k)
    {
        if (p.mask[k] != 0)
        {
            first_lit = k;
            has_lit = true;
            break;
        }
    }

    if (!has_lit)
    {
        return hits;
    }

    uint8_t target_byte = p.bytes[first_lit];
    size_t max_start = len - pl;
    size_t i = 0;

    while (i <= max_start)
    {
        const void *found = std::memchr(buf + i + first_lit, target_byte, (max_start - i) + 1);
        if (found == nullptr)
        {
            break;
        }

        i = static_cast<size_t>((static_cast<const uint8_t *>(found) - buf) - first_lit);

        bool ok = true;
        for (size_t j = 0; j < pl; ++j)
        {
            if (p.mask[j] != 0 && buf[i + j] != p.bytes[j])
            {
                ok = false;
                break;
            }
        }
        if (ok)
        {
            hits.push_back(i);
        }
        ++i;
    }
    return hits;
}

// Translates Win32 memory protection flags into short text.
std::string prot_short(DWORD protect)
{
    DWORD base = protect & 0xFF;
    if (base == PAGE_READONLY)
        return "R--";
    if (base == PAGE_READWRITE)
        return "RW-";
    if (base == PAGE_WRITECOPY)
        return "RWC";
    if (base == PAGE_EXECUTE)
        return "--X";
    if (base == PAGE_EXECUTE_READ)
        return "R-X";
    if (base == PAGE_EXECUTE_READWRITE)
        return "RWX";
    if (base == PAGE_EXECUTE_WRITECOPY)
        return "RXC";
    return "???";
}

// Translates Win32 protection flags into full readable string.
std::string prot_full(DWORD protect)
{
    DWORD base = protect & 0xFF;
    std::string s;
    if (base == PAGE_NOACCESS)
        s = "PAGE_NOACCESS";
    else if (base == PAGE_READONLY)
        s = "PAGE_READONLY";
    else if (base == PAGE_READWRITE)
        s = "PAGE_READWRITE";
    else if (base == PAGE_WRITECOPY)
        s = "PAGE_WRITECOPY";
    else if (base == PAGE_EXECUTE)
        s = "PAGE_EXECUTE";
    else if (base == PAGE_EXECUTE_READ)
        s = "PAGE_EXECUTE_READ";
    else if (base == PAGE_EXECUTE_READWRITE)
        s = "PAGE_EXECUTE_READWRITE";
    else if (base == PAGE_EXECUTE_WRITECOPY)
        s = "PAGE_EXECUTE_WRITECOPY";
    else
    {
        char tmp[24];
        std::snprintf(tmp, sizeof(tmp), "0x%02lX", static_cast<unsigned long>(base));
        s = tmp;
    }
    if (protect & PAGE_GUARD)
        s += "|PAGE_GUARD";
    if (protect & PAGE_NOCACHE)
        s += "|PAGE_NOCACHE";
    if (protect & PAGE_WRITECOMBINE)
        s += "|PAGE_WRITECOMBINE";
    return s;
}

// Translates MEMORY_BASIC_INFORMATION.Type into short tag.
std::string type_short(DWORD t)
{
    if (t == MEM_IMAGE)
        return "IMG ";
    if (t == MEM_MAPPED)
        return "MAP ";
    if (t == MEM_PRIVATE)
        return "PRIV";
    return "UNK ";
}

// Translates MEMORY_BASIC_INFORMATION.Type into full string.
std::string type_full(DWORD t)
{
    if (t == MEM_IMAGE)
        return "IMAGE";
    if (t == MEM_MAPPED)
        return "MAPPED";
    if (t == MEM_PRIVATE)
        return "PRIVATE";
    return "UNKNOWN";
}

// Returns true if a region is MEM_PRIVATE and has executable+writable protection.
bool is_private_rwx(DWORD type, DWORD protect)
{
    if (type != MEM_PRIVATE)
        return false;
    DWORD base = protect & 0xFF;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

// Returns true if memory protection grants execution permission.
bool is_executable_protect(DWORD protect)
{
    DWORD base = protect & 0xFF;
    return (base == PAGE_EXECUTE ||
            base == PAGE_EXECUTE_READ ||
            base == PAGE_EXECUTE_READWRITE ||
            base == PAGE_EXECUTE_WRITECOPY);
}

// Returns true if region is executable but not backed by an image file on disk.
bool is_unbacked_exec(DWORD type, DWORD protect)
{
    return (type != MEM_IMAGE) && is_executable_protect(protect);
}

// Checks if buffer starts with a valid DOS ("MZ") and PE NT ("PE\0\0") header.
bool has_pe_header(const uint8_t *buf, size_t len)
{
    if (len < 0x40)
        return false;
    if (buf[0] != 0x4D || buf[1] != 0x5A)
        return false;
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, buf + 0x3C, sizeof(e_lfanew));
    if (e_lfanew < 0x40 || static_cast<uint64_t>(e_lfanew) + 4 > len)
        return false;
    return (buf[e_lfanew] == 'P' &&
            buf[e_lfanew + 1] == 'E' &&
            buf[e_lfanew + 2] == '\0' &&
            buf[e_lfanew + 3] == '\0');
}

// Attempts to enable SeDebugPrivilege for inspecting elevated/service processes.
bool enable_debug_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid))
    {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);
    return (ok && err == ERROR_SUCCESS);
}

// Reads memory from proc at base+offset for up to to_read bytes.
// If the 1 MB chunk read fails or is partial, it falls back to 4 KB page-by-page reads,
// skipping unreadable/guarded pages without aborting the rest of the region.
SIZE_T scan_chunk_robust(HANDLE proc, uintptr_t chunk_addr, SIZE_T to_read,
                         const Pattern *pat, std::vector<uint8_t> &chunk_buf,
                         SIZE_T chunk_offset_in_reg, std::vector<SIZE_T> &out_hits,
                         size_t max_hits, bool &out_truncated, bool &out_has_pe)
{
    if (to_read == 0)
        return 0;
    if (chunk_buf.size() < to_read)
        chunk_buf.resize(to_read);

    SIZE_T bytes_read = 0;
    BOOL ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk_addr),
                                chunk_buf.data(), to_read, &bytes_read);

    if (ok && bytes_read == to_read)
    {
        if (chunk_offset_in_reg == 0 && has_pe_header(chunk_buf.data(), bytes_read))
        {
            out_has_pe = true;
        }
        if (pat != nullptr && !pat->bytes.empty())
        {
            std::vector<size_t> hits = find_all(chunk_buf.data(), bytes_read, *pat);
            for (size_t h : hits)
            {
                if (out_hits.size() < max_hits)
                {
                    out_hits.push_back(chunk_offset_in_reg + h);
                }
                else
                {
                    out_truncated = true;
                    break;
                }
            }
        }
        return bytes_read;
    }

    // Fallback: Read page-by-page (4 KB) across this chunk window
    static const SIZE_T PAGE_4K = 4096;
    SIZE_T total_read = 0;
    std::vector<uint8_t> page_buf(PAGE_4K);
    std::vector<uint8_t> prev_tail;
    SIZE_T overlap = (pat != nullptr && !pat->bytes.empty()) ? (pat->bytes.size() - 1) : 0;

    for (SIZE_T page_off = 0; page_off < to_read; page_off += PAGE_4K)
    {
        SIZE_T page_len = (to_read - page_off < PAGE_4K) ? (to_read - page_off) : PAGE_4K;
        SIZE_T p_read = 0;
        BOOL p_ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(chunk_addr + page_off),
                                      page_buf.data(), page_len, &p_read);
        if (!p_ok || p_read == 0)
        {
            prev_tail.clear();
            continue;
        }

        total_read += p_read;
        if (chunk_offset_in_reg + page_off == 0 && has_pe_header(page_buf.data(), p_read))
        {
            out_has_pe = true;
        }

        if (pat != nullptr && !pat->bytes.empty())
        {
            if (!prev_tail.empty() && overlap > 0)
            {
                size_t b_len = prev_tail.size() + std::min(overlap, p_read);
                std::vector<uint8_t> b_buf(b_len);
                std::memcpy(b_buf.data(), prev_tail.data(), prev_tail.size());
                std::memcpy(b_buf.data() + prev_tail.size(), page_buf.data(), std::min(overlap, p_read));

                std::vector<size_t> b_hits = find_all(b_buf.data(), b_len, *pat);
                for (size_t bh : b_hits)
                {
                    if (bh < prev_tail.size() && page_off >= prev_tail.size())
                    {
                        SIZE_T hit_pos = chunk_offset_in_reg + (page_off - prev_tail.size()) + bh;
                        if (out_hits.size() < max_hits)
                        {
                            out_hits.push_back(hit_pos);
                        }
                        else
                        {
                            out_truncated = true;
                            break;
                        }
                    }
                }
            }

            std::vector<size_t> phits = find_all(page_buf.data(), p_read, *pat);
            for (size_t hit_off : phits)
            {
                SIZE_T hit_pos = chunk_offset_in_reg + page_off + hit_off;
                if (out_hits.size() < max_hits)
                {
                    out_hits.push_back(hit_pos);
                }
                else
                {
                    out_truncated = true;
                    break;
                }
            }

            if (p_read >= overlap)
            {
                prev_tail.assign(page_buf.data() + (p_read - overlap), page_buf.data() + p_read);
            }
            else
            {
                prev_tail.assign(page_buf.data(), page_buf.data() + p_read);
            }
        }
    }
    return total_read;
}

// Parses a numeric PID string with whitespace trimming.
bool parse_pid_string(const std::string &arg, DWORD &out_pid)
{
    size_t start = 0;
    while (start < arg.size() && std::isspace(static_cast<unsigned char>(arg[start])))
        ++start;
    size_t end = arg.size();
    while (end > start && std::isspace(static_cast<unsigned char>(arg[end - 1])))
        --end;
    std::string trimmed = arg.substr(start, end - start);

    if (trimmed.empty())
        return false;
    for (size_t i = 0; i < trimmed.size(); ++i)
    {
        if (!std::isdigit(static_cast<unsigned char>(trimmed[i])))
            return false;
    }
    errno = 0;
    char *end_ptr = nullptr;
    unsigned long val = std::strtoul(trimmed.c_str(), &end_ptr, 10);
    if (errno != 0 || end_ptr == nullptr || *end_ptr != '\0' || val == 0)
    {
        return false;
    }
    out_pid = static_cast<DWORD>(val);
    return true;
}

// Returns true if allocation was writable and current protection is executable (write-then-flip).
bool is_write_then_flip(DWORD alloc_protect, DWORD current_protect)
{
    DWORD a_base = alloc_protect & 0xFF;
    DWORD c_base = current_protect & 0xFF;

    bool was_writable = (a_base == PAGE_READWRITE || a_base == PAGE_WRITECOPY);
    bool now_exec = (c_base == PAGE_EXECUTE ||
                     c_base == PAGE_EXECUTE_READ ||
                     c_base == PAGE_EXECUTE_READWRITE ||
                     c_base == PAGE_EXECUTE_WRITECOPY);

    return was_writable && now_exec;
}

typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

// Traverses target process PEB loader list (InLoadOrderModuleList) on x64.
// If target is WOW64 (32-bit on 64-bit Windows), reports out_wow64 = true and returns false.
bool query_peb_modules_x64(HANDLE proc, std::vector<LoadedModuleRange> &out_modules, bool &out_wow64)
{
    out_modules.clear();
    out_wow64 = false;

    BOOL is_wow64 = FALSE;
    if (IsWow64Process(proc, &is_wow64) && is_wow64)
    {
        out_wow64 = true;
        return false;
    }

    HMODULE h_ntdll = GetModuleHandleA("ntdll.dll");
    if (h_ntdll == nullptr)
        return false;

    pfnNtQueryInformationProcess pfnQIP = reinterpret_cast<pfnNtQueryInformationProcess>(
        reinterpret_cast<void *>(GetProcAddress(h_ntdll, "NtQueryInformationProcess")));
    if (pfnQIP == nullptr)
        return false;

    struct
    {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        ULONG_PTR UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    } pbi = {};

    ULONG ret_len = 0;
    NTSTATUS status = pfnQIP(proc, 0, &pbi, sizeof(pbi), &ret_len);
    if (status != 0 || pbi.PebBaseAddress == nullptr)
    {
        return false;
    }

    uintptr_t peb_addr = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
    uintptr_t ldr_addr = 0;
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(peb_addr + 0x18),
                           &ldr_addr, sizeof(ldr_addr), &bytes_read) ||
        ldr_addr == 0)
    {
        return false;
    }

    uintptr_t head = ldr_addr + 0x10;
    uintptr_t curr = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(head),
                           &curr, sizeof(curr), &bytes_read) ||
        curr == 0 || curr == head)
    {
        return false;
    }

    size_t count = 0;
    while (curr != head && count < 500)
    {
        uintptr_t flink = 0;
        uintptr_t dll_base = 0;
        ULONG size_of_image = 0;
        USHORT name_len = 0;
        uintptr_t name_buf_ptr = 0;

        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(curr), &flink, sizeof(flink), &bytes_read))
            break;
        if (flink == 0 || flink == curr)
            break;
        ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(curr + 0x30), &dll_base, sizeof(dll_base), &bytes_read);
        ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(curr + 0x40), &size_of_image, sizeof(size_of_image), &bytes_read);
        ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(curr + 0x58), &name_len, sizeof(name_len), &bytes_read);
        ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(curr + 0x60), &name_buf_ptr, sizeof(name_buf_ptr), &bytes_read);

        if (dll_base != 0)
        {
            LoadedModuleRange mod;
            mod.base = dll_base;
            mod.size = size_of_image;
            if (name_buf_ptr != 0 && name_len > 0 && name_len < 512)
            {
                std::vector<wchar_t> wbuf(name_len / 2 + 1, 0);
                ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(name_buf_ptr),
                                  wbuf.data(), name_len, &bytes_read);
                mod.name = wbuf.data();
            }
            out_modules.push_back(mod);
        }

        curr = flink;
        count++;
    }

    return !out_modules.empty();
}

// Queries all committed virtual memory regions for the target process.
// UI-independent core function.
bool query_process_regions(HANDLE proc, std::vector<RegionInfo> &out_regions, std::string &err_msg)
{
    out_regions.clear();
    err_msg.clear();

    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (true)
    {
        std::memset(&mbi, 0, sizeof(mbi));
        SIZE_T q = VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (q == 0)
        {
            DWORD err = GetLastError();
            if (err != ERROR_INVALID_PARAMETER && out_regions.empty())
            {
                err_msg = format_win32_error(err);
                return false;
            }
            break;
        }

        uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T region_size = mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_NOACCESS) == 0 &&
            (mbi.Protect & PAGE_GUARD) == 0)
        {

            RegionInfo reg;
            reg.base = region_base;
            reg.size = region_size;
            reg.type = mbi.Type;
            reg.protect = mbi.Protect;
            reg.alloc_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            reg.alloc_protect = mbi.AllocationProtect;
            reg.is_unbacked_exec = is_unbacked_exec(mbi.Type, mbi.Protect);
            reg.private_rwx = is_private_rwx(mbi.Type, mbi.Protect);
            reg.write_then_flip = is_write_then_flip(mbi.AllocationProtect, mbi.Protect);

            out_regions.push_back(reg);
        }

        if (region_size == 0)
            break;
        uintptr_t next = region_base + region_size;
        if (next <= addr)
            break;
        addr = next;
    }

    return true;
}

// Evaluates defensive triage heuristics against process memory regions.
// UI-independent core function.
TriageReport run_process_triage(HANDLE proc, DWORD pid, std::vector<RegionInfo> &regions,
                                std::atomic<bool> *abort_flag,
                                void (*progress_cb)(SIZE_T current, SIZE_T total, void *user_data),
                                void *user_data)
{
    TriageReport report;
    report.pid = pid;

    std::vector<LoadedModuleRange> peb_modules;
    bool peb_ok = query_peb_modules_x64(proc, peb_modules, report.wow64_unsupported);

    std::vector<uint8_t> header_buf(4096);
    SIZE_T total_regions = regions.size();

    for (size_t i = 0; i < regions.size(); ++i)
    {
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
            break;

        RegionInfo &reg = regions[i];

        // Check for injected PE header in MEM_PRIVATE regions
        if (reg.type == MEM_PRIVATE)
        {
            SIZE_T to_read = (reg.size < 4096) ? reg.size : 4096;
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(reg.base),
                                  header_buf.data(), to_read, &bytes_read))
            {
                if (has_pe_header(header_buf.data(), bytes_read))
                {
                    reg.is_pe_in_private = true;
                }
            }
        }

        // Check for unlinked MEM_IMAGE allocations (missing from PEB loader list)
        if (!report.wow64_unsupported && peb_ok && reg.type == MEM_IMAGE && reg.base == reg.alloc_base)
        {
            bool in_peb = false;
            for (const auto &mod : peb_modules)
            {
                if (mod.base == reg.base)
                {
                    in_peb = true;
                    break;
                }
            }
            if (!in_peb)
            {
                reg.is_unlinked_image = true;
            }
        }

        // Calculate additive triage severity score
        TriageFinding finding;
        finding.region_index = i;
        finding.base = reg.base;
        finding.size = reg.size;
        finding.alloc_base = reg.alloc_base;
        finding.type = reg.type;
        finding.protect = reg.protect;
        finding.alloc_protect = reg.alloc_protect;
        finding.severity_score = 0;

        if (reg.is_pe_in_private)
        {
            finding.severity_score += WEIGHT_INJECTED_PE;
            finding.flags.push_back("INJECTED_PE");
            finding.reasons.push_back("Injected PE/Reflective DLL header in private memory (+" +
                                      std::to_string(WEIGHT_INJECTED_PE) + ")");
        }
        if (reg.is_unlinked_image)
        {
            finding.severity_score += WEIGHT_UNLINKED_MODULE;
            finding.flags.push_back("UNLINKED_MODULE");
            finding.reasons.push_back("Image allocation unlinked from PEB loader list (+" +
                                      std::to_string(WEIGHT_UNLINKED_MODULE) + ")");
        }
        if (reg.private_rwx)
        {
            finding.severity_score += WEIGHT_PRIVATE_RWX;
            finding.flags.push_back("PRIVATE_RWX");
            finding.reasons.push_back("Private memory with RWX/RXC protection (+" +
                                      std::to_string(WEIGHT_PRIVATE_RWX) + ")");
        }
        if (reg.write_then_flip)
        {
            finding.severity_score += WEIGHT_WRITE_THEN_FLIP;
            finding.flags.push_back("WRITE_THEN_FLIP");
            finding.reasons.push_back("Write-then-flip: allocated writable, currently executable (+" +
                                      std::to_string(WEIGHT_WRITE_THEN_FLIP) + ")");
        }
        if (reg.is_unbacked_exec)
        {
            finding.severity_score += WEIGHT_UNBACKED_EXEC;
            finding.flags.push_back("UNBACKED_EXEC");
            finding.reasons.push_back("Executable memory not backed by a disk image (+" +
                                      std::to_string(WEIGHT_UNBACKED_EXEC) + ")");
        }
        if (reg.behavior_unpack_detected)
        {
            finding.severity_score += WEIGHT_BEHAVIOR_UNPACK;
            finding.flags.push_back("BEHAVIOR_UNPACK");
            finding.reasons.push_back("Unpack detected: memory flipped to executable with byte changes / entropy shift (+" +
                                      std::to_string(WEIGHT_BEHAVIOR_UNPACK) + ")");
        }
        if (reg.sleep_obfuscation_detected)
        {
            finding.severity_score += WEIGHT_SLEEP_OBFUSCATION;
            finding.flags.push_back("SLEEP_OBFUSCATION");
            finding.reasons.push_back("Sleep obfuscation detected: oscillating between dormant encrypted and active executable (+" +
                                      std::to_string(WEIGHT_SLEEP_OBFUSCATION) + ")");
        }

        if (finding.severity_score >= SEV_MIN_CRITICAL)
            finding.severity_label = "CRIT";
        else if (finding.severity_score >= SEV_MIN_HIGH)
            finding.severity_label = "HIGH";
        else if (finding.severity_score >= SEV_MIN_MEDIUM)
            finding.severity_label = "MED";
        else if (finding.severity_score >= SEV_MIN_LOW)
            finding.severity_label = "LOW";
        else
            finding.severity_label = "CLEAN";

        report.findings.push_back(finding);

        if (progress_cb != nullptr && (i % 20 == 0 || i + 1 == total_regions))
        {
            progress_cb(i + 1, total_regions, user_data);
        }
    }

    // Sort findings by severity score descending (highest threat first)
    std::stable_sort(report.findings.begin(), report.findings.end(),
                     [](const TriageFinding &a, const TriageFinding &b)
                     {
                         return a.severity_score > b.severity_score;
                     });

    return report;
}

// Serializes a TriageReport into valid JSON.
// UI-independent core function.
std::string export_triage_json(const TriageReport &report)
{
    std::string json;
    json.reserve(report.findings.size() * 512 + 256);
    json += "{\n";
    json += "  \"pid\": " + std::to_string(report.pid) + ",\n";
    json += "  \"wow64_unsupported\": " + std::string(report.wow64_unsupported ? "true" : "false") + ",\n";
    json += "  \"findings_count\": " + std::to_string(report.findings.size()) + ",\n";
    json += "  \"findings\": [\n";

    for (size_t i = 0; i < report.findings.size(); ++i)
    {
        const TriageFinding &f = report.findings[i];
        json += "    {\n";
        json += "      \"base\": \"" + to_hex_string(f.base) + "\",\n";
        json += "      \"size\": " + std::to_string(f.size) + ",\n";
        json += "      \"alloc_base\": \"" + to_hex_string(f.alloc_base) + "\",\n";
        json += "      \"type\": \"" + type_full(f.type) + "\",\n";
        json += "      \"protect\": \"" + prot_full(f.protect) + "\",\n";
        json += "      \"alloc_protect\": \"" + prot_full(f.alloc_protect) + "\",\n";
        json += "      \"severity_score\": " + std::to_string(f.severity_score) + ",\n";
        json += "      \"severity_label\": \"" + f.severity_label + "\",\n";

        json += "      \"flags\": [";
        for (size_t k = 0; k < f.flags.size(); ++k)
        {
            json += "\"" + f.flags[k] + "\"" + (k + 1 < f.flags.size() ? ", " : "");
        }
        json += "],\n";

        json += "      \"reasons\": [\n";
        for (size_t k = 0; k < f.reasons.size(); ++k)
        {
            json += "        \"" + f.reasons[k] + "\"" + (k + 1 < f.reasons.size() ? ",\n" : "\n");
        }
        json += "      ]\n";
        json += "    }" + std::string(i + 1 < report.findings.size() ? ",\n" : "\n");
    }

    json += "  ]\n";
    json += "}\n";
    return json;
}

// ============================================================================
// 3. GUI Subsystem (Visual Triage, Owner-Draw List, Memory Hex Viewer)
// ============================================================================

static HWND g_hwnd_main = nullptr;
static HWND g_edit_pid = nullptr;
static HWND g_btn_load = nullptr;
static HWND g_btn_triage = nullptr;
static HWND g_edit_pattern = nullptr;
static HWND g_btn_search = nullptr;
static HWND g_btn_next_hit = nullptr;
static HWND g_chk_hits_only = nullptr;
static HWND g_chk_heartbeat = nullptr;
static HWND g_btn_diff_proc = nullptr;
static HWND g_btn_yara = nullptr;

static HWND g_combo_view_mode = nullptr;
static HWND g_combo_min_sev = nullptr;
static HWND g_chk_hide_clean = nullptr;
static HWND g_btn_export_json = nullptr;

static HWND g_list_regions = nullptr;
static HWND g_lbl_hex_info = nullptr;
static HWND g_btn_prev_page = nullptr;
static HWND g_btn_next_page = nullptr;
static HWND g_btn_snap = nullptr;
static HWND g_combo_diff = nullptr;
static HWND g_btn_clear_snaps = nullptr;
static HWND g_edit_hex = nullptr;
static HWND g_lbl_triage_reasons = nullptr;
static HWND g_lbl_status = nullptr;

static HFONT g_mono_font = nullptr;
static HFONT g_ui_font = nullptr;
static HFONT g_ui_font_bold = nullptr;
static HBRUSH g_br_window = nullptr;
static HBRUSH g_br_control = nullptr;
static HACCEL g_haccel = nullptr;

static AppTheme g_theme = AppTheme::Light;
static ViewMode g_view_mode = ViewMode::TriageFindings;
static int g_min_sev_filter = 0;
static bool g_hide_clean = false;

static DWORD g_current_pid = 0;
static std::string g_current_pid_label;
static Pattern g_active_pattern;
static bool g_has_pattern = false;
static std::vector<RegionInfo> g_regions;
static TriageReport g_triage_report;
static std::vector<size_t> g_visible_indices;
static size_t g_selected_region = 0;
static bool g_has_selection = false;
static SIZE_T g_view_offset = 0;
static size_t g_hit_cursor_region = 0;
static size_t g_hit_cursor_index = 0;

// Process-wide Diff and Behavioral Tracking State
static ProcessSnapshotSession g_process_baseline;
static ProcessSnapshotSession g_process_target;
static std::vector<ProcessDiffItem> g_process_diffs;
static bool g_has_baseline = false;
static bool g_has_target = false;
static std::vector<RevealedString> g_revealed_strings;

static HANDLE g_target_proc = nullptr;
static std::string g_last_hex_dump;
static std::string g_last_hex_info;

void close_target_proc()
{
    if (g_target_proc != nullptr)
    {
        CloseHandle(g_target_proc);
        g_target_proc = nullptr;
    }
}

HANDLE get_or_open_target_proc(DWORD pid)
{
    if (g_target_proc != nullptr)
    {
        DWORD exit_code = 0;
        if (g_current_pid == pid && GetExitCodeProcess(g_target_proc, &exit_code) && exit_code == STILL_ACTIVE)
        {
            return g_target_proc;
        }
        close_target_proc();
    }
    g_target_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    return g_target_proc;
}

void invalidate_hex_cache()
{
    g_last_hex_dump.clear();
    g_last_hex_info.clear();
}

void set_status(const std::string &text)
{
    SetWindowTextA(g_lbl_status, text.c_str());
}

const ThemeColors &get_current_theme()
{
    return (g_theme == AppTheme::Light) ? g_theme_light : g_theme_dark;
}

void update_theme_brushes()
{
    if (g_br_window)
        DeleteObject(g_br_window);
    if (g_br_control)
        DeleteObject(g_br_control);
    const ThemeColors &tc = get_current_theme();
    g_br_window = CreateSolidBrush(tc.bg_window);
    g_br_control = CreateSolidBrush(tc.bg_control);
}

void apply_theme_switch(HWND hwnd, AppTheme new_theme)
{
    g_theme = new_theme;
    update_theme_brushes();
    InvalidateRect(hwnd, nullptr, TRUE);
    if (g_list_regions) InvalidateRect(g_list_regions, nullptr, TRUE);
    if (g_edit_hex) InvalidateRect(g_edit_hex, nullptr, TRUE);
    if (g_lbl_triage_reasons) InvalidateRect(g_lbl_triage_reasons, nullptr, TRUE);
    if (g_lbl_status) InvalidateRect(g_lbl_status, nullptr, TRUE);
    HWND btns[] = { g_btn_load, g_btn_triage, g_btn_search, g_btn_next_hit, g_btn_export_json, g_btn_snap, g_btn_clear_snaps, g_btn_prev_page, g_btn_next_page, g_btn_diff_proc, g_btn_yara };
    for (HWND b : btns) { if (b) InvalidateRect(b, nullptr, TRUE); }
    set_status((g_theme == AppTheme::Dark) ? "Theme switched to Modern Dark." : "Theme switched to Classic Light.");
}

struct DiffPair
{
    bool active;
    std::string title;
    const std::vector<uint8_t> *ref_data;
    const std::vector<uint8_t> *cmp_data;
    SIZE_T ref_view_offset;
    SIZE_T cmp_view_offset;
};

DiffPair get_active_diff_pair()
{
    DiffPair dp = {false, "", nullptr, nullptr, 0, 0};
    if (!g_has_selection || g_selected_region >= g_regions.size())
        return dp;
    const RegionInfo &reg = g_regions[g_selected_region];
    if (reg.snapshots.empty())
        return dp;

    LRESULT sel = SendMessageA(g_combo_diff, CB_GETCURSEL, 0, 0);
    if (sel <= 0 || sel == CB_ERR)
        return dp;

    size_t snap_count = reg.snapshots.size();
    if (static_cast<size_t>(sel) <= snap_count)
    {
        size_t idx = static_cast<size_t>(sel - 1);
        dp.active = true;
        dp.title = "Live vs " + reg.snapshots[idx].label;
        dp.ref_data = &reg.snapshots[idx].data;
        dp.cmp_data = nullptr; // Live
        dp.ref_view_offset = reg.snapshots[idx].view_offset;
        dp.cmp_view_offset = g_view_offset;
        return dp;
    }

    size_t pair_idx = static_cast<size_t>(sel - 1 - snap_count);
    if (pair_idx + 1 < snap_count)
    {
        dp.active = true;
        dp.title = reg.snapshots[pair_idx].label + " vs " + reg.snapshots[pair_idx + 1].label;
        dp.ref_data = &reg.snapshots[pair_idx].data;
        dp.cmp_data = &reg.snapshots[pair_idx + 1].data;
        dp.ref_view_offset = reg.snapshots[pair_idx].view_offset;
        dp.cmp_view_offset = reg.snapshots[pair_idx + 1].view_offset;
        return dp;
    }
    return dp;
}

std::string build_hex_dump(const uint8_t *buf, size_t buf_len, uintptr_t view_addr,
                           const std::vector<SIZE_T> &region_hits, SIZE_T view_offset,
                           size_t pat_len, SIZE_T focus_offset, int &out_focus_line,
                           const uint8_t *ref_buf, size_t ref_len, bool diff_active,
                           size_t &out_chg_bytes, size_t &out_new_bytes, size_t &out_zeroed_bytes)
{
    out_focus_line = -1;
    out_chg_bytes = 0;
    out_new_bytes = 0;
    out_zeroed_bytes = 0;

    if (buf_len == 0)
    {
        return "(No readable bytes in this page)\r\n";
    }

    std::vector<uint8_t> hit_byte(buf_len, 0);
    if (g_has_pattern && pat_len > 0)
    {
        for (size_t i = 0; i < region_hits.size(); ++i)
        {
            SIZE_T h = region_hits[i];
            if (h + pat_len <= view_offset || h >= view_offset + buf_len)
            {
                continue;
            }
            for (size_t j = 0; j < pat_len; ++j)
            {
                if (h + j >= view_offset && h + j < view_offset + buf_len)
                {
                    hit_byte[(h + j) - view_offset] = 1;
                }
            }
        }
    }

    std::string out;
    out.reserve(buf_len * 6 + 256);
    out += "    Address           00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  0123456789ABCDEF\r\n";
    out += "    ----------------  -----------------------  -----------------------  ----------------\r\n";

    size_t num_rows = (buf_len + 15) / 16;
    int line_counter = 2;

    for (size_t row = 0; row < num_rows; ++row)
    {
        size_t rs = row * 16;
        size_t re = rs + 16;
        if (re > buf_len)
            re = buf_len;

        bool row_has_hit = false;
        bool row_has_diff = false;

        for (size_t i = rs; i < re; ++i)
        {
            if (hit_byte[i] != 0)
            {
                row_has_hit = true;
            }
            if (diff_active && ref_buf != nullptr)
            {
                if (i < ref_len)
                {
                    if (buf[i] != ref_buf[i])
                    {
                        row_has_diff = true;
                        out_chg_bytes++;
                        if (ref_buf[i] == 0 && buf[i] != 0)
                            out_new_bytes++;
                        else if (ref_buf[i] != 0 && buf[i] == 0)
                            out_zeroed_bytes++;
                    }
                }
                else
                {
                    row_has_diff = true;
                    out_chg_bytes++;
                    if (buf[i] != 0)
                        out_new_bytes++;
                }
            }
        }

        if (focus_offset != static_cast<SIZE_T>(-1) &&
            focus_offset >= view_offset + rs && focus_offset < view_offset + re)
        {
            out_focus_line = line_counter;
        }

        if (row_has_hit && row_has_diff)
        {
            out += "!>> ";
        }
        else if (row_has_diff)
        {
            out += "CHG ";
        }
        else if (row_has_hit)
        {
            out += ">>> ";
        }
        else
        {
            out += "    ";
        }

        out += fmt_addr(view_addr + rs);
        out += "  ";

        char hx[8];
        for (size_t i = rs; i < rs + 16; ++i)
        {
            if (i == rs + 8)
                out += " ";
            if (i < re)
            {
                std::snprintf(hx, sizeof(hx), "%02X ", buf[i]);
                out += hx;
            }
            else
            {
                out += "   ";
            }
        }
        out += " ";

        for (size_t i = rs; i < rs + 16; ++i)
        {
            if (i < re)
            {
                uint8_t b = buf[i];
                out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            }
            else
            {
                out += ' ';
            }
        }
        out += "\r\n";
        line_counter++;

        // Sub-row for changed bytes in diff timeline
        if (row_has_diff && ref_buf != nullptr)
        {
            out += "        old:          ";
            for (size_t i = rs; i < rs + 16; ++i)
            {
                if (i == rs + 8)
                    out += " ";
                if (i < re && i < ref_len && buf[i] != ref_buf[i])
                {
                    std::snprintf(hx, sizeof(hx), "%02X ", ref_buf[i]);
                    out += hx;
                }
                else
                {
                    out += "   ";
                }
            }
            out += " ";
            for (size_t i = rs; i < rs + 16; ++i)
            {
                if (i < re && i < ref_len && buf[i] != ref_buf[i])
                {
                    uint8_t b = ref_buf[i];
                    out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
                }
                else
                {
                    out += ' ';
                }
            }
            out += "\r\n";
            line_counter++;
        }
    }
    return out;
}

void display_selected_region(SIZE_T focus_offset);
void populate_region_list();
void update_triage_details_label(size_t reg_idx);

void update_diff_combo()
{
    SendMessageA(g_combo_diff, CB_RESETCONTENT, 0, 0);
    SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Diff: Off (Normal)"));

    if (!g_has_selection || g_selected_region >= g_regions.size())
    {
        SendMessageA(g_combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(g_btn_snap, FALSE);
        EnableWindow(g_combo_diff, FALSE);
        EnableWindow(g_btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(g_btn_snap, TRUE);
    const RegionInfo &reg = g_regions[g_selected_region];

    if (reg.snapshots.empty())
    {
        SendMessageA(g_combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(g_combo_diff, FALSE);
        EnableWindow(g_btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(g_combo_diff, TRUE);
    EnableWindow(g_btn_clear_snaps, TRUE);

    for (size_t i = 0; i < reg.snapshots.size(); ++i)
    {
        std::string item = "Live vs " + reg.snapshots[i].label;
        SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
    }

    if (reg.snapshots.size() >= 2)
    {
        for (size_t i = 0; i + 1 < reg.snapshots.size(); ++i)
        {
            std::string item = reg.snapshots[i].label + " vs " + reg.snapshots[i + 1].label;
            SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
        }
    }

    LRESULT count = SendMessageA(g_combo_diff, CB_GETCOUNT, 0, 0);
    WPARAM sel = (reg.snapshots.size() > 0) ? static_cast<WPARAM>(reg.snapshots.size()) : 0;
    if (sel >= static_cast<WPARAM>(count))
        sel = 0;
    SendMessageA(g_combo_diff, CB_SETCURSEL, sel, 0);
}

void on_take_snapshot()
{
    if (!g_has_selection || g_selected_region >= g_regions.size())
        return;
    RegionInfo &reg = g_regions[g_selected_region];

    if (g_view_offset >= reg.size)
        g_view_offset = 0;
    SIZE_T remaining = reg.size - g_view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    HANDLE proc = get_or_open_target_proc(g_current_pid);
    if (proc == nullptr)
    {
        DWORD err = GetLastError();
        set_status("[ERROR] OpenProcess failed: " + format_win32_error(err));
        return;
    }

    Snapshot snap;
    snap.data.resize(to_read);
    SIZE_T bytes_read = 0;
    BOOL ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(reg.base + g_view_offset),
                                snap.data.data(), to_read, &bytes_read);
    DWORD read_err = ok ? 0 : GetLastError();

    if (bytes_read == 0)
    {
        set_status("[ERROR] Could not capture snapshot: " + format_win32_error(read_err));
        return;
    }
    snap.data.resize(bytes_read);
    snap.view_offset = g_view_offset;
    snap.timestamp_ms = GetTickCount();

    size_t snap_num = reg.snapshots.size() + 1;
    char label_buf[64];
    if (reg.snapshots.empty())
    {
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (0.0s)", snap_num);
    }
    else
    {
        DWORD elapsed_ms = snap.timestamp_ms - reg.snapshots[0].timestamp_ms;
        double sec = static_cast<double>(elapsed_ms) / 1000.0;
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (+%.1fs)", snap_num, sec);
    }
    snap.label = label_buf;

    reg.snapshots.push_back(snap);
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis)
    {
        if (g_visible_indices[vis] == g_selected_region)
        {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }

    char status[192];
    std::snprintf(status, sizeof(status),
                  "Captured %s for region 0x%016llX (%zu bytes) | %zu snapshot(s) in timeline",
                  snap.label.c_str(),
                  static_cast<unsigned long long>(reg.base + g_view_offset),
                  bytes_read, reg.snapshots.size());
    set_status(status);
    display_selected_region(static_cast<SIZE_T>(-1));
}

void on_clear_snapshots()
{
    if (!g_has_selection || g_selected_region >= g_regions.size())
        return;
    RegionInfo &reg = g_regions[g_selected_region];
    size_t count = reg.snapshots.size();
    reg.snapshots.clear();
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis)
    {
        if (g_visible_indices[vis] == g_selected_region)
        {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    display_selected_region(static_cast<SIZE_T>(-1));

    char status[128];
    std::snprintf(status, sizeof(status), "Cleared %zu snapshot(s) for current region.", count);
    set_status(status);
}

void display_selected_region(SIZE_T focus_offset)
{
    if (!g_has_selection || g_selected_region >= g_regions.size())
    {
        SetWindowTextA(g_lbl_hex_info, "Hex View: (no region selected)");
        SetWindowTextA(g_edit_hex, "");
        g_last_hex_info.clear();
        g_last_hex_dump.clear();
        EnableWindow(g_btn_prev_page, FALSE);
        EnableWindow(g_btn_next_page, FALSE);
        return;
    }

    const RegionInfo &reg = g_regions[g_selected_region];
    if (g_view_offset >= reg.size)
    {
        g_view_offset = 0;
    }

    SIZE_T remaining = reg.size - g_view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    EnableWindow(g_btn_prev_page, g_view_offset > 0 ? TRUE : FALSE);
    EnableWindow(g_btn_next_page, (g_view_offset + to_read < reg.size) ? TRUE : FALSE);

    DiffPair dp = get_active_diff_pair();
    std::vector<uint8_t> buf;
    SIZE_T bytes_read = 0;
    BOOL ok = TRUE;
    DWORD read_err = 0;

    if (dp.active && dp.cmp_data != nullptr)
    {
        buf = *dp.cmp_data;
        bytes_read = buf.size();
    }
    else
    {
        HANDLE proc = get_or_open_target_proc(g_current_pid);
        if (proc == nullptr)
        {
            DWORD err = GetLastError();
            std::string msg = "[ERROR] OpenProcess failed: " + format_win32_error(err) + "\r\n";
            SetWindowTextA(g_edit_hex, msg.c_str());
            g_last_hex_dump = msg;
            return;
        }

        buf.resize(to_read);
        ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(reg.base + g_view_offset),
                               buf.data(), to_read, &bytes_read);
        read_err = ok ? 0 : GetLastError();

        if (bytes_read == 0)
        {
            std::string msg = "[WARN] ReadProcessMemory failed at 0x" + fmt_addr(reg.base + g_view_offset) +
                              ": " + format_win32_error(read_err) + "\r\n";
            SetWindowTextA(g_edit_hex, msg.c_str());
            g_last_hex_dump = msg;
            return;
        }
        buf.resize(bytes_read);
    }

    const uint8_t *ref_ptr = nullptr;
    size_t ref_len = 0;
    bool offset_mismatch = false;
    uintptr_t display_addr = reg.base + g_view_offset;
    SIZE_T display_view_offset = g_view_offset;

    if (dp.active)
    {
        if (dp.cmp_data != nullptr)
        {
            display_view_offset = dp.cmp_view_offset;
            display_addr = reg.base + display_view_offset;
            if (dp.ref_view_offset != dp.cmp_view_offset)
            {
                offset_mismatch = true;
            }
            else
            {
                ref_ptr = dp.ref_data->data();
                ref_len = dp.ref_data->size();
            }
        }
        else
        {
            if (dp.ref_view_offset == g_view_offset)
            {
                ref_ptr = dp.ref_data->data();
                ref_len = dp.ref_data->size();
            }
            else
            {
                offset_mismatch = true;
            }
        }
    }

    int focus_line = -1;
    size_t chg_bytes = 0, new_bytes = 0, zeroed_bytes = 0;
    std::string dump = build_hex_dump(buf.data(), bytes_read, display_addr,
                                      reg.hits, display_view_offset, g_active_pattern.bytes.size(),
                                      focus_offset, focus_line,
                                      ref_ptr, ref_len, dp.active && !offset_mismatch,
                                      chg_bytes, new_bytes, zeroed_bytes);

    if (offset_mismatch)
    {
        char warn_note[256];
        if (dp.cmp_data != nullptr)
        {
            std::snprintf(warn_note, sizeof(warn_note),
                          "[Note: Snapshots belong to different page offsets (0x%llX vs 0x%llX). Cannot diff across different offsets.]\r\n\r\n",
                          static_cast<unsigned long long>(dp.ref_view_offset),
                          static_cast<unsigned long long>(dp.cmp_view_offset));
        }
        else
        {
            std::snprintf(warn_note, sizeof(warn_note),
                          "[Note: Selected snapshot belongs to offset 0x%llX; current page is 0x%llX. Navigate back or take a new snapshot.]\r\n\r\n",
                          static_cast<unsigned long long>(dp.ref_view_offset),
                          static_cast<unsigned long long>(g_view_offset));
        }
        dump = warn_note + dump;
        if (focus_line >= 0)
            focus_line += 2;
    }

    if (!ok)
    {
        dump = "[WARN] Partial read (" + std::to_string(bytes_read) + "/" + std::to_string(to_read) +
               " bytes): " + format_win32_error(read_err) + "\r\n\r\n" + dump;
        if (focus_line >= 0)
            focus_line += 2;
    }

    char info[360];
    std::string det_tag;
    if (reg.is_pe_in_private)
        det_tag = " [! INJECTED PE]";
    else if (reg.private_rwx)
        det_tag = " [! RWX]";
    else if (reg.is_unbacked_exec)
        det_tag = " [! UNBACKED EXEC]";

    if (dp.active && !offset_mismatch)
    {
        std::snprintf(info, sizeof(info),
                      "Reg %zu/%zu | Base 0x%016llX | AllocBase 0x%016llX | %s | %s%s | Diff [%s]: %zu chg (%zu new, %zu wiped)",
                      g_selected_region + 1, g_regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      static_cast<unsigned long long>(reg.alloc_base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      det_tag.c_str(),
                      dp.title.c_str(), chg_bytes, new_bytes, zeroed_bytes);
    }
    else
    {
        std::snprintf(info, sizeof(info),
                      "Reg %zu/%zu | Base 0x%016llX | AllocBase 0x%016llX | %s | %s%s | Showing 0x%llX..0x%llX of 0x%llX",
                      g_selected_region + 1, g_regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      static_cast<unsigned long long>(reg.alloc_base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      det_tag.c_str(),
                      static_cast<unsigned long long>(display_view_offset),
                      static_cast<unsigned long long>(display_view_offset + to_read),
                      static_cast<unsigned long long>(reg.size));
    }

    if (g_last_hex_info != info)
    {
        SetWindowTextA(g_lbl_hex_info, info);
        g_last_hex_info = info;
    }

    if (g_last_hex_dump != dump)
    {
        int first_line = static_cast<int>(SendMessageA(g_edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(g_edit_hex, WM_SETREDRAW, FALSE, 0);
        SetWindowTextA(g_edit_hex, dump.c_str());
        if (focus_line > 3)
        {
            SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(focus_line - 3));
        }
        else if (first_line > 0)
        {
            SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(first_line));
        }
        else
        {
            SendMessageA(g_edit_hex, EM_SETSEL, 0, 0);
            SendMessageA(g_edit_hex, EM_SCROLLCARET, 0, 0);
        }
        SendMessageA(g_edit_hex, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_edit_hex, nullptr, TRUE);
        g_last_hex_dump = dump;
    }
    else if (focus_line > 3)
    {
        int cur = static_cast<int>(SendMessageA(g_edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>((focus_line - 3) - cur));
    }
}

void update_triage_details_label(size_t reg_idx)
{
    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (reg_idx < g_process_diffs.size())
        {
            const auto &d = g_process_diffs[reg_idx];
            std::string kind_str = (d.kind == ProcessDiffKind::Appeared) ? "NEW" :
                                   (d.kind == ProcessDiffKind::Disappeared) ? "REMOVED" :
                                   (d.kind == ProcessDiffKind::ProtectionChg) ? "PROT_CHG" : "MODIFIED";
            std::string text = "Diff Details [" + kind_str + "]: 0x" + to_hex_string(d.base) + " (" + fmt_size_short(d.size) + ") | " + d.summary;
            SetWindowTextA(g_lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(g_lbl_triage_reasons, "Diff Details: Ready.");
        }
        return;
    }

    if (reg_idx >= g_regions.size())
    {
        SetWindowTextA(g_lbl_triage_reasons, "Details: Ready.");
        return;
    }
    const RegionInfo &reg = g_regions[reg_idx];

    const TriageFinding *match = nullptr;
    for (const auto &f : g_triage_report.findings)
    {
        if (f.region_index == reg_idx)
        {
            match = &f;
            break;
        }
    }

    if (match != nullptr && !match->reasons.empty())
    {
        std::string text = "Details [" + match->severity_label + " " + std::to_string(match->severity_score) + "]: ";
        for (size_t i = 0; i < match->reasons.size(); ++i)
        {
            text += match->reasons[i];
            if (i + 1 < match->reasons.size())
                text += " | ";
        }
        SetWindowTextA(g_lbl_triage_reasons, text.c_str());
    }
    else
    {
        std::string text = "Details [CLEAN 0]: Normal " + type_full(reg.type) + " memory (" +
                           prot_full(reg.protect) + "), AllocBase " + to_hex_string(reg.alloc_base);
        SetWindowTextA(g_lbl_triage_reasons, text.c_str());
    }
}

void populate_region_list()
{
    SendMessageA(g_list_regions, WM_SETREDRAW, FALSE, 0);
    SendMessageA(g_list_regions, LB_RESETCONTENT, 0, 0);
    g_visible_indices.clear();

    bool hits_only = (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);

    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (g_process_diffs.empty())
        {
            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No process diffs. Capture baseline (Ctrl+B), then diff (Ctrl+D)."));
        }
        else
        {
            for (size_t i = 0; i < g_process_diffs.size(); ++i)
            {
                const auto &d = g_process_diffs[i];
                std::string badge;
                switch (d.kind)
                {
                    case ProcessDiffKind::Appeared: badge = "[+NEW   ]"; break;
                    case ProcessDiffKind::Disappeared: badge = "[-FREED ]"; break;
                    case ProcessDiffKind::ProtectionChg: badge = "[!PROT  ]"; break;
                    case ProcessDiffKind::ContentChg: badge = "[~MODIF ]"; break;
                    default: badge = "[ UNCHG ]"; break;
                }

                char row[256];
                std::snprintf(row, sizeof(row), "%-9s %016llX %s %-4s %-8s %s",
                              badge.c_str(),
                              static_cast<unsigned long long>(d.base),
                              fmt_size_short(d.size).c_str(),
                              type_short(d.type).c_str(),
                              prot_short(d.new_protect ? d.new_protect : d.old_protect).c_str(),
                              d.summary.c_str());

                SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                g_visible_indices.push_back(i);
            }
        }
        SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_list_regions, nullptr, TRUE);
        return;
    }

    if (g_view_mode == ViewMode::TriageFindings)
    {
        for (size_t i = 0; i < g_triage_report.findings.size(); ++i)
        {
            const TriageFinding &f = g_triage_report.findings[i];
            if (f.region_index >= g_regions.size())
                continue;
            const RegionInfo &r = g_regions[f.region_index];

            if (f.severity_score < g_min_sev_filter)
                continue;
            if (g_hide_clean && f.severity_score == 0)
                continue;
            if (hits_only && r.hits.empty())
                continue;

            char sev_badge[32];
            std::snprintf(sev_badge, sizeof(sev_badge), "[%-4s %3d]", f.severity_label.c_str(), f.severity_score);

            std::string flg_str;
            for (const auto &flg : f.flags)
            {
                if (flg == "INJECTED_PE")
                    flg_str += "!PE ";
                else if (flg == "UNLINKED_MODULE")
                    flg_str += "!UNL ";
                else if (flg == "PRIVATE_RWX")
                    flg_str += "!RWX ";
                else if (flg == "WRITE_THEN_FLIP")
                    flg_str += "!FLIP ";
                else if (flg == "UNBACKED_EXEC")
                    flg_str += "!X ";
                else if (flg == "BEHAVIOR_UNPACK")
                    flg_str += "!UNPK ";
                else if (flg == "SLEEP_OBFUSCATION")
                    flg_str += "!SLP ";
            }
            if (flg_str.empty())
                flg_str = "      ";
            while (flg_str.size() < 14)
                flg_str.push_back(' ');

            std::string tag;
            if (!r.hits.empty())
            {
                tag += " [" + std::to_string(r.hits.size()) + "h]";
            }
            if (!r.snapshots.empty())
            {
                tag += " (" + std::to_string(r.snapshots.size()) + "s)";
            }

            char row[256];
            std::snprintf(row, sizeof(row), "%-11s %-14s %016llX %s %-4s %-4s%s",
                          sev_badge, flg_str.c_str(),
                          static_cast<unsigned long long>(f.base),
                          fmt_size_short(f.size).c_str(),
                          type_short(f.type).c_str(),
                          prot_short(f.protect).c_str(),
                          tag.c_str());

            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
            g_visible_indices.push_back(f.region_index);
        }
    }
    else
    {
        // ViewMode::MemoryMap
        for (size_t i = 0; i < g_regions.size(); ++i)
        {
            const RegionInfo &r = g_regions[i];
            if (hits_only && r.hits.empty())
                continue;

            // Find severity for filtering in map mode
            int sev = 0;
            for (const auto &f : g_triage_report.findings)
            {
                if (f.region_index == i)
                {
                    sev = f.severity_score;
                    break;
                }
            }

            if (sev < g_min_sev_filter)
                continue;
            if (g_hide_clean && sev == 0)
                continue;

            char row[256];
            std::string tag;
            if (!r.hits.empty())
            {
                char hbuf[48];
                if (r.hits_truncated)
                {
                    std::snprintf(hbuf, sizeof(hbuf), " [%zu+ hits (capped)]", r.hits.size());
                }
                else
                {
                    std::snprintf(hbuf, sizeof(hbuf), " [%zu hit%s]", r.hits.size(), r.hits.size() == 1 ? "" : "s");
                }
                tag += hbuf;
            }
            if (!r.snapshots.empty())
            {
                char sbuf[32];
                std::snprintf(sbuf, sizeof(sbuf), " (%zu snap%s)", r.snapshots.size(), r.snapshots.size() == 1 ? "" : "s");
                tag += sbuf;
            }

            std::string flag = "    ";
            if (r.is_pe_in_private)
                flag = "!PE ";
            else if (r.private_rwx)
                flag = "!RWX";
            else if (r.write_then_flip)
                flag = "!FLP";
            else if (r.is_unlinked_image)
                flag = "!UNL";
            else if (r.is_unbacked_exec)
                flag = "!X  ";

            std::snprintf(row, sizeof(row), "%016llX %s %s %s %s%s",
                          static_cast<unsigned long long>(r.base),
                          fmt_size_short(r.size).c_str(),
                          type_short(r.type).c_str(),
                          prot_short(r.protect).c_str(),
                          flag.c_str(),
                          tag.c_str());

            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
            g_visible_indices.push_back(i);
        }
    }

    SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list_regions, nullptr, TRUE);
}

void select_region_in_ui(size_t region_idx, SIZE_T view_offset, SIZE_T focus_offset)
{
    if (region_idx >= g_regions.size())
        return;
    g_selected_region = region_idx;
    g_has_selection = true;
    g_view_offset = view_offset;

    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis)
    {
        if (g_visible_indices[vis] == region_idx)
        {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    update_diff_combo();
    invalidate_hex_cache();
    display_selected_region(focus_offset);
    update_triage_details_label(region_idx);
}

// Visual Triage List Item Drawing Handler
void draw_region_list_item(DRAWITEMSTRUCT *dis)
{
    if (dis->itemID == static_cast<UINT>(-1))
        return;

    const ThemeColors &tc = get_current_theme();
    size_t vis_idx = static_cast<size_t>(dis->itemID);

    if (g_visible_indices.empty() || vis_idx >= g_visible_indices.size())
    {
        HDC hdc = dis->hDC;
        HBRUSH hbr = CreateSolidBrush(tc.bg_control);
        FillRect(hdc, &dis->rcItem, hbr);
        DeleteObject(hbr);

        char buf[256] = {};
        SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(buf));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, tc.text_muted);
        HGDIOBJ old_font = SelectObject(hdc, g_mono_font);
        RECT text_rc = dis->rcItem;
        text_rc.left += 6;
        DrawTextA(hdc, buf, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, old_font);
        return;
    }

    size_t reg_idx = g_visible_indices[vis_idx];

    bool is_selected = (dis->itemState & ODS_SELECTED) != 0;

    COLORREF bg_color = tc.row_image_bg;
    COLORREF text_color = tc.row_image_text;

    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (reg_idx < g_process_diffs.size())
        {
            const auto &d = g_process_diffs[reg_idx];
            switch (d.kind)
            {
                case ProcessDiffKind::Appeared:
                    bg_color = tc.row_diff_new_bg;
                    text_color = tc.row_diff_new_text;
                    break;
                case ProcessDiffKind::ProtectionChg:
                    bg_color = tc.row_diff_chg_bg;
                    text_color = tc.row_diff_chg_text;
                    break;
                case ProcessDiffKind::ContentChg:
                    bg_color = tc.row_diff_mod_bg;
                    text_color = tc.row_diff_mod_text;
                    break;
                case ProcessDiffKind::Disappeared:
                    bg_color = tc.row_diff_del_bg;
                    text_color = tc.row_diff_del_text;
                    break;
                default:
                    break;
            }
        }
    }
    else
    {
        if (reg_idx >= g_regions.size())
            return;
        const RegionInfo &reg = g_regions[reg_idx];

        // Apply highlight colors based on region threat indicators
        if (reg.is_pe_in_private)
        {
            bg_color = tc.row_pe_bg;
            text_color = tc.row_pe_text;
        }
        else if (reg.private_rwx)
        {
            bg_color = tc.row_rwx_bg;
            text_color = tc.row_rwx_text;
        }
        else if (reg.write_then_flip)
        {
            bg_color = tc.row_flip_bg;
            text_color = tc.row_flip_text;
        }
        else if (reg.is_unlinked_image)
        {
            bg_color = tc.row_unlinked_bg;
            text_color = tc.row_unlinked_text;
        }
        else if (reg.is_unbacked_exec)
        {
            bg_color = tc.row_unbacked_bg;
            text_color = tc.row_unbacked_text;
        }
        else if (reg.type == MEM_PRIVATE)
        {
            bg_color = tc.row_priv_bg;
            text_color = tc.row_priv_text;
        }
        else if (reg.type == MEM_MAPPED)
        {
            bg_color = tc.row_mapped_bg;
            text_color = tc.row_mapped_text;
        }
    }

    if (is_selected)
    {
        bg_color = tc.row_sel_bg;
        text_color = tc.row_sel_text;
    }

    HDC hdc = dis->hDC;
    HBRUSH hbr = CreateSolidBrush(bg_color);
    FillRect(hdc, &dis->rcItem, hbr);
    DeleteObject(hbr);

    char buf[256] = {};
    SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(buf));

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text_color);
    HGDIOBJ old_font = SelectObject(hdc, g_mono_font);

    RECT text_rc = dis->rcItem;
    text_rc.left += 6; // Left margin padding
    DrawTextA(hdc, buf, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, old_font);
}

enum class WorkerTaskType
{
    MemoryMapScan = 0,
    Triage = 1
};

struct WorkerTask
{
    HWND hwnd;
    DWORD pid;
    std::string pid_label;
    Pattern pat;
    bool use_pattern;
    WorkerTaskType task_type;
};

struct WorkerResult
{
    WorkerTaskType task_type;
    DWORD pid;
    std::string pid_label;
    Pattern pat;
    bool use_pattern;
    bool success;
    DWORD error_code;
    std::string error_msg;
    std::vector<RegionInfo> regions;
    TriageReport report;
    SIZE_T total_bytes;
    SIZE_T total_hits;
    size_t regions_with_hits;
};

static HANDLE g_h_worker_thread = nullptr;
static std::atomic<bool> g_scan_abort{false};

DWORD WINAPI WorkerThreadProc(LPVOID param)
{
    WorkerTask *task = reinterpret_cast<WorkerTask *>(param);
    WorkerResult *res = new WorkerResult();
    res->task_type = task->task_type;
    res->pid = task->pid;
    res->pid_label = task->pid_label;
    res->pat = task->pat;
    res->use_pattern = task->use_pattern;
    res->success = false;
    res->error_code = 0;
    res->total_bytes = 0;
    res->total_hits = 0;
    res->regions_with_hits = 0;

    HWND hwnd = task->hwnd;
    delete task;

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, res->pid);
    if (proc == nullptr)
    {
        res->error_code = GetLastError();
        res->error_msg = format_win32_error(res->error_code);
        if (!PostMessageA(hwnd, (res->task_type == WorkerTaskType::Triage) ? WM_TRIAGE_COMPLETE : WM_SCAN_COMPLETE,
                          FALSE, reinterpret_cast<LPARAM>(res)))
        {
            delete res;
        }
        return 0;
    }

    if (res->task_type == WorkerTaskType::Triage)
    {
        std::string err;
        if (!query_process_regions(proc, res->regions, err))
        {
            res->error_code = GetLastError();
            res->error_msg = err.empty() ? format_win32_error(res->error_code) : err;
            CloseHandle(proc);
            if (!PostMessageA(hwnd, WM_TRIAGE_COMPLETE, FALSE, reinterpret_cast<LPARAM>(res)))
            {
                delete res;
            }
            return 0;
        }

        auto triage_cb = [](SIZE_T cur, SIZE_T tot, void *u)
        {
            HWND h = reinterpret_cast<HWND>(u);
            PostMessageA(h, WM_SCAN_PROGRESS, cur, tot);
        };

        res->report = run_process_triage(proc, res->pid, res->regions, &g_scan_abort, triage_cb, hwnd);
        CloseHandle(proc);

        if (g_scan_abort.load(std::memory_order_relaxed))
        {
            delete res;
            return 0;
        }

        res->success = true;
        if (!PostMessageA(hwnd, WM_TRIAGE_COMPLETE, TRUE, reinterpret_cast<LPARAM>(res)))
        {
            delete res;
        }
        return 0;
    }

    // MemoryMapScan (Load / Search)
    std::vector<uint8_t> chunk_buf(CLI_CHUNK_SIZE);
    std::vector<SIZE_T> chunk_hits;
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T last_progress_bytes = 0;

    while (!g_scan_abort.load(std::memory_order_relaxed))
    {
        std::memset(&mbi, 0, sizeof(mbi));
        SIZE_T q = VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (q == 0)
            break;

        uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T region_size = mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_NOACCESS) == 0 &&
            (mbi.Protect & PAGE_GUARD) == 0)
        {

            RegionInfo reg;
            reg.base = region_base;
            reg.size = region_size;
            reg.type = mbi.Type;
            reg.protect = mbi.Protect;
            reg.alloc_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            reg.alloc_protect = mbi.AllocationProtect;
            reg.is_unbacked_exec = is_unbacked_exec(mbi.Type, mbi.Protect);
            reg.private_rwx = is_private_rwx(mbi.Type, mbi.Protect);
            reg.write_then_flip = is_write_then_flip(mbi.AllocationProtect, mbi.Protect);

            SIZE_T offset = 0;
            SIZE_T overlap = (res->use_pattern && !res->pat.bytes.empty()) ? (res->pat.bytes.size() - 1) : 0;
            SIZE_T prev_overlap = 0;
            bool pe_found = false;

            while (offset < region_size && !g_scan_abort.load(std::memory_order_relaxed))
            {
                SIZE_T rem = region_size - offset;
                SIZE_T to_read = (rem < CLI_CHUNK_SIZE) ? rem : CLI_CHUNK_SIZE;
                chunk_hits.clear();

                bool truncated = false;
                SIZE_T bytes_read = scan_chunk_robust(proc, region_base + offset, to_read,
                                                      res->use_pattern ? &res->pat : nullptr,
                                                      chunk_buf, offset, chunk_hits,
                                                      MAX_HITS_PER_REGION - reg.hits.size(),
                                                      truncated, pe_found);

                if (truncated)
                {
                    reg.hits_truncated = true;
                }

                if (mbi.Type == MEM_PRIVATE && pe_found)
                {
                    reg.is_pe_in_private = true;
                }

                if (bytes_read > prev_overlap)
                {
                    res->total_bytes += (bytes_read - prev_overlap);
                }

                for (SIZE_T h : chunk_hits)
                {
                    if (reg.hits.size() < MAX_HITS_PER_REGION)
                    {
                        reg.hits.push_back(h);
                    }
                    else
                    {
                        reg.hits_truncated = true;
                        break;
                    }
                }

                if (offset + to_read >= region_size)
                    break;
                if (bytes_read <= overlap)
                {
                    offset += to_read;
                    prev_overlap = 0;
                }
                else
                {
                    offset += (bytes_read - overlap);
                    prev_overlap = overlap;
                }
            }

            if (!reg.hits.empty())
            {
                res->total_hits += reg.hits.size();
                res->regions_with_hits += 1;
            }

            res->regions.push_back(std::move(reg));

            if (res->total_bytes - last_progress_bytes >= 8 * 1024 * 1024)
            {
                last_progress_bytes = res->total_bytes;
                PostMessageA(hwnd, WM_SCAN_PROGRESS,
                             static_cast<WPARAM>(res->total_bytes / (1024 * 1024)),
                             static_cast<LPARAM>(res->total_hits));
            }
        }

        if (region_size == 0)
            break;
        uintptr_t next = region_base + region_size;
        if (next <= addr)
            break;
        addr = next;
    }

    if (!g_scan_abort.load(std::memory_order_relaxed))
    {
        // Automatically evaluate triage findings on the loaded regions
        res->report = run_process_triage(proc, res->pid, res->regions, &g_scan_abort, nullptr, nullptr);
    }

    CloseHandle(proc);

    if (g_scan_abort.load(std::memory_order_relaxed))
    {
        delete res;
        return 0;
    }

    res->success = true;
    if (!PostMessageA(hwnd, WM_SCAN_COMPLETE, TRUE, reinterpret_cast<LPARAM>(res)))
    {
        delete res;
    }
    return 0;
}

void enable_ui_controls(BOOL enable)
{
    EnableWindow(g_btn_load, enable);
    EnableWindow(g_btn_triage, enable);
    EnableWindow(g_btn_search, enable);
    EnableWindow(g_edit_pid, enable);
    EnableWindow(g_edit_pattern, enable);
}

void on_worker_completed(WorkerResult *res)
{
    if (g_h_worker_thread != nullptr)
    {
        WaitForSingleObject(g_h_worker_thread, 100);
        CloseHandle(g_h_worker_thread);
        g_h_worker_thread = nullptr;
    }

    enable_ui_controls(TRUE);

    if (!res->success)
    {
        std::string msg = "Cannot open PID " + std::to_string(res->pid) + ": " + res->error_msg;
        if (res->error_code == ERROR_ACCESS_DENIED)
        {
            msg += "\n\nRun elevated or inspect a non-protected process.";
        }
        set_status("[ERROR] " + msg);
        MessageBoxA(g_hwnd_main, msg.c_str(), "Deadeye Scanner", MB_ICONERROR);
        return;
    }

    close_target_proc();
    invalidate_hex_cache();

    g_regions = std::move(res->regions);
    g_triage_report = std::move(res->report);
    g_current_pid = res->pid;
    g_current_pid_label = res->pid_label;
    g_active_pattern = res->pat;
    g_has_pattern = res->use_pattern;
    g_has_selection = false;
    g_view_offset = 0;

    EnableWindow(g_btn_next_hit, (g_has_pattern && res->total_hits > 0) ? TRUE : FALSE);

    if (res->task_type == WorkerTaskType::Triage)
    {
        g_view_mode = ViewMode::TriageFindings;
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);
    }

    populate_region_list();

    // Select the first finding or region
    if (!g_visible_indices.empty())
    {
        select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
    }
    else
    {
        update_diff_combo();
        display_selected_region(static_cast<SIZE_T>(-1));
        SetWindowTextA(g_lbl_triage_reasons, "Details: Ready.");
    }

    // Calculate threat breakdown
    size_t crit = 0, high = 0, med = 0, low = 0;
    for (const auto &f : g_triage_report.findings)
    {
        if (f.severity_label == "CRIT")
            crit++;
        else if (f.severity_label == "HIGH")
            high++;
        else if (f.severity_label == "MED")
            med++;
        else if (f.severity_label == "LOW")
            low++;
    }

    double mb = static_cast<double>(res->total_bytes) / (1024.0 * 1024.0);
    char status[320];
    if (res->task_type == WorkerTaskType::Triage)
    {
        std::snprintf(status, sizeof(status),
                      "Triage complete for PID %lu (%s): %zu regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW%s",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      g_regions.size(), crit, high, med, low,
                      res->report.wow64_unsupported ? " (WOW64: PEB unlinked check unsupported)" : "");
    }
    else if (g_has_pattern)
    {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): %zu regions, %.2f MB scanned | %zu hit(s) in %zu region(s) | Triage: %zu Suspicious",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      g_regions.size(), mb, res->total_hits, res->regions_with_hits,
                      crit + high + med);
    }
    else
    {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): Loaded %zu committed regions (%.2f MB) | Triage: %zu Suspicious (%zu CRIT, %zu HIGH)",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      g_regions.size(), mb, crit + high + med, crit, high);
    }
    set_status(status);
}

void start_worker_task(WorkerTaskType task_type, bool require_pattern)
{
    if (g_h_worker_thread != nullptr)
    {
        DWORD exit_code = 0;
        if (GetExitCodeThread(g_h_worker_thread, &exit_code) && exit_code == STILL_ACTIVE)
        {
            set_status("Operation already in progress. Please wait...");
            return;
        }
        CloseHandle(g_h_worker_thread);
        g_h_worker_thread = nullptr;
    }

    char pid_buf[64] = {};
    char pat_buf[512] = {};
    GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
    GetWindowTextA(g_edit_pattern, pat_buf, sizeof(pat_buf));

    std::string pid_str(pid_buf);
    std::string pat_str(pat_buf);

    DWORD pid = 0;
    if (!parse_pid_string(pid_str, pid))
    {
        MessageBoxA(g_hwnd_main, "Enter a valid numeric PID.", "Invalid Target PID", MB_ICONWARNING);
        return;
    }

    bool trim_empty = true;
    for (size_t i = 0; i < pat_str.size(); ++i)
    {
        if (!std::isspace(static_cast<unsigned char>(pat_str[i])))
        {
            trim_empty = false;
            break;
        }
    }

    if (require_pattern && trim_empty)
    {
        MessageBoxA(g_hwnd_main, "Enter a hex pattern to search (e.g. '4D 5A ?? 00'), or click 'Load' / 'Triage'.",
                    "Pattern Required", MB_ICONINFORMATION);
        return;
    }

    Pattern pat;
    bool use_pattern = !trim_empty && (task_type == WorkerTaskType::MemoryMapScan);
    if (use_pattern)
    {
        std::string err;
        if (!parse_pattern(pat_str, pat, err))
        {
            MessageBoxA(g_hwnd_main, err.c_str(), "Invalid Hex Pattern", MB_ICONWARNING);
            return;
        }
    }

    close_target_proc();
    invalidate_hex_cache();
    enable_ui_controls(FALSE);
    EnableWindow(g_btn_next_hit, FALSE);

    if (task_type == WorkerTaskType::Triage)
    {
        set_status("Triaging process memory in background...");
    }
    else
    {
        set_status(use_pattern ? "Scanning process memory in background..." : "Loading process memory map in background...");
    }

    WorkerTask *task = new WorkerTask();
    task->hwnd = g_hwnd_main;
    task->pid = pid;
    task->pid_label = pid_str;
    task->pat = pat;
    task->use_pattern = use_pattern;
    task->task_type = task_type;

    g_scan_abort.store(false, std::memory_order_relaxed);
    g_h_worker_thread = CreateThread(nullptr, 0, WorkerThreadProc, task, 0, nullptr);
    if (g_h_worker_thread == nullptr)
    {
        DWORD err = GetLastError();
        delete task;
        enable_ui_controls(TRUE);
        set_status("[ERROR] CreateThread failed: " + format_win32_error(err));
        MessageBoxA(g_hwnd_main, "Failed to launch background worker thread.", "Thread Error", MB_ICONERROR);
    }
}

void on_next_hit()
{
    if (!g_has_pattern || g_regions.empty())
        return;

    size_t total_hits = 0;
    for (size_t i = 0; i < g_regions.size(); ++i)
    {
        total_hits += g_regions[i].hits.size();
    }
    if (total_hits == 0)
        return;

    g_hit_cursor_index += 1;
    if (g_hit_cursor_region >= g_regions.size() ||
        g_hit_cursor_index >= g_regions[g_hit_cursor_region].hits.size())
    {
        g_hit_cursor_index = 0;
        size_t r = (g_hit_cursor_region + 1) % g_regions.size();
        while (g_regions[r].hits.empty())
        {
            r = (r + 1) % g_regions.size();
        }
        g_hit_cursor_region = r;
    }

    SIZE_T hit_off = g_regions[g_hit_cursor_region].hits[g_hit_cursor_index];
    SIZE_T page_off = (hit_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
    select_region_in_ui(g_hit_cursor_region, page_off, hit_off);

    char status[160];
    std::snprintf(status, sizeof(status),
                  "Hit at 0x%016llX (region %zu, hit %zu/%zu in region)",
                  static_cast<unsigned long long>(g_regions[g_hit_cursor_region].base + hit_off),
                  g_hit_cursor_region + 1,
                  g_hit_cursor_index + 1,
                  g_regions[g_hit_cursor_region].hits.size());
    set_status(status);
}

void on_export_json()
{
    if (g_triage_report.findings.empty() && g_regions.empty())
    {
        MessageBoxA(g_hwnd_main, "Please Load or Triage a target process before exporting findings.",
                    "No Data", MB_ICONINFORMATION);
        return;
    }

    if (g_triage_report.findings.empty())
    {
        HANDLE proc = get_or_open_target_proc(g_current_pid);
        if (proc != nullptr)
        {
            g_triage_report = run_process_triage(proc, g_current_pid, g_regions, nullptr, nullptr, nullptr);
        }
    }

    char filename_buf[MAX_PATH] = {};
    std::snprintf(filename_buf, sizeof(filename_buf), "deadeye_triage_pid_%lu.json",
                  static_cast<unsigned long>(g_current_pid));

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename_buf;
    ofn.nMaxFile = sizeof(filename_buf);
    ofn.lpstrTitle = "Export Triage Report (JSON)";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "json";

    if (GetSaveFileNameA(&ofn))
    {
        std::string json_data = export_triage_json(g_triage_report);
        FILE *fp = std::fopen(filename_buf, "wb");
        if (fp != nullptr)
        {
            std::fwrite(json_data.data(), 1, json_data.size(), fp);
            std::fclose(fp);
            char status[320];
            std::snprintf(status, sizeof(status), "Exported %zu triage findings to %s",
                          g_triage_report.findings.size(), filename_buf);
            set_status(status);
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Failed to write JSON file to chosen location.",
                        "Export Error", MB_ICONERROR);
        }
    }
}

// ============================================================================
// Modern Flat / Fluent Button Rendering Engine
// ============================================================================

enum class ModernButtonStyle {
    Standard,
    Primary, // "Triage"
    Accent   // "Export JSON"
};

struct ModernButtonData {
    WNDPROC old_proc = nullptr;
    ModernButtonStyle style = ModernButtonStyle::Standard;
    bool is_hovered = false;
};

static const char* const DEADEYE_BTN_PROP = "DEADEYE_MODERN_BTN_DATA";

LRESULT CALLBACK ModernButtonSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    ModernButtonData* data = reinterpret_cast<ModernButtonData*>(GetPropA(hwnd, DEADEYE_BTN_PROP));
    if (data == nullptr) {
        return DefWindowProcA(hwnd, msg, wp, lp);
    }

    switch (msg) {
    case WM_MOUSEMOVE: {
        if (!data->is_hovered) {
            data->is_hovered = true;
            TRACKMOUSEEVENT tme = {};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hwnd;
            TrackMouseEvent(&tme);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        break;
    }

    case WM_MOUSELEAVE: {
        data->is_hovered = false;
        InvalidateRect(hwnd, nullptr, FALSE);
        break;
    }

    case WM_SETCURSOR: {
        if (IsWindowEnabled(hwnd)) {
            SetCursor(LoadCursorA(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    }

    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_CAPTURECHANGED:
    case WM_ENABLE:
    case WM_SETFOCUS:
    case WM_KILLFOCUS: {
        InvalidateRect(hwnd, nullptr, FALSE);
        break;
    }

    case WM_NCDESTROY: {
        WNDPROC old_proc = data->old_proc;
        RemovePropA(hwnd, DEADEYE_BTN_PROP);
        delete data;
        return CallWindowProcA(old_proc, hwnd, msg, wp, lp);
    }

    case WM_ERASEBKGND:
        return 1; // Handled in double-buffered WM_PAINT

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w <= 0 || h <= 0) {
            EndPaint(hwnd, &ps);
            return 0;
        }

        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, w, h);
        HGDIOBJ oldBmp = SelectObject(memDC, memBmp);

        // Pre-fill corners with parent window background color
        const ThemeColors& tc = get_current_theme();
        HBRUSH brParent = CreateSolidBrush(tc.bg_window);
        FillRect(memDC, &rc, brParent);
        DeleteObject(brParent);

        bool is_enabled = (IsWindowEnabled(hwnd) != FALSE);
        bool is_pressed = ((SendMessageA(hwnd, BM_GETSTATE, 0, 0) & BST_PUSHED) != 0);
        bool is_hovered = (data->is_hovered && is_enabled);
        bool is_focused = (GetFocus() == hwnd && is_enabled);
        bool is_dark    = (g_theme == AppTheme::Dark);

        COLORREF bg_color, border_color, text_color;

        if (data->style == ModernButtonStyle::Primary) {
            // Modern Primary Accent ("Triage") - High-visibility cobalt / azure
            if (!is_enabled) {
                bg_color     = is_dark ? RGB(45, 55, 70)    : RGB(195, 218, 242);
                border_color = is_dark ? RGB(50, 60, 75)    : RGB(180, 205, 230);
                text_color   = is_dark ? RGB(110, 120, 135) : RGB(255, 255, 255);
            } else if (is_pressed) {
                bg_color     = is_dark ? RGB(0, 90, 175)    : RGB(0, 84, 153);
                border_color = is_dark ? RGB(0, 80, 160)    : RGB(0, 70, 130);
                text_color   = RGB(255, 255, 255);
            } else if (is_hovered) {
                bg_color     = is_dark ? RGB(24, 138, 248)  : RGB(16, 110, 190);
                border_color = is_dark ? RGB(50, 155, 255)  : RGB(10, 95, 165);
                text_color   = RGB(255, 255, 255);
            } else {
                bg_color     = is_dark ? RGB(0, 120, 215)   : RGB(0, 102, 204);
                border_color = is_focused ? (is_dark ? RGB(100, 180, 255) : RGB(0, 60, 140))
                                          : (is_dark ? RGB(20, 130, 225)  : RGB(0, 90, 185));
                text_color   = RGB(255, 255, 255);
            }
        } else if (data->style == ModernButtonStyle::Accent) {
            // Modern Emerald Accent ("Export JSON")
            if (!is_enabled) {
                bg_color     = is_dark ? RGB(35, 50, 40)    : RGB(195, 225, 205);
                border_color = is_dark ? RGB(40, 55, 45)    : RGB(180, 210, 190);
                text_color   = is_dark ? RGB(100, 120, 105) : RGB(255, 255, 255);
            } else if (is_pressed) {
                bg_color     = is_dark ? RGB(10, 90, 48)    : RGB(11, 85, 45);
                border_color = is_dark ? RGB(8, 75, 40)     : RGB(9, 70, 36);
                text_color   = RGB(255, 255, 255);
            } else if (is_hovered) {
                bg_color     = is_dark ? RGB(20, 145, 82)   : RGB(18, 138, 72);
                border_color = is_dark ? RGB(25, 160, 92)   : RGB(14, 120, 62);
                text_color   = RGB(255, 255, 255);
            } else {
                bg_color     = is_dark ? RGB(16, 124, 65)   : RGB(14, 115, 60);
                border_color = is_focused ? (is_dark ? RGB(80, 220, 140) : RGB(8, 80, 40))
                                          : (is_dark ? RGB(20, 135, 75)  : RGB(12, 100, 52));
                text_color   = RGB(255, 255, 255);
            }
        } else {
            // Modern Flat Card Pushbuttons (Load, Search, Next Hit, + Snap, Clear, Navigation)
            if (!is_enabled) {
                bg_color     = is_dark ? RGB(38, 38, 42)    : RGB(244, 245, 247);
                border_color = is_dark ? RGB(50, 50, 55)    : RGB(225, 228, 233);
                text_color   = is_dark ? RGB(100, 100, 105) : RGB(165, 170, 180);
            } else if (is_pressed) {
                bg_color     = is_dark ? RGB(32, 32, 35)    : RGB(220, 224, 230);
                border_color = is_dark ? RGB(75, 75, 82)    : RGB(170, 175, 185);
                text_color   = is_dark ? RGB(255, 255, 255) : RGB(15, 23, 42);
            } else if (is_hovered) {
                bg_color     = is_dark ? RGB(54, 54, 60)    : RGB(238, 242, 246);
                border_color = is_dark ? RGB(95, 95, 105)   : RGB(160, 168, 180);
                text_color   = is_dark ? RGB(255, 255, 255) : RGB(15, 23, 42);
            } else {
                bg_color     = is_dark ? RGB(45, 45, 50)    : RGB(255, 255, 255);
                border_color = is_focused ? (is_dark ? RGB(100, 160, 240) : RGB(0, 120, 215))
                                          : (is_dark ? RGB(70, 70, 78)    : RGB(205, 210, 218));
                text_color   = is_dark ? RGB(225, 225, 230) : RGB(30, 41, 59);
            }
        }

        // Draw modern rounded rectangle
        HBRUSH brBtn = CreateSolidBrush(bg_color);
        HPEN penBorder = CreatePen(PS_SOLID, 1, border_color);
        HGDIOBJ oldBrush = SelectObject(memDC, brBtn);
        HGDIOBJ oldPen = SelectObject(memDC, penBorder);

        RoundRect(memDC, rc.left, rc.top, rc.right, rc.bottom, 6, 6);

        SelectObject(memDC, oldPen);
        SelectObject(memDC, oldBrush);
        DeleteObject(penBorder);
        DeleteObject(brBtn);

        // Fetch button text
        char text_buf[128] = {};
        GetWindowTextA(hwnd, text_buf, sizeof(text_buf));

        SetBkMode(memDC, TRANSPARENT);
        SetTextColor(memDC, text_color);
        HFONT btn_font = (data->style == ModernButtonStyle::Primary) ? g_ui_font_bold : g_ui_font;
        HGDIOBJ oldFont = SelectObject(memDC, btn_font);

        RECT text_rc = rc;
        if (is_pressed) {
            text_rc.top  += 1;
            text_rc.left += 1;
        }
        DrawTextA(memDC, text_buf, -1, &text_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        BitBlt(hdc, 0, 0, w, h, memDC, 0, 0, SRCCOPY);

        SelectObject(memDC, oldFont);
        SelectObject(memDC, oldBmp);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    }

    return CallWindowProcA(data->old_proc, hwnd, msg, wp, lp);
}

void make_button_modern(HWND btn, ModernButtonStyle style) {
    if (btn == nullptr) return;
    ModernButtonData* existing = reinterpret_cast<ModernButtonData*>(GetPropA(btn, DEADEYE_BTN_PROP));
    if (existing != nullptr) {
        existing->style = style;
        return;
    }
    ModernButtonData* data = new ModernButtonData();
    data->style = style;
    data->is_hovered = false;
    data->old_proc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrA(btn, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ModernButtonSubclassProc))
    );
    SetPropA(btn, DEADEYE_BTN_PROP, reinterpret_cast<HANDLE>(data));
}

void copy_text_to_clipboard(HWND hwnd, const std::string &text)
{
    if (!OpenClipboard(hwnd))
        return;
    EmptyClipboard();
    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hGlob)
    {
        char *p = static_cast<char *>(GlobalLock(hGlob));
        if (p)
        {
            std::memcpy(p, text.c_str(), text.size() + 1);
            GlobalUnlock(hGlob);
            if (!SetClipboardData(CF_TEXT, hGlob))
            {
                GlobalFree(hGlob);
            }
        }
        else
        {
            GlobalFree(hGlob);
        }
    }
    CloseClipboard();
}

#include "tier1.inl"

HMENU create_application_menu()
{
    HMENU hMenuBar = CreateMenu();

    // 1. File Menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_TRIAGE, "Run Defensive &Triage\tCtrl+T");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXPORT_JSON, "&Export Triage JSON...\tCtrl+S");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);

    HMENU hThemeMenu = CreatePopupMenu();
    AppendMenuA(hThemeMenu, MF_STRING, IDM_FILE_THEME_LIGHT, "&Light Mode");
    AppendMenuA(hThemeMenu, MF_STRING, IDM_FILE_THEME_DARK, "&Dark Mode");
    AppendMenuA(hFileMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hThemeMenu), "&Theme");

    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "E&xit\tAlt+F4");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), "&File");

    // 2. Edit Menu
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_ADDR, "&Copy Region Address\tCtrl+C");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_HEX, "Copy &Hex Dump\tCtrl+Shift+C");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_PATTERN, "&Find Hex Pattern...\tCtrl+F");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_NEXT, "Find &Next Hit\tF3");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_GENERATE_YARA, "Generate &YARA Rule from Selection...\tCtrl+Y");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hEditMenu), "&Edit");

    // 3. View Menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_TRIAGE_FINDINGS, "&Triage Findings View\tCtrl+1");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MEMORY_MAP, "&Memory Map View\tCtrl+2");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_PROCESS_DIFF, "&Process Diff View\tCtrl+3");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_HIDE_CLEAN, "&Hide Clean Regions");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_HITS_ONLY, "&Hits Only Filter");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_REFRESH, "&Refresh Memory Walk\tF5");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hViewMenu), "&View");

    // 4. Diff Menu
    HMENU hDiffMenu = CreatePopupMenu();
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_CAPTURE_BASELINE, "Capture &Baseline Snapshot\tCtrl+B");
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_CAPTURE_CURRENT, "Compare with &Current (Diff)\tCtrl+D");
    AppendMenuA(hDiffMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_SAVE_SESSION, "&Save Diff Session to JSON...");
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_LOAD_SESSION, "&Load Diff Session from JSON...");
    AppendMenuA(hDiffMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_VIEW_STRINGS, "View Newly &Revealed Strings...\tCtrl+U");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDiffMenu), "&Diff");

    // 5. Timeline Menu
    HMENU hTimelineMenu = CreatePopupMenu();
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_SNAP, "&Take Snapshot\tCtrl+N");
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_CLEAR, "&Clear All Snapshots");
    AppendMenuA(hTimelineMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_HEARTBEAT, "&Live Memory Heartbeat (1s)");
    AppendMenuA(hTimelineMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_PREV_PAGE, "&Previous 64K Page\tPgUp");
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_NEXT_PAGE, "&Next 64K Page\tPgDn");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hTimelineMenu), "&Timeline");

    // 6. Help Menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_HEURISTICS, "&Defensive Heuristics Guide...");
    AppendMenuA(hHelpMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "&About Deadeye...");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelpMenu), "&Help");

    return hMenuBar;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_hwnd_main = hwnd;
        HINSTANCE hInst = GetModuleHandleA(nullptr);

        g_ui_font = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_ui_font_bold = CreateFontA(15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_mono_font = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        update_theme_brushes();

        const int M = 8, RH = 24;
        int x = M;

        // Row 1: Top Bar
        HWND lbl_pid = CreateWindowA("STATIC", "PID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 28, RH, hwnd, nullptr, hInst, nullptr);
        x += 30;

        g_edit_pid = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                   x, M, 64, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PID), hInst, nullptr);
        x += 68;

        g_btn_load = CreateWindowA("BUTTON", "Load",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 52, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_LOAD), hInst, nullptr);
        x += 56;

        g_btn_triage = CreateWindowA("BUTTON", "Triage",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     x, M, 62, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_TRIAGE), hInst, nullptr);
        x += 68;

        HWND lbl_pat = CreateWindowA("STATIC", "Search Hex:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 76, RH, hwnd, nullptr, hInst, nullptr);
        x += 78;

        g_edit_pattern = CreateWindowA("EDIT", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                       x, M, 220, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PATTERN), hInst, nullptr);
        x += 224;

        g_btn_search = CreateWindowA("BUTTON", "Search",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     x, M, 58, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SEARCH), hInst, nullptr);
        x += 62;

        g_btn_next_hit = CreateWindowA("BUTTON", "Next Hit",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                                       x, M, 66, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_HIT), hInst, nullptr);
        x += 70;

        g_chk_hits_only = CreateWindowA("BUTTON", "Hits only",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 78, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HITS_ONLY), hInst, nullptr);
        x += 82;

        g_chk_heartbeat = CreateWindowA("BUTTON", "Heartbeat (1s)",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 110, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HEARTBEAT), hInst, nullptr);
        x += 114;

        g_btn_diff_proc = CreateWindowA("BUTTON", "Diff Proc",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                        x, M, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_DIFF_PROC), hInst, nullptr);
        x += 78;

        g_btn_yara = CreateWindowA("BUTTON", "YARA Rule",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 78, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_YARA), hInst, nullptr);

        // Row 2: Filter Bar (Left side) & Hex Timeline Bar (Right side)
        int r2_y = M + RH + 6;

        g_combo_view_mode = CreateWindowA("COMBOBOX", "",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                          M, r2_y, 148, 120, hwnd, reinterpret_cast<HMENU>(ID_COMBO_VIEW_MODE), hInst, nullptr);
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Triage Findings"));
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Memory Map"));
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Process Diff"));
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);

        g_combo_min_sev = CreateWindowA("COMBOBOX", "",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                        M + 152, r2_y, 102, 140, hwnd, reinterpret_cast<HMENU>(ID_COMBO_MIN_SEV), hInst, nullptr);
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: All (0+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Low (10+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Med (25+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: High (50+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Crit (80+)"));
        SendMessageA(g_combo_min_sev, CB_SETCURSEL, 0, 0);

        g_chk_hide_clean = CreateWindowA("BUTTON", "Hide clean",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                         M + 258, r2_y, 84, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HIDE_CLEAN), hInst, nullptr);

        g_btn_export_json = CreateWindowA("BUTTON", "Export JSON",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          M + 346, r2_y, 88, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_EXPORT_JSON), hInst, nullptr);

        // Right side timeline header controls
        g_lbl_hex_info = CreateWindowA("STATIC", "Hex View",
                                       WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                       442, r2_y, 300, RH, hwnd, nullptr, hInst, nullptr);

        g_btn_snap = CreateWindowA("BUTTON", "+ Snap",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                   0, 0, 68, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SNAP), hInst, nullptr);
        g_combo_diff = CreateWindowA("COMBOBOX", "",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL | WS_DISABLED,
                                     0, 0, 142, 160, hwnd, reinterpret_cast<HMENU>(ID_COMBO_DIFF), hInst, nullptr);
        g_btn_clear_snaps = CreateWindowA("BUTTON", "Clear",
                                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                          0, 0, 50, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_CLEAR_SNAPS), hInst, nullptr);
        g_btn_prev_page = CreateWindowA("BUTTON", "< Prev 64K",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_PREV_PAGE), hInst, nullptr);
        g_btn_next_page = CreateWindowA("BUTTON", "Next 64K >",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_PAGE), hInst, nullptr);

        // Main Panes: Left Owner-Drawn ListBox & Right Hex Edit View
        g_list_regions = CreateWindowA("LISTBOX", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                           WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                                       M, 66, 434, 400, hwnd, reinterpret_cast<HMENU>(ID_LIST_REGIONS), hInst, nullptr);

        g_edit_hex = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                       WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                   442, 66, 500, 400, hwnd, reinterpret_cast<HMENU>(ID_EDIT_HEX), hInst, nullptr);
        SendMessageA(g_edit_hex, EM_SETLIMITTEXT, 0, 0);

        // Details label and Status bar
        g_lbl_triage_reasons = CreateWindowA("STATIC", "Details: Ready.",
                                             WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                             M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        g_lbl_status = CreateWindowA("STATIC", "Ready.",
                                     WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                     M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        HWND ui_items[] = {
            lbl_pid, g_edit_pid, g_btn_load, g_btn_triage, lbl_pat, g_edit_pattern, g_btn_search,
            g_btn_next_hit, g_chk_hits_only, g_chk_heartbeat, g_btn_diff_proc, g_btn_yara,
            g_combo_view_mode, g_combo_min_sev, g_chk_hide_clean, g_btn_export_json,
            g_lbl_hex_info, g_btn_snap, g_combo_diff, g_btn_clear_snaps,
            g_btn_prev_page, g_btn_next_page, g_lbl_triage_reasons, g_lbl_status};
        for (size_t i = 0; i < sizeof(ui_items) / sizeof(ui_items[0]); ++i)
        {
            SendMessageA(ui_items[i], WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }
        SendMessageA(g_edit_hex, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

        // Modernize all push buttons with sleek flat rounded styling and interactive hover effects
        make_button_modern(g_btn_triage, ModernButtonStyle::Primary);
        make_button_modern(g_btn_export_json, ModernButtonStyle::Accent);
        make_button_modern(g_btn_load, ModernButtonStyle::Standard);
        make_button_modern(g_btn_search, ModernButtonStyle::Standard);
        make_button_modern(g_btn_next_hit, ModernButtonStyle::Standard);
        make_button_modern(g_btn_snap, ModernButtonStyle::Standard);
        make_button_modern(g_btn_clear_snaps, ModernButtonStyle::Standard);
        make_button_modern(g_btn_prev_page, ModernButtonStyle::Standard);
        make_button_modern(g_btn_next_page, ModernButtonStyle::Standard);
        make_button_modern(g_btn_diff_proc, ModernButtonStyle::Accent);
        make_button_modern(g_btn_yara, ModernButtonStyle::Primary);

        // Attach application menu bar
        HMENU hMenu = create_application_menu();
        SetMenu(hwnd, hMenu);

        // Build global keyboard accelerators
        ACCEL accels[] = {
            { FCONTROL | FVIRTKEY, 'T', ID_BTN_TRIAGE },
            { FCONTROL | FVIRTKEY, 'S', ID_BTN_EXPORT_JSON },
            { FCONTROL | FVIRTKEY, 'F', IDM_EDIT_FIND_PATTERN },
            { FVIRTKEY, VK_F3, ID_BTN_NEXT_HIT },
            { FVIRTKEY, VK_F5, ID_BTN_LOAD },
            { FCONTROL | FVIRTKEY, 'C', IDM_EDIT_COPY_ADDR },
            { FCONTROL | FSHIFT | FVIRTKEY, 'C', IDM_EDIT_COPY_HEX },
            { FCONTROL | FVIRTKEY, 'N', ID_BTN_SNAP },
            { FCONTROL | FVIRTKEY, '1', IDM_VIEW_TRIAGE_FINDINGS },
            { FCONTROL | FVIRTKEY, '2', IDM_VIEW_MEMORY_MAP },
            { FCONTROL | FVIRTKEY, '3', IDM_VIEW_PROCESS_DIFF },
            { FCONTROL | FVIRTKEY, 'B', IDM_DIFF_CAPTURE_BASELINE },
            { FCONTROL | FVIRTKEY, 'D', IDM_DIFF_CAPTURE_CURRENT },
            { FCONTROL | FVIRTKEY, 'Y', ID_BTN_YARA },
            { FCONTROL | FVIRTKEY, 'U', IDM_DIFF_VIEW_STRINGS }
        };
        g_haccel = CreateAcceleratorTableA(accels, sizeof(accels) / sizeof(accels[0]));

        if (GetWindowTextLengthA(g_edit_pid) > 0)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_TRIAGE, 0);
        }
        else
        {
            set_status("Ready. Enter target PID and click 'Triage Findings'.");
        }
        return 0;
    }

    case WM_INITMENUPOPUP:
    {
        HMENU hMenu = reinterpret_cast<HMENU>(wp);
        CheckMenuItem(hMenu, IDM_FILE_THEME_LIGHT, (g_theme == AppTheme::Light) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_FILE_THEME_DARK, (g_theme == AppTheme::Dark) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_TRIAGE_FINDINGS, (g_view_mode == ViewMode::TriageFindings) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_MEMORY_MAP, (g_view_mode == ViewMode::MemoryMap) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_PROCESS_DIFF, (g_view_mode == ViewMode::ProcessDiff) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_HIDE_CLEAN, g_hide_clean ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_HITS_ONLY, (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_TIMELINE_HEARTBEAT, (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED) ? MF_CHECKED : MF_UNCHECKED);
        return 0;
    }

    case WM_MEASUREITEM:
    {
        MEASUREITEMSTRUCT *mis = reinterpret_cast<MEASUREITEMSTRUCT *>(lp);
        if (mis->CtlID == ID_LIST_REGIONS)
        {
            mis->itemHeight = 20; // Row height
            return TRUE;
        }
        break;
    }

    case WM_DRAWITEM:
    {
        DRAWITEMSTRUCT *dis = reinterpret_cast<DRAWITEMSTRUCT *>(lp);
        if (dis->CtlID == ID_LIST_REGIONS)
        {
            draw_region_list_item(dis);
            return TRUE;
        }
        break;
    }

    case WM_CTLCOLOREDIT:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        HWND hctl = reinterpret_cast<HWND>(lp);
        const ThemeColors &tc = get_current_theme();
        if (hctl == g_edit_hex)
        {
            SetTextColor(hdc, tc.text_normal);
            SetBkColor(hdc, tc.bg_control);
            return reinterpret_cast<INT_PTR>(g_br_control);
        }
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_window);
        return reinterpret_cast<INT_PTR>(g_br_window);
    }

    case WM_CTLCOLORLISTBOX:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
        return 1;
    }

    case WM_SIZE:
    {
        int w = LOWORD(lp);
        int h = HIWORD(lp);
        const int M = 8, RH = 24;

        int list_w = 434;
        if (w < 880)
            list_w = w / 2 - M;

        int right_x = M + list_w + M;
        int right_w = w - right_x - M;
        if (right_w < 120)
            right_w = 120;

        int r2_y = M + RH + 6;
        int pane_top = r2_y + RH + 6;
        int pane_h = h - pane_top - 46;
        if (pane_h < 60)
            pane_h = 60;

        int cur_r = w - M;
        int btn_next_x = cur_r - 74;
        cur_r -= 78;
        int btn_prev_x = cur_r - 74;
        cur_r -= 78;
        int btn_clr_x = cur_r - 50;
        cur_r -= 54;
        int combo_x = cur_r - 142;
        cur_r -= 146;
        int btn_snap_x = cur_r - 68;
        cur_r -= 72;
        int info_w = btn_snap_x - right_x - 6;
        if (info_w < 50)
            info_w = 50;

        MoveWindow(g_lbl_hex_info, right_x, r2_y, info_w, RH, TRUE);
        MoveWindow(g_btn_snap, btn_snap_x, r2_y, 68, RH, TRUE);
        MoveWindow(g_combo_diff, combo_x, r2_y, 142, 160, TRUE);
        MoveWindow(g_btn_clear_snaps, btn_clr_x, r2_y, 50, RH, TRUE);
        MoveWindow(g_btn_prev_page, btn_prev_x, r2_y, 74, RH, TRUE);
        MoveWindow(g_btn_next_page, btn_next_x, r2_y, 74, RH, TRUE);

        MoveWindow(g_list_regions, M, pane_top, list_w, pane_h, TRUE);
        MoveWindow(g_edit_hex, right_x, pane_top, right_w, pane_h, TRUE);

        MoveWindow(g_lbl_triage_reasons, M, h - 42, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
        MoveWindow(g_lbl_status, M, h - 22, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);

        if (id == ID_BTN_LOAD)
        {
            start_worker_task(WorkerTaskType::MemoryMapScan, false);
        }
        else if (id == ID_BTN_TRIAGE)
        {
            start_worker_task(WorkerTaskType::Triage, false);
        }
        else if (id == ID_BTN_SEARCH || id == IDOK)
        {
            if (GetFocus() == g_edit_pid)
            {
                start_worker_task(WorkerTaskType::Triage, false);
            }
            else
            {
                start_worker_task(WorkerTaskType::MemoryMapScan, true);
            }
        }
        else if (id == ID_BTN_NEXT_HIT)
        {
            on_next_hit();
        }
        else if (id == ID_BTN_EXPORT_JSON)
        {
            on_export_json();
        }
        else if (id == ID_COMBO_VIEW_MODE && code == CBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(g_combo_view_mode, CB_GETCURSEL, 0, 0);
            if (sel == 2)
                g_view_mode = ViewMode::ProcessDiff;
            else if (sel == 1)
                g_view_mode = ViewMode::MemoryMap;
            else
                g_view_mode = ViewMode::TriageFindings;

            populate_region_list();
            if (g_view_mode == ViewMode::ProcessDiff)
            {
                if (!g_visible_indices.empty())
                {
                    SendMessageA(g_list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(0);
                }
                else
                {
                    SetWindowTextA(g_lbl_triage_reasons, "Diff Details: No diffs. Click Diff Proc to compare.");
                }
            }
            else
            {
                if (!g_visible_indices.empty())
                {
                    select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
                }
                else
                {
                    g_has_selection = false;
                    update_diff_combo();
                    display_selected_region(static_cast<SIZE_T>(-1));
                    SetWindowTextA(g_lbl_triage_reasons, "Details: Ready.");
                }
            }
        }
        else if (id == ID_COMBO_MIN_SEV && code == CBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(g_combo_min_sev, CB_GETCURSEL, 0, 0);
            if (sel == 1)
                g_min_sev_filter = SEV_MIN_LOW;
            else if (sel == 2)
                g_min_sev_filter = SEV_MIN_MEDIUM;
            else if (sel == 3)
                g_min_sev_filter = SEV_MIN_HIGH;
            else if (sel == 4)
                g_min_sev_filter = SEV_MIN_CRITICAL;
            else
                g_min_sev_filter = 0;
            populate_region_list();
        }
        else if (id == ID_CHK_HIDE_CLEAN)
        {
            g_hide_clean = (SendMessageA(g_chk_hide_clean, BM_GETCHECK, 0, 0) == BST_CHECKED);
            populate_region_list();
        }
        else if (id == ID_CHK_HITS_ONLY)
        {
            populate_region_list();
            if (!g_visible_indices.empty())
            {
                select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
            }
            else
            {
                g_has_selection = false;
                update_diff_combo();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_LIST_REGIONS && code == LBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(g_list_regions, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && static_cast<size_t>(sel) < g_visible_indices.size())
            {
                size_t reg_idx = g_visible_indices[static_cast<size_t>(sel)];
                if (g_view_mode == ViewMode::ProcessDiff)
                {
                    if (reg_idx < g_process_diffs.size())
                    {
                        update_triage_details_label(reg_idx);
                        uintptr_t target_base = g_process_diffs[reg_idx].base;
                        for (size_t r = 0; r < g_regions.size(); ++r)
                        {
                            if (g_regions[r].base == target_base)
                            {
                                g_selected_region = r;
                                g_has_selection = true;
                                g_view_offset = 0;
                                display_selected_region(static_cast<SIZE_T>(-1));
                                break;
                            }
                        }
                    }
                }
                else
                {
                    if (reg_idx < g_regions.size())
                    {
                        SIZE_T first_hit = g_regions[reg_idx].hits.empty()
                                               ? static_cast<SIZE_T>(-1)
                                               : g_regions[reg_idx].hits[0];
                        SIZE_T page_off = (first_hit == static_cast<SIZE_T>(-1))
                                              ? 0
                                              : (first_hit / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                        g_selected_region = reg_idx;
                        g_has_selection = true;
                        g_view_offset = page_off;
                        display_selected_region(first_hit);
                        update_triage_details_label(reg_idx);
                    }
                }
            }
        }
        else if (id == ID_BTN_PREV_PAGE)
        {
            if (g_has_selection && g_view_offset >= VIEW_PAGE_SIZE)
            {
                g_view_offset -= VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_BTN_NEXT_PAGE)
        {
            if (g_has_selection && g_selected_region < g_regions.size() &&
                g_view_offset + VIEW_PAGE_SIZE < g_regions[g_selected_region].size)
            {
                g_view_offset += VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_BTN_SNAP)
        {
            on_take_snapshot();
        }
        else if (id == ID_BTN_CLEAR_SNAPS)
        {
            on_clear_snapshots();
        }
        else if (id == ID_COMBO_DIFF && code == CBN_SELCHANGE)
        {
            invalidate_hex_cache();
            display_selected_region(static_cast<SIZE_T>(-1));
        }
        else if (id == ID_CHK_HEARTBEAT)
        {
            bool checked = (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (checked)
            {
                if (g_has_selection && g_selected_region < g_regions.size())
                {
                    RegionInfo &reg = g_regions[g_selected_region];
                    if (reg.snapshots.empty())
                    {
                        on_take_snapshot();
                    }
                }
                SetTimer(hwnd, IDT_HEARTBEAT, 1000, nullptr);
                set_status("Heartbeat active (1s interval): Monitoring memory diff in real time...");
            }
            else
            {
                KillTimer(hwnd, IDT_HEARTBEAT);
                set_status("Heartbeat stopped.");
            }
        }
        else if (id == IDM_FILE_TRIAGE)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_TRIAGE, 0);
        }
        else if (id == IDM_FILE_EXPORT_JSON)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_EXPORT_JSON, 0);
        }
        else if (id == IDM_FILE_EXIT)
        {
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
        }
        else if (id == IDM_EDIT_COPY_ADDR)
        {
            HWND focused = GetFocus();
            if (focused == g_edit_hex)
            {
                DWORD sel_start = 0, sel_end = 0;
                SendMessageA(g_edit_hex, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start), reinterpret_cast<LPARAM>(&sel_end));
                if (sel_start != sel_end)
                {
                    SendMessageA(g_edit_hex, WM_COPY, 0, 0);
                    return 0;
                }
            }
            if (g_has_selection && g_selected_region < g_regions.size())
            {
                std::string addr_hex = to_hex_string(g_regions[g_selected_region].base);
                copy_text_to_clipboard(hwnd, addr_hex);
                set_status("Copied region address " + addr_hex + " to clipboard.");
            }
        }
        else if (id == IDM_EDIT_COPY_HEX)
        {
            int len = GetWindowTextLengthA(g_edit_hex);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(g_edit_hex, buf.data(), len + 1);
                copy_text_to_clipboard(hwnd, buf.data());
                set_status("Hex dump copied to clipboard (" + std::to_string(len) + " bytes).");
            }
        }
        else if (id == IDM_EDIT_FIND_PATTERN)
        {
            SetFocus(g_edit_pattern);
            SendMessageA(g_edit_pattern, EM_SETSEL, 0, -1);
        }
        else if (id == IDM_EDIT_FIND_NEXT)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_NEXT_HIT, 0);
        }
        else if (id == IDM_VIEW_TRIAGE_FINDINGS)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_VIEW_MEMORY_MAP)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 1, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_FILE_THEME_LIGHT)
        {
            apply_theme_switch(hwnd, AppTheme::Light);
        }
        else if (id == IDM_FILE_THEME_DARK)
        {
            apply_theme_switch(hwnd, AppTheme::Dark);
        }
        else if (id == IDM_VIEW_HIDE_CLEAN)
        {
            bool cur = (SendMessageA(g_chk_hide_clean, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(g_chk_hide_clean, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HIDE_CLEAN, 0);
        }
        else if (id == IDM_VIEW_HITS_ONLY)
        {
            bool cur = (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(g_chk_hits_only, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HITS_ONLY, 0);
        }
        else if (id == IDM_VIEW_REFRESH)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_LOAD, 0);
        }
        else if (id == IDM_TIMELINE_SNAP)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_SNAP, 0);
        }
        else if (id == IDM_TIMELINE_CLEAR)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_CLEAR_SNAPS, 0);
        }
        else if (id == IDM_TIMELINE_HEARTBEAT)
        {
            bool cur = (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(g_chk_heartbeat, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HEARTBEAT, 0);
        }
        else if (id == IDM_TIMELINE_PREV_PAGE)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_PREV_PAGE, 0);
        }
        else if (id == IDM_TIMELINE_NEXT_PAGE)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_NEXT_PAGE, 0);
        }
        else if (id == ID_BTN_DIFF_PROC)
        {
            on_capture_diff();
        }
        else if (id == ID_BTN_YARA || id == IDM_EDIT_GENERATE_YARA)
        {
            open_yara_dialog(hwnd);
        }
        else if (id == IDM_DIFF_CAPTURE_BASELINE)
        {
            on_capture_baseline();
        }
        else if (id == IDM_DIFF_CAPTURE_CURRENT)
        {
            on_capture_diff();
        }
        else if (id == IDM_DIFF_SAVE_SESSION)
        {
            on_save_diff_session();
        }
        else if (id == IDM_DIFF_LOAD_SESSION)
        {
            on_load_diff_session();
        }
        else if (id == IDM_DIFF_VIEW_STRINGS)
        {
            open_revealed_strings_dialog(hwnd);
        }
        else if (id == IDM_VIEW_PROCESS_DIFF)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 2, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_HELP_HEURISTICS)
        {
            std::string info =
                "[+50] INJECTED_PE:\n"
                "   MZ/PE header detected inside committed MEM_PRIVATE pages.\n"
                "   (Reflective DLL injection, process hollowing, unhooking)\n\n"
                "[+50] BEHAVIOR_UNPACK:\n"
                "   Memory flipped to executable with byte mutations or entropy drop.\n"
                "   (Payload unpacking, dynamically decoded shellcode)\n\n"
                "[+65] SLEEP_OBFUSCATION:\n"
                "   Region protection/entropy oscillates across heartbeat ticks.\n"
                "   (Encrypted at rest, decrypted while running)\n\n"
                "[+45] UNLINKED_MODULE:\n"
                "   MEM_IMAGE allocation missing from PEB InLoadOrderModuleList.\n"
                "   (DKOM evasion, stealth module unlinking)\n\n"
                "[+40] PRIVATE_RWX:\n"
                "   Committed MEM_PRIVATE page with PAGE_EXECUTE_READWRITE.\n"
                "   (Classic shellcode staging, JIT anomaly)\n\n"
                "[+35] WRITE_THEN_FLIP:\n"
                "   Allocated writable (PAGE_READWRITE), currently executable (PAGE_EXECUTE_READ).\n"
                "   (Evasive staged payload execution)\n\n"
                "[+25] UNBACKED_EXEC:\n"
                "   Executable memory not backed by an on-disk image file.\n\n"
                "Severity Scoring Thresholds:\n"
                "  * CRITICAL: Score >= 80\n"
                "  * HIGH:     Score >= 50\n"
                "  * MEDIUM:   Score >= 25\n"
                "  * LOW:      Score >= 10\n"
                "  * CLEAN:    Score = 0\n\n"
                "Note: Heartbeat polling interval is 1s; sub-second transitions may be missed.";
            MessageBoxA(hwnd, info.c_str(), "Deadeye Heuristics Reference", MB_OK | MB_ICONINFORMATION);
        }
        else if (id == IDM_HELP_ABOUT)
        {
            std::string about =
                "Deadeye v1.0\n"
                "Process Memory Triage Scanner & Real-Time Diff Timeline\n\n"
                "Built with C++17 & Native Win32 for defensive reverse engineering,\n"
                "malware analysis, and detection engineering.\n\n"
                "Repository: https://github.com/Winter0x11/Deadeye";
            MessageBoxA(hwnd, about.c_str(), "About Deadeye", MB_OK | MB_ICONINFORMATION);
        }
        return 0;
    }

    case WM_SCAN_PROGRESS:
    {
        SIZE_T cur = static_cast<SIZE_T>(wp);
        SIZE_T tot = static_cast<SIZE_T>(lp);
        char status[160];
        if (tot > 0)
        {
            std::snprintf(status, sizeof(status), "Evaluating process memory... %llu / %llu regions analyzed",
                          static_cast<unsigned long long>(cur), static_cast<unsigned long long>(tot));
        }
        else
        {
            std::snprintf(status, sizeof(status), "Scanning process memory... %llu MB scanned",
                          static_cast<unsigned long long>(cur));
        }
        set_status(status);
        return 0;
    }

    case WM_SCAN_COMPLETE:
    case WM_TRIAGE_COMPLETE:
    {
        WorkerResult *res = reinterpret_cast<WorkerResult *>(lp);
        if (res != nullptr)
        {
            on_worker_completed(res);
            delete res;
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == IDT_HEARTBEAT)
        {
            evaluate_memory_behavior_heartbeat();
            if (g_has_selection && g_selected_region < g_regions.size())
            {
                display_selected_region(static_cast<SIZE_T>(-1));
            }
            return 0;
        }
        break;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_HEARTBEAT);
        g_scan_abort.store(true, std::memory_order_relaxed);
        if (g_h_worker_thread != nullptr)
        {
            WaitForSingleObject(g_h_worker_thread, 1000);
            CloseHandle(g_h_worker_thread);
            g_h_worker_thread = nullptr;
        }
        close_target_proc();
        if (g_mono_font)
            DeleteObject(g_mono_font);
        if (g_ui_font)
            DeleteObject(g_ui_font);
        if (g_ui_font_bold)
            DeleteObject(g_ui_font_bold);
        if (g_br_window)
            DeleteObject(g_br_window);
        if (g_br_control)
            DeleteObject(g_br_control);
        if (g_haccel)
        {
            DestroyAcceleratorTable(g_haccel);
            g_haccel = nullptr;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int run_gui(HINSTANCE hInst, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    HICON hIconBig = static_cast<HICON>(LoadImageA(hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON,
                                                   GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                                                   LR_DEFAULTCOLOR | LR_SHARED));
    HICON hIconSmall = static_cast<HICON>(LoadImageA(hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON,
                                                     GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                                     LR_DEFAULTCOLOR | LR_SHARED));
    if (hIconBig == nullptr)
    {
        hIconBig = LoadIconA(nullptr, IDI_APPLICATION);
    }

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = "DeadeyeHexViewer";
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hIcon = hIconBig;
    wc.hIconSm = hIconSmall;
    RegisterClassExA(&wc);

    WNDCLASSEXA wcYara = {};
    wcYara.cbSize = sizeof(wcYara);
    wcYara.lpfnWndProc = YaraDlgProc;
    wcYara.hInstance = hInst;
    wcYara.hbrBackground = nullptr;
    wcYara.lpszClassName = "DeadeyeYaraDlg";
    wcYara.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wcYara.hIcon = hIconSmall;
    RegisterClassExA(&wcYara);

    WNDCLASSEXA wcStr = {};
    wcStr.cbSize = sizeof(wcStr);
    wcStr.lpfnWndProc = StringsDlgProc;
    wcStr.hInstance = hInst;
    wcStr.hbrBackground = nullptr;
    wcStr.lpszClassName = "DeadeyeStringsDlg";
    wcStr.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wcStr.hIcon = hIconSmall;
    RegisterClassExA(&wcStr);

    HWND hwnd = CreateWindowA("DeadeyeHexViewer", "Deadeye",
                              WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                              1220, 740, nullptr, nullptr, hInst, nullptr);

    if (hIconBig != nullptr)
    {
        SendMessageA(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIconBig));
    }
    if (hIconSmall != nullptr)
    {
        SendMessageA(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIconSmall));
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0))
    {
        if (g_haccel != nullptr && TranslateAcceleratorA(hwnd, g_haccel, &msg))
        {
            continue;
        }
        if (!IsDialogMessageA(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

// ============================================================================
// 4. Pure Windows Subsystem Entry Point
// ============================================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    // Acquire SeDebugPrivilege so elevated runs can inspect system services
    enable_debug_privilege();

    return run_gui(hInstance, nCmdShow);
}
