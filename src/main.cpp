// src/main.cpp
// Deadeye - Unified Process Memory Pattern Scanner, Hex Viewer & Real-Time Diff Timeline.
// Built for defensive malware analysis and detection engineering.
// Supports both headless CLI mode and interactive GUI mode from a single executable.
//
// Usage:
//   deadeye.exe                         -> Launches interactive GUI mode
//   deadeye.exe <pid|self> "<pattern>"  -> Runs fast headless CLI scan
//   deadeye.exe --gui                   -> Explicitly opens GUI window
//
// Build (MinGW-w64, x64):
//   g++ -std=c++17 -m64 -Wall -Wextra -O2 src/main.cpp -o build/deadeye.exe -mwindows
// Build (MSVC x64):
//   cl /std:c++17 /EHsc /W4 /O2 src/main.cpp /Fe:build/deadeye.exe /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

// ============================================================================
// 1. Constants & Core Data Structures
// ============================================================================

// CLI exit codes
const int EXIT_HITS_FOUND  = 0;
const int EXIT_NO_HITS     = 1;
const int EXIT_BAD_ARGS    = 2;
const int EXIT_OPEN_FAILED = 3;

// Memory read chunk sizes
static const SIZE_T CLI_CHUNK_SIZE      = 1024 * 1024; // 1 MB per read
static const SIZE_T VIEW_PAGE_SIZE      = 64 * 1024;   // 64 KB per GUI page
static const size_t MAX_HITS_PER_REGION = 10000;       // Max pattern matches tracked per region

// Control IDs for GUI child windows
#define ID_EDIT_PID        101
#define ID_BTN_LOAD        102
#define ID_EDIT_PATTERN    103
#define ID_BTN_SEARCH      104
#define ID_BTN_NEXT_HIT    105
#define ID_CHK_HITS_ONLY   106
#define ID_LIST_REGIONS    107
#define ID_EDIT_HEX        108
#define ID_BTN_PREV_PAGE   109
#define ID_BTN_NEXT_PAGE   110
#define ID_BTN_SNAP        111
#define ID_COMBO_DIFF      112
#define ID_BTN_CLEAR_SNAPS 113
#define ID_CHK_HEARTBEAT   114
#define IDT_HEARTBEAT      1001

// Compiled byte pattern: mask[i] == 1 means exact byte match, 0 means wildcard (??).
struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

// Snapshot of a memory page for timeline diffing.
struct Snapshot {
    std::vector<uint8_t> data;
    SIZE_T view_offset;
    DWORD timestamp_ms;
    std::string label;
};

// Metadata, hit offsets, and snapshot timeline for a committed virtual memory region.
struct RegionInfo {
    uintptr_t base;
    SIZE_T size;
    DWORD type;
    DWORD protect;
    bool private_rwx;
    std::vector<SIZE_T> hits;
    bool hits_truncated = false;
    std::vector<Snapshot> snapshots;
};

// Statistics tracked during a CLI memory walk.
struct ScanStats {
    SIZE_T regions_scanned;
    SIZE_T bytes_scanned;
    SIZE_T total_hits;
};

// ============================================================================
// 2. Shared Utilities (Win32, Hex Formatting, Pattern Parser, Matcher)
// ============================================================================

// Formats a Win32 error code into a human-readable string.
std::string format_win32_error(DWORD err) {
    LPSTR buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageA(flags, nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    if (len == 0 || buf == nullptr) {
        return "Unknown error";
    }
    std::string s(buf, len);
    LocalFree(buf);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) {
        s.pop_back();
    }
    return s;
}

// Formats a 64-bit address as a zero-padded 16-digit hex string.
std::string fmt_addr(uintptr_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

// Formats a 64-bit value as a "0x..." hex string.
std::string to_hex_string(uintptr_t value) {
    const char* digits = "0123456789ABCDEF";
    if (value == 0) return "0x0";
    std::string rev;
    while (value > 0) {
        rev.push_back(digits[value & 0xF]);
        value >>= 4;
    }
    std::string out = "0x";
    for (size_t i = rev.size(); i > 0; --i) {
        out.push_back(rev[i - 1]);
    }
    return out;
}

// Formats a region size concisely (B, KB, MB) for memory maps.
std::string fmt_size_short(SIZE_T sz) {
    char buf[32];
    if (sz >= 1024 * 1024) {
        std::snprintf(buf, sizeof(buf), "%4lluM", static_cast<unsigned long long>(sz / (1024 * 1024)));
    } else if (sz >= 1024) {
        std::snprintf(buf, sizeof(buf), "%4lluK", static_cast<unsigned long long>(sz / 1024));
    } else {
        std::snprintf(buf, sizeof(buf), "%4lluB", static_cast<unsigned long long>(sz));
    }
    return std::string(buf);
}

// Converts a single hex character to its 0..15 value.
bool hex_nibble(char c, uint8_t& out) {
    if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(10 + (c - 'a')); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(10 + (c - 'A')); return true; }
    return false;
}

// Parses hex strings like "4D 5A ?? 00 03" into bytes and a match mask.
bool parse_pattern(const std::string& input, Pattern& out, std::string& err) {
    out.bytes.clear();
    out.mask.clear();
    size_t i = 0;

    while (i < input.size()) {
        while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i]))) ++i;
        if (i >= input.size()) break;

        size_t start = i;
        while (i < input.size() && !std::isspace(static_cast<unsigned char>(input[i]))) ++i;
        std::string tok = input.substr(start, i - start);

        if (tok.size() % 2 != 0) {
            err = "Odd-length token '" + tok + "' in pattern.";
            return false;
        }

        for (size_t k = 0; k < tok.size(); k += 2) {
            if (tok[k] == '?' && tok[k + 1] == '?') {
                out.bytes.push_back(0);
                out.mask.push_back(0);
            } else {
                uint8_t hi = 0;
                uint8_t lo = 0;
                if (!hex_nibble(tok[k], hi) || !hex_nibble(tok[k + 1], lo)) {
                    err = "Invalid hex byte '" + tok.substr(k, 2) + "' in token '" + tok + "'.";
                    return false;
                }
                out.bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
                out.mask.push_back(1);
            }
        }
    }

    if (out.bytes.empty()) {
        err = "Pattern is empty.";
        return false;
    }

    bool has_literal = false;
    for (size_t k = 0; k < out.mask.size(); ++k) {
        if (out.mask[k] != 0) {
            has_literal = true;
            break;
        }
    }
    if (!has_literal) {
        err = "Pattern cannot consist only of wildcards (must contain at least one literal hex byte).";
        return false;
    }
    return true;
}

// Searches buf[0..len) using SIMD-accelerated memchr anchored on the first literal byte.
std::vector<size_t> find_all(const uint8_t* buf, size_t len, const Pattern& p) {
    std::vector<size_t> hits;
    size_t pl = p.bytes.size();
    if (buf == nullptr || pl == 0 || len < pl) {
        return hits;
    }

    size_t first_lit = 0;
    bool has_lit = false;
    for (size_t k = 0; k < pl; ++k) {
        if (p.mask[k] != 0) {
            first_lit = k;
            has_lit = true;
            break;
        }
    }

    if (!has_lit) {
        return hits;
    }

    uint8_t target_byte = p.bytes[first_lit];
    size_t max_start = len - pl;
    size_t i = 0;

    while (i <= max_start) {
        const void* found = std::memchr(buf + i + first_lit, target_byte, (max_start - i) + 1);
        if (found == nullptr) {
            break;
        }

        i = static_cast<size_t>((static_cast<const uint8_t*>(found) - buf) - first_lit);

        bool ok = true;
        for (size_t j = 0; j < pl; ++j) {
            if (p.mask[j] != 0 && buf[i + j] != p.bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            hits.push_back(i);
        }
        ++i;
    }
    return hits;
}

// Translates Win32 memory protection flags into short text.
std::string prot_short(DWORD protect) {
    DWORD base = protect & 0xFF;
    if (base == PAGE_READONLY) return "R--";
    if (base == PAGE_READWRITE) return "RW-";
    if (base == PAGE_WRITECOPY) return "RWC";
    if (base == PAGE_EXECUTE) return "--X";
    if (base == PAGE_EXECUTE_READ) return "R-X";
    if (base == PAGE_EXECUTE_READWRITE) return "RWX";
    if (base == PAGE_EXECUTE_WRITECOPY) return "RXC";
    return "???";
}

// Translates Win32 protection flags into full readable string.
std::string prot_full(DWORD protect) {
    DWORD base = protect & 0xFF;
    std::string s;
    if (base == PAGE_NOACCESS) s = "PAGE_NOACCESS";
    else if (base == PAGE_READONLY) s = "PAGE_READONLY";
    else if (base == PAGE_READWRITE) s = "PAGE_READWRITE";
    else if (base == PAGE_WRITECOPY) s = "PAGE_WRITECOPY";
    else if (base == PAGE_EXECUTE) s = "PAGE_EXECUTE";
    else if (base == PAGE_EXECUTE_READ) s = "PAGE_EXECUTE_READ";
    else if (base == PAGE_EXECUTE_READWRITE) s = "PAGE_EXECUTE_READWRITE";
    else if (base == PAGE_EXECUTE_WRITECOPY) s = "PAGE_EXECUTE_WRITECOPY";
    else {
        char tmp[24];
        std::snprintf(tmp, sizeof(tmp), "0x%02lX", static_cast<unsigned long>(base));
        s = tmp;
    }
    if (protect & PAGE_GUARD) s += "|PAGE_GUARD";
    if (protect & PAGE_NOCACHE) s += "|PAGE_NOCACHE";
    if (protect & PAGE_WRITECOMBINE) s += "|PAGE_WRITECOMBINE";
    return s;
}

// Translates MEMORY_BASIC_INFORMATION.Type into short tag.
std::string type_short(DWORD t) {
    if (t == MEM_IMAGE) return "IMG ";
    if (t == MEM_MAPPED) return "MAP ";
    if (t == MEM_PRIVATE) return "PRIV";
    return "UNK ";
}

// Translates MEMORY_BASIC_INFORMATION.Type into full string.
std::string type_full(DWORD t) {
    if (t == MEM_IMAGE) return "IMAGE";
    if (t == MEM_MAPPED) return "MAPPED";
    if (t == MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

// Returns true if a region is MEM_PRIVATE and has executable+writable protection.
bool is_private_rwx(DWORD type, DWORD protect) {
    if (type != MEM_PRIVATE) return false;
    DWORD base = protect & 0xFF;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

// ============================================================================
// 3. CLI Subsystem
// ============================================================================

void print_cli_usage(const char* prog_name) {
    std::cout << "Deadeye - Process Memory Pattern Scanner & Hex Diff Viewer\n"
              << "Usage:\n"
              << "  " << prog_name << "                         (Launch GUI viewer)\n"
              << "  " << prog_name << " <pid|self> \"<pattern>\"    (Headless CLI scan)\n"
              << "Example:\n"
              << "  " << prog_name << " 1234 \"4D 5A ?? 00 03\"\n"
              << "Exit codes: 0=hits found, 1=no hits, 2=bad args, 3=OpenProcess failed\n";
}

bool parse_pid_arg(const std::string& arg, DWORD& out_pid) {
    if (arg == "self") {
        out_pid = GetCurrentProcessId();
        return true;
    }
    if (arg.empty()) return false;
    for (size_t i = 0; i < arg.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(arg[i]))) return false;
    }
    errno = 0;
    char* end_ptr = nullptr;
    unsigned long val = std::strtoul(arg.c_str(), &end_ptr, 10);
    if (errno != 0 || end_ptr == nullptr || *end_ptr != '\0' || val == 0) {
        return false;
    }
    out_pid = static_cast<DWORD>(val);
    return true;
}

void scan_region_cli(HANDLE proc, const MEMORY_BASIC_INFORMATION& mbi, const Pattern& pat, ScanStats& stats) {
    uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    SIZE_T region_size = mbi.RegionSize;
    SIZE_T overlap = pat.bytes.size() - 1;
    SIZE_T offset = 0;
    SIZE_T prev_overlap = 0;
    size_t region_hits = 0;
    bool hits_capped = false;

    stats.regions_scanned += 1;
    std::vector<uint8_t> buf(CLI_CHUNK_SIZE);

    while (offset < region_size) {
        SIZE_T remaining = region_size - offset;
        SIZE_T to_read = (remaining < CLI_CHUNK_SIZE) ? remaining : CLI_CHUNK_SIZE;
        SIZE_T bytes_read = 0;

        BOOL ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(region_base + offset),
                                    buf.data(), to_read, &bytes_read);
        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "[WARN] ReadProcessMemory failed at " << to_hex_string(region_base + offset)
                      << " (read " << bytes_read << "/" << to_read << " bytes): "
                      << format_win32_error(err) << " (err=" << err << ")\n";
        }
        if (bytes_read == 0) break;

        if (bytes_read > prev_overlap) {
            stats.bytes_scanned += (bytes_read - prev_overlap);
        }

        std::vector<size_t> hits = find_all(buf.data(), bytes_read, pat);
        for (size_t i = 0; i < hits.size(); ++i) {
            if (region_hits < MAX_HITS_PER_REGION) {
                uintptr_t hit_addr = region_base + offset + hits[i];
                std::string marker = is_private_rwx(mbi.Type, mbi.Protect) ? "[!] " : "    ";
                std::cout << marker << "HIT addr=" << to_hex_string(hit_addr)
                          << " region_base=" << to_hex_string(region_base)
                          << " region_size=" << to_hex_string(region_size)
                          << " type=" << type_full(mbi.Type)
                          << " protect=" << prot_full(mbi.Protect) << "\n";
                stats.total_hits += 1;
                region_hits += 1;
            } else if (!hits_capped) {
                hits_capped = true;
                std::cerr << "[WARN] Region at " << to_hex_string(region_base)
                          << " exceeded limit of " << MAX_HITS_PER_REGION
                          << " hits. Truncating further output for this region.\n";
                break;
            }
        }

        if (!ok || offset + bytes_read >= region_size || bytes_read <= overlap) break;
        offset += (bytes_read - overlap);
        prev_overlap = overlap;
    }
}

int run_cli(int argc, char* argv[]) {
    if (argc < 3) {
        print_cli_usage(argv[0]);
        return EXIT_BAD_ARGS;
    }

    DWORD pid = 0;
    if (!parse_pid_arg(argv[1], pid)) {
        std::cout << "[ERROR] Invalid PID: '" << argv[1] << "'\n";
        print_cli_usage(argv[0]);
        return EXIT_BAD_ARGS;
    }

    Pattern pat;
    std::string pat_err;
    if (!parse_pattern(argv[2], pat, pat_err)) {
        std::cout << "[ERROR] " << pat_err << "\n";
        print_cli_usage(argv[0]);
        return EXIT_BAD_ARGS;
    }

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (proc == nullptr) {
        DWORD err = GetLastError();
        std::cout << "[ERROR] OpenProcess failed for PID " << pid << ": "
                  << format_win32_error(err) << " (err=" << err << ")\n";
        if (err == ERROR_ACCESS_DENIED) {
            std::cout << "        Access denied: the target may be a Protected Process (PPL),\n"
                      << "        running elevated, or require Administrator/SeDebugPrivilege.\n";
        }
        return EXIT_OPEN_FAILED;
    }

    std::cout << "[Deadeye] Scanning PID " << pid << " for " << pat.bytes.size() << "-byte pattern...\n";

    ScanStats stats;
    stats.regions_scanned = 0;
    stats.bytes_scanned = 0;
    stats.total_hits = 0;

    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (true) {
        std::memset(&mbi, 0, sizeof(mbi));
        SIZE_T queried = VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (queried == 0) {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER) break;
            std::cerr << "[WARN] VirtualQueryEx failed at " << to_hex_string(addr)
                      << ": " << format_win32_error(err) << " (err=" << err << ")\n";
            break;
        }

        uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T region_size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0 && (mbi.Protect & PAGE_GUARD) == 0) {
            scan_region_cli(proc, mbi, pat, stats);
        }

        if (region_size == 0) break;
        uintptr_t next_addr = region_base + region_size;
        if (next_addr <= addr) break;
        addr = next_addr;
    }

    CloseHandle(proc);

    std::cout << "\n--- Deadeye Summary ---\n"
              << "Regions scanned: " << stats.regions_scanned << "\n"
              << "Bytes scanned:   " << stats.bytes_scanned << "\n"
              << "Total hits:      " << stats.total_hits << "\n";

    return (stats.total_hits > 0) ? EXIT_HITS_FOUND : EXIT_NO_HITS;
}

// ============================================================================
// 4. GUI Subsystem (Memory Map, Hex Viewer, Heartbeat Diff Timeline)
// ============================================================================

static HWND g_hwnd_main       = nullptr;
static HWND g_edit_pid        = nullptr;
static HWND g_btn_load        = nullptr;
static HWND g_edit_pattern    = nullptr;
static HWND g_btn_search      = nullptr;
static HWND g_btn_next_hit    = nullptr;
static HWND g_chk_hits_only   = nullptr;
static HWND g_chk_heartbeat   = nullptr;
static HWND g_list_regions    = nullptr;
static HWND g_lbl_hex_info    = nullptr;
static HWND g_btn_prev_page   = nullptr;
static HWND g_btn_next_page   = nullptr;
static HWND g_btn_snap        = nullptr;
static HWND g_combo_diff      = nullptr;
static HWND g_btn_clear_snaps = nullptr;
static HWND g_edit_hex        = nullptr;
static HWND g_lbl_status      = nullptr;
static HFONT g_mono_font      = nullptr;
static HFONT g_ui_font        = nullptr;

static DWORD g_current_pid = 0;
static std::string g_current_pid_label;
static Pattern g_active_pattern;
static bool g_has_pattern = false;
static std::vector<RegionInfo> g_regions;
static std::vector<size_t> g_visible_indices;
static size_t g_selected_region = 0;
static bool g_has_selection = false;
static SIZE_T g_view_offset = 0;
static size_t g_hit_cursor_region = 0;
static size_t g_hit_cursor_index = 0;

static HANDLE g_target_proc = nullptr;
static std::string g_last_hex_dump;
static std::string g_last_hex_info;

void close_target_proc() {
    if (g_target_proc != nullptr) {
        CloseHandle(g_target_proc);
        g_target_proc = nullptr;
    }
}

HANDLE get_or_open_target_proc(DWORD pid) {
    if (g_target_proc != nullptr) {
        DWORD exit_code = 0;
        if (g_current_pid == pid && GetExitCodeProcess(g_target_proc, &exit_code) && exit_code == STILL_ACTIVE) {
            return g_target_proc;
        }
        close_target_proc();
    }
    g_target_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    return g_target_proc;
}

void invalidate_hex_cache() {
    g_last_hex_dump.clear();
    g_last_hex_info.clear();
}

void set_status(const std::string& text) {
    SetWindowTextA(g_lbl_status, text.c_str());
}

struct DiffPair {
    bool active;
    std::string title;
    const std::vector<uint8_t>* ref_data;
    const std::vector<uint8_t>* cmp_data;
    SIZE_T ref_view_offset;
    SIZE_T cmp_view_offset;
};

DiffPair get_active_diff_pair() {
    DiffPair dp = { false, "", nullptr, nullptr, 0, 0 };
    if (!g_has_selection || g_selected_region >= g_regions.size()) return dp;
    const RegionInfo& reg = g_regions[g_selected_region];
    if (reg.snapshots.empty()) return dp;

    LRESULT sel = SendMessageA(g_combo_diff, CB_GETCURSEL, 0, 0);
    if (sel <= 0 || sel == CB_ERR) return dp;

    size_t snap_count = reg.snapshots.size();
    if (static_cast<size_t>(sel) <= snap_count) {
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
    if (pair_idx + 1 < snap_count) {
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

std::string build_hex_dump(const uint8_t* buf, size_t buf_len, uintptr_t view_addr,
                           const std::vector<SIZE_T>& region_hits, SIZE_T view_offset,
                           size_t pat_len, SIZE_T focus_offset, int& out_focus_line,
                           const uint8_t* ref_buf, size_t ref_len, bool diff_active,
                           size_t& out_chg_bytes, size_t& out_new_bytes, size_t& out_zeroed_bytes) {
    out_focus_line = -1;
    out_chg_bytes = 0;
    out_new_bytes = 0;
    out_zeroed_bytes = 0;

    if (buf_len == 0) {
        return "(No readable bytes in this page)\r\n";
    }

    std::vector<uint8_t> hit_byte(buf_len, 0);
    if (g_has_pattern && pat_len > 0) {
        for (size_t i = 0; i < region_hits.size(); ++i) {
            SIZE_T h = region_hits[i];
            if (h + pat_len <= view_offset || h >= view_offset + buf_len) {
                continue;
            }
            for (size_t j = 0; j < pat_len; ++j) {
                if (h + j >= view_offset && h + j < view_offset + buf_len) {
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

    for (size_t row = 0; row < num_rows; ++row) {
        size_t rs = row * 16;
        size_t re = rs + 16;
        if (re > buf_len) re = buf_len;

        bool row_has_hit = false;
        bool row_has_diff = false;

        for (size_t i = rs; i < re; ++i) {
            if (hit_byte[i] != 0) {
                row_has_hit = true;
            }
            if (diff_active && ref_buf != nullptr) {
                if (i < ref_len) {
                    if (buf[i] != ref_buf[i]) {
                        row_has_diff = true;
                        out_chg_bytes++;
                        if (ref_buf[i] == 0 && buf[i] != 0) out_new_bytes++;
                        else if (ref_buf[i] != 0 && buf[i] == 0) out_zeroed_bytes++;
                    }
                } else {
                    row_has_diff = true;
                    out_chg_bytes++;
                    if (buf[i] != 0) out_new_bytes++;
                }
            }
        }

        if (focus_offset != static_cast<SIZE_T>(-1) &&
            focus_offset >= view_offset + rs && focus_offset < view_offset + re) {
            out_focus_line = line_counter;
        }

        if (row_has_hit && row_has_diff) {
            out += "!>> ";
        } else if (row_has_diff) {
            out += "CHG ";
        } else if (row_has_hit) {
            out += ">>> ";
        } else {
            out += "    ";
        }

        out += fmt_addr(view_addr + rs);
        out += "  ";

        char hx[8];
        for (size_t i = rs; i < rs + 16; ++i) {
            if (i == rs + 8) out += " ";
            if (i < re) {
                std::snprintf(hx, sizeof(hx), "%02X ", buf[i]);
                out += hx;
            } else {
                out += "   ";
            }
        }
        out += " ";

        for (size_t i = rs; i < rs + 16; ++i) {
            if (i < re) {
                uint8_t b = buf[i];
                out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            } else {
                out += ' ';
            }
        }
        out += "\r\n";
        line_counter++;

        // Sub-row for changed bytes
        if (row_has_diff && ref_buf != nullptr) {
            out += "        old:          ";
            for (size_t i = rs; i < rs + 16; ++i) {
                if (i == rs + 8) out += " ";
                if (i < re && i < ref_len && buf[i] != ref_buf[i]) {
                    std::snprintf(hx, sizeof(hx), "%02X ", ref_buf[i]);
                    out += hx;
                } else {
                    out += "   ";
                }
            }
            out += " ";
            for (size_t i = rs; i < rs + 16; ++i) {
                if (i < re && i < ref_len && buf[i] != ref_buf[i]) {
                    uint8_t b = ref_buf[i];
                    out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
                } else {
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

void update_diff_combo() {
    SendMessageA(g_combo_diff, CB_RESETCONTENT, 0, 0);
    SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Diff: Off (Normal)"));

    if (!g_has_selection || g_selected_region >= g_regions.size()) {
        SendMessageA(g_combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(g_btn_snap, FALSE);
        EnableWindow(g_combo_diff, FALSE);
        EnableWindow(g_btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(g_btn_snap, TRUE);
    const RegionInfo& reg = g_regions[g_selected_region];

    if (reg.snapshots.empty()) {
        SendMessageA(g_combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(g_combo_diff, FALSE);
        EnableWindow(g_btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(g_combo_diff, TRUE);
    EnableWindow(g_btn_clear_snaps, TRUE);

    for (size_t i = 0; i < reg.snapshots.size(); ++i) {
        std::string item = "Live vs " + reg.snapshots[i].label;
        SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
    }

    if (reg.snapshots.size() >= 2) {
        for (size_t i = 0; i + 1 < reg.snapshots.size(); ++i) {
            std::string item = reg.snapshots[i].label + " vs " + reg.snapshots[i + 1].label;
            SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
        }
    }

    LRESULT count = SendMessageA(g_combo_diff, CB_GETCOUNT, 0, 0);
    WPARAM sel = (reg.snapshots.size() > 0) ? static_cast<WPARAM>(reg.snapshots.size()) : 0;
    if (sel >= static_cast<WPARAM>(count)) sel = 0;
    SendMessageA(g_combo_diff, CB_SETCURSEL, sel, 0);
}

void on_take_snapshot() {
    if (!g_has_selection || g_selected_region >= g_regions.size()) return;
    RegionInfo& reg = g_regions[g_selected_region];

    if (g_view_offset >= reg.size) g_view_offset = 0;
    SIZE_T remaining = reg.size - g_view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    HANDLE proc = get_or_open_target_proc(g_current_pid);
    if (proc == nullptr) {
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

    if (bytes_read == 0) {
        set_status("[ERROR] Could not capture snapshot: " + format_win32_error(read_err));
        return;
    }
    snap.data.resize(bytes_read);
    snap.view_offset = g_view_offset;
    snap.timestamp_ms = GetTickCount();

    size_t snap_num = reg.snapshots.size() + 1;
    char label_buf[64];
    if (reg.snapshots.empty()) {
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (0.0s)", snap_num);
    } else {
        DWORD elapsed_ms = snap.timestamp_ms - reg.snapshots[0].timestamp_ms;
        double sec = static_cast<double>(elapsed_ms) / 1000.0;
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (+%.1fs)", snap_num, sec);
    }
    snap.label = label_buf;

    reg.snapshots.push_back(snap);
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis) {
        if (g_visible_indices[vis] == g_selected_region) {
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

void on_clear_snapshots() {
    if (!g_has_selection || g_selected_region >= g_regions.size()) return;
    RegionInfo& reg = g_regions[g_selected_region];
    size_t count = reg.snapshots.size();
    reg.snapshots.clear();
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis) {
        if (g_visible_indices[vis] == g_selected_region) {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    display_selected_region(static_cast<SIZE_T>(-1));

    char status[128];
    std::snprintf(status, sizeof(status), "Cleared %zu snapshot(s) for current region.", count);
    set_status(status);
}

void display_selected_region(SIZE_T focus_offset) {
    if (!g_has_selection || g_selected_region >= g_regions.size()) {
        SetWindowTextA(g_lbl_hex_info, "Hex View: (no region selected)");
        SetWindowTextA(g_edit_hex, "");
        g_last_hex_info.clear();
        g_last_hex_dump.clear();
        EnableWindow(g_btn_prev_page, FALSE);
        EnableWindow(g_btn_next_page, FALSE);
        return;
    }

    const RegionInfo& reg = g_regions[g_selected_region];
    if (g_view_offset >= reg.size) {
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

    if (dp.active && dp.cmp_data != nullptr) {
        buf = *dp.cmp_data;
        bytes_read = buf.size();
    } else {
        HANDLE proc = get_or_open_target_proc(g_current_pid);
        if (proc == nullptr) {
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

        if (bytes_read == 0) {
            std::string msg = "[WARN] ReadProcessMemory failed at 0x" + fmt_addr(reg.base + g_view_offset) +
                              ": " + format_win32_error(read_err) + "\r\n";
            SetWindowTextA(g_edit_hex, msg.c_str());
            g_last_hex_dump = msg;
            return;
        }
        buf.resize(bytes_read);
    }

    const uint8_t* ref_ptr = nullptr;
    size_t ref_len = 0;
    bool offset_mismatch = false;
    if (dp.active && dp.ref_data != nullptr) {
        if (dp.ref_view_offset == g_view_offset) {
            ref_ptr = dp.ref_data->data();
            ref_len = dp.ref_data->size();
        } else {
            offset_mismatch = true;
        }
    }

    int focus_line = -1;
    size_t chg_bytes = 0, new_bytes = 0, zeroed_bytes = 0;
    std::string dump = build_hex_dump(buf.data(), bytes_read, reg.base + g_view_offset,
                                      reg.hits, g_view_offset, g_active_pattern.bytes.size(),
                                      focus_offset, focus_line,
                                      ref_ptr, ref_len, dp.active && !offset_mismatch,
                                      chg_bytes, new_bytes, zeroed_bytes);

    if (offset_mismatch) {
        char warn_note[192];
        std::snprintf(warn_note, sizeof(warn_note),
                      "[Note: Selected snapshot belongs to offset 0x%llX; current page is 0x%llX. Navigate back or take a new snapshot.]\r\n\r\n",
                      static_cast<unsigned long long>(dp.ref_view_offset),
                      static_cast<unsigned long long>(g_view_offset));
        dump = warn_note + dump;
        if (focus_line >= 0) focus_line += 2;
    }

    if (!ok) {
        dump = "[WARN] Partial read (" + std::to_string(bytes_read) + "/" + std::to_string(to_read) +
               " bytes): " + format_win32_error(read_err) + "\r\n\r\n" + dump;
        if (focus_line >= 0) focus_line += 2;
    }

    char info[320];
    if (dp.active && !offset_mismatch) {
        std::snprintf(info, sizeof(info),
                      "Region %zu/%zu | Base 0x%016llX | %s | %s%s | Diff [%s]: %zu chg (%zu new, %zu wiped)",
                      g_selected_region + 1, g_regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      reg.private_rwx ? " [!]" : "",
                      dp.title.c_str(), chg_bytes, new_bytes, zeroed_bytes);
    } else {
        std::snprintf(info, sizeof(info),
                      "Region %zu/%zu | Base 0x%016llX | %s | %s%s | Showing 0x%llX..0x%llX of 0x%llX",
                      g_selected_region + 1, g_regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      reg.private_rwx ? " [!]" : "",
                      static_cast<unsigned long long>(g_view_offset),
                      static_cast<unsigned long long>(g_view_offset + to_read),
                      static_cast<unsigned long long>(reg.size));
    }

    if (g_last_hex_info != info) {
        SetWindowTextA(g_lbl_hex_info, info);
        g_last_hex_info = info;
    }

    if (g_last_hex_dump != dump) {
        int first_line = static_cast<int>(SendMessageA(g_edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(g_edit_hex, WM_SETREDRAW, FALSE, 0);
        SetWindowTextA(g_edit_hex, dump.c_str());
        if (focus_line > 3) {
            SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(focus_line - 3));
        } else if (first_line > 0) {
            SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(first_line));
        } else {
            SendMessageA(g_edit_hex, EM_SETSEL, 0, 0);
            SendMessageA(g_edit_hex, EM_SCROLLCARET, 0, 0);
        }
        SendMessageA(g_edit_hex, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_edit_hex, nullptr, TRUE);
        g_last_hex_dump = dump;
    } else if (focus_line > 3) {
        int cur = static_cast<int>(SendMessageA(g_edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>((focus_line - 3) - cur));
    }
}

void populate_region_list() {
    SendMessageA(g_list_regions, WM_SETREDRAW, FALSE, 0);
    SendMessageA(g_list_regions, LB_RESETCONTENT, 0, 0);
    g_visible_indices.clear();

    bool hits_only = (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);

    for (size_t i = 0; i < g_regions.size(); ++i) {
        const RegionInfo& r = g_regions[i];
        if (hits_only && r.hits.empty()) {
            continue;
        }

        char row[160];
        std::string tag;
        if (!r.hits.empty()) {
            char hbuf[48];
            if (r.hits_truncated) {
                std::snprintf(hbuf, sizeof(hbuf), " [%zu+ hits (capped)]", r.hits.size());
            } else {
                std::snprintf(hbuf, sizeof(hbuf), " [%zu hit%s]", r.hits.size(), r.hits.size() == 1 ? "" : "s");
            }
            tag += hbuf;
        }
        if (!r.snapshots.empty()) {
            char sbuf[32];
            std::snprintf(sbuf, sizeof(sbuf), " (%zu snap%s)", r.snapshots.size(), r.snapshots.size() == 1 ? "" : "s");
            tag += sbuf;
        }

        std::snprintf(row, sizeof(row), "%016llX %s %s %s%s%s",
                      static_cast<unsigned long long>(r.base),
                      fmt_size_short(r.size).c_str(),
                      type_short(r.type).c_str(),
                      prot_short(r.protect).c_str(),
                      r.private_rwx ? "!" : " ",
                      tag.c_str());

        SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
        g_visible_indices.push_back(i);
    }

    SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list_regions, nullptr, TRUE);
}

void select_region_in_ui(size_t region_idx, SIZE_T view_offset, SIZE_T focus_offset) {
    g_selected_region = region_idx;
    g_has_selection = true;
    g_view_offset = view_offset;

    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis) {
        if (g_visible_indices[vis] == region_idx) {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    update_diff_combo();
    invalidate_hex_cache();
    display_selected_region(focus_offset);
}

void run_load_or_search(bool require_pattern) {
    char pid_buf[64] = {};
    char pat_buf[512] = {};
    GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
    GetWindowTextA(g_edit_pattern, pat_buf, sizeof(pat_buf));

    std::string pid_str(pid_buf);
    std::string pat_str(pat_buf);

    DWORD pid = 0;
    if (!parse_pid_arg(pid_str, pid)) {
        MessageBoxA(g_hwnd_main, "Enter a numeric PID or 'self'.", "Invalid PID", MB_ICONWARNING);
        return;
    }

    bool trim_empty = true;
    for (size_t i = 0; i < pat_str.size(); ++i) {
        if (!std::isspace(static_cast<unsigned char>(pat_str[i]))) {
            trim_empty = false;
            break;
        }
    }

    if (require_pattern && trim_empty) {
        MessageBoxA(g_hwnd_main, "Enter a hex pattern to search (e.g. '4D 5A ?? 00'), or click 'Load' to view memory without searching.",
                    "Pattern Required", MB_ICONINFORMATION);
        return;
    }

    Pattern pat;
    bool use_pattern = !trim_empty;
    if (use_pattern) {
        std::string err;
        if (!parse_pattern(pat_str, pat, err)) {
            MessageBoxA(g_hwnd_main, err.c_str(), "Invalid Hex Pattern", MB_ICONWARNING);
            return;
        }
    }

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (proc == nullptr) {
        DWORD err = GetLastError();
        std::string msg = "OpenProcess failed for PID " + std::to_string(pid) + ": " +
                          format_win32_error(err) + " (err=" + std::to_string(err) + ")";
        if (err == ERROR_ACCESS_DENIED) {
            msg += "\n\nRun as Administrator or pick a non-protected user process.";
        }
        set_status("[ERROR] " + msg);
        MessageBoxA(g_hwnd_main, msg.c_str(), "Cannot Open Process", MB_ICONERROR);
        return;
    }

    set_status(use_pattern ? "Scanning process memory..." : "Loading process memory map...");
    EnableWindow(g_btn_load, FALSE);
    EnableWindow(g_btn_search, FALSE);

    close_target_proc();
    invalidate_hex_cache();

    g_regions.clear();
    g_current_pid = pid;
    g_current_pid_label = pid_str;
    g_active_pattern = pat;
    g_has_pattern = use_pattern;
    g_has_selection = false;
    g_view_offset = 0;

    SIZE_T total_bytes = 0;
    SIZE_T total_hits = 0;
    size_t regions_with_hits = 0;
    size_t first_hit_region = 0;
    bool found_first_hit = false;

    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (true) {
        std::memset(&mbi, 0, sizeof(mbi));
        SIZE_T q = VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (q == 0) break;

        uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T region_size = mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_NOACCESS) == 0 &&
            (mbi.Protect & PAGE_GUARD) == 0) {
            RegionInfo reg;
            reg.base = region_base;
            reg.size = region_size;
            reg.type = mbi.Type;
            reg.protect = mbi.Protect;
            reg.private_rwx = is_private_rwx(mbi.Type, mbi.Protect);

            if (use_pattern) {
                SIZE_T overlap = pat.bytes.size() - 1;
                SIZE_T offset = 0;
                SIZE_T prev_ov = 0;
                std::vector<uint8_t> chunk(CLI_CHUNK_SIZE);
                while (offset < region_size) {
                    SIZE_T rem = region_size - offset;
                    SIZE_T to_read = (rem < CLI_CHUNK_SIZE) ? rem : CLI_CHUNK_SIZE;
                    SIZE_T bytes_read = 0;
                    BOOL ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(region_base + offset),
                                                chunk.data(), to_read, &bytes_read);
                    if (!ok && bytes_read == 0) break;
                    if (bytes_read > prev_ov) {
                        total_bytes += (bytes_read - prev_ov);
                    }
                    std::vector<size_t> hits = find_all(chunk.data(), bytes_read, pat);
                    for (size_t i = 0; i < hits.size(); ++i) {
                        if (reg.hits.size() < MAX_HITS_PER_REGION) {
                            reg.hits.push_back(offset + hits[i]);
                        } else {
                            reg.hits_truncated = true;
                            break;
                        }
                    }
                    if (!ok || offset + bytes_read >= region_size || bytes_read <= overlap) break;
                    offset += (bytes_read - overlap);
                    prev_ov = overlap;
                }
                if (!reg.hits.empty()) {
                    total_hits += reg.hits.size();
                    regions_with_hits += 1;
                    if (!found_first_hit) {
                        first_hit_region = g_regions.size();
                        found_first_hit = true;
                    }
                }
            } else {
                total_bytes += region_size;
            }

            g_regions.push_back(reg);
        }

        if (region_size == 0) break;
        uintptr_t next = region_base + region_size;
        if (next <= addr) break;
        addr = next;
    }

    CloseHandle(proc);

    EnableWindow(g_btn_load, TRUE);
    EnableWindow(g_btn_search, TRUE);
    EnableWindow(g_btn_next_hit, (use_pattern && total_hits > 0) ? TRUE : FALSE);

    populate_region_list();

    if (use_pattern && found_first_hit) {
        g_hit_cursor_region = first_hit_region;
        g_hit_cursor_index = 0;
        SIZE_T hit_off = g_regions[first_hit_region].hits[0];
        SIZE_T page_off = (hit_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
        select_region_in_ui(first_hit_region, page_off, hit_off);
    } else if (!g_visible_indices.empty()) {
        select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
    } else {
        update_diff_combo();
        display_selected_region(static_cast<SIZE_T>(-1));
    }

    char status[256];
    double mb = static_cast<double>(total_bytes) / (1024.0 * 1024.0);
    if (use_pattern) {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): %zu regions, %.2f MB scanned | %zu hit(s) in %zu region(s) | Click any region to view hex",
                      static_cast<unsigned long>(pid), pid_str.c_str(),
                      g_regions.size(), mb, total_hits, regions_with_hits);
    } else {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): Loaded %zu committed regions (%.2f MB) | Click any region on the left to inspect its hex",
                      static_cast<unsigned long>(pid), pid_str.c_str(),
                      g_regions.size(), mb);
    }
    set_status(status);
}

void on_next_hit() {
    if (!g_has_pattern || g_regions.empty()) return;

    size_t total_hits = 0;
    for (size_t i = 0; i < g_regions.size(); ++i) {
        total_hits += g_regions[i].hits.size();
    }
    if (total_hits == 0) return;

    g_hit_cursor_index += 1;
    if (g_hit_cursor_region >= g_regions.size() ||
        g_hit_cursor_index >= g_regions[g_hit_cursor_region].hits.size()) {
        g_hit_cursor_index = 0;
        size_t r = (g_hit_cursor_region + 1) % g_regions.size();
        while (g_regions[r].hits.empty()) {
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

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd_main = hwnd;
        HINSTANCE hInst = GetModuleHandleA(nullptr);

        g_ui_font = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_mono_font = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        const int M = 8, RH = 24;
        int x = M;

        HWND lbl_pid = CreateWindowA("STATIC", "PID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 28, RH, hwnd, nullptr, hInst, nullptr);
        x += 32;

        g_edit_pid = CreateWindowA("EDIT", "self",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                   x, M, 80, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PID), hInst, nullptr);
        x += 86;

        g_btn_load = CreateWindowA("BUTTON", "Load",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 60, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_LOAD), hInst, nullptr);
        x += 72;

        HWND lbl_pat = CreateWindowA("STATIC", "Search Hex (optional):", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 134, RH, hwnd, nullptr, hInst, nullptr);
        x += 138;

        g_edit_pattern = CreateWindowA("EDIT", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                       x, M, 280, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PATTERN), hInst, nullptr);
        x += 286;

        g_btn_search = CreateWindowA("BUTTON", "Search",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     x, M, 68, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SEARCH), hInst, nullptr);
        x += 74;

        g_btn_next_hit = CreateWindowA("BUTTON", "Next Hit",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                                       x, M, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_HIT), hInst, nullptr);
        x += 82;

        g_chk_hits_only = CreateWindowA("BUTTON", "Hits only",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 84, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HITS_ONLY), hInst, nullptr);
        x += 88;

        g_chk_heartbeat = CreateWindowA("BUTTON", "Heartbeat (1s)",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 116, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HEARTBEAT), hInst, nullptr);

        HWND lbl_map = CreateWindowA("STATIC", "Memory Map (Address | Size | Type | Prot | !RWX)",
                                     WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     M, M + RH + M, 390, 18, hwnd, nullptr, hInst, nullptr);

        g_lbl_hex_info = CreateWindowA("STATIC", "Hex View",
                                       WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                       406, M + RH + M, 500, 18, hwnd, nullptr, hInst, nullptr);

        g_btn_prev_page = CreateWindowA("BUTTON", "< Prev 64K",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 76, 20, hwnd, reinterpret_cast<HMENU>(ID_BTN_PREV_PAGE), hInst, nullptr);
        g_btn_next_page = CreateWindowA("BUTTON", "Next 64K >",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 76, 20, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_PAGE), hInst, nullptr);

        g_btn_snap = CreateWindowA("BUTTON", "+ Snap",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                   0, 0, 72, 22, hwnd, reinterpret_cast<HMENU>(ID_BTN_SNAP), hInst, nullptr);
        g_combo_diff = CreateWindowA("COMBOBOX", "",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL | WS_DISABLED,
                                     0, 0, 146, 160, hwnd, reinterpret_cast<HMENU>(ID_COMBO_DIFF), hInst, nullptr);
        g_btn_clear_snaps = CreateWindowA("BUTTON", "Clear",
                                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                          0, 0, 52, 22, hwnd, reinterpret_cast<HMENU>(ID_BTN_CLEAR_SNAPS), hInst, nullptr);

        g_list_regions = CreateWindowA("LISTBOX", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                       WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                                       M, 60, 390, 400, hwnd, reinterpret_cast<HMENU>(ID_LIST_REGIONS), hInst, nullptr);

        g_edit_hex = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                   WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                   406, 60, 500, 400, hwnd, reinterpret_cast<HMENU>(ID_EDIT_HEX), hInst, nullptr);
        SendMessageA(g_edit_hex, EM_SETLIMITTEXT, 0, 0);

        g_lbl_status = CreateWindowA("STATIC", "Ready.",
                                     WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                     M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        HWND ui_items[] = {
            lbl_pid, g_edit_pid, g_btn_load, lbl_pat, g_edit_pattern, g_btn_search,
            g_btn_next_hit, g_chk_hits_only, g_chk_heartbeat, lbl_map, g_lbl_hex_info,
            g_btn_snap, g_combo_diff, g_btn_clear_snaps,
            g_btn_prev_page, g_btn_next_page, g_lbl_status
        };
        for (size_t i = 0; i < sizeof(ui_items) / sizeof(ui_items[0]); ++i) {
            SendMessageA(ui_items[i], WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }
        SendMessageA(g_list_regions, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);
        SendMessageA(g_edit_hex, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

        PostMessageA(hwnd, WM_COMMAND, ID_BTN_LOAD, 0);
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lp);
        int h = HIWORD(lp);
        const int M = 8, RH = 24;
        int list_w = 390;
        if (w < 750) list_w = w / 3;

        int right_x = M + list_w + M;
        int right_w = w - right_x - M;
        if (right_w < 120) right_w = 120;

        int hdr_y = M + RH + M;
        int pane_top = hdr_y + 24;
        int pane_h = h - pane_top - 28;
        if (pane_h < 60) pane_h = 60;

        int cur_r = w - M;
        int btn_next_x = cur_r - 74; cur_r -= 78;
        int btn_prev_x = cur_r - 74; cur_r -= 78;
        int btn_clr_x  = cur_r - 52; cur_r -= 56;
        int combo_x    = cur_r - 146; cur_r -= 150;
        int btn_snap_x = cur_r - 72; cur_r -= 76;
        int info_w     = btn_snap_x - right_x - 6;
        if (info_w < 50) info_w = 50;

        MoveWindow(g_lbl_hex_info, right_x, hdr_y + 2, info_w, 18, TRUE);
        MoveWindow(g_btn_snap, btn_snap_x, hdr_y - 1, 72, 22, TRUE);
        MoveWindow(g_combo_diff, combo_x, hdr_y - 1, 146, 160, TRUE);
        MoveWindow(g_btn_clear_snaps, btn_clr_x, hdr_y - 1, 52, 22, TRUE);
        MoveWindow(g_btn_prev_page, btn_prev_x, hdr_y - 1, 74, 22, TRUE);
        MoveWindow(g_btn_next_page, btn_next_x, hdr_y - 1, 74, 22, TRUE);

        MoveWindow(g_list_regions, M, pane_top, list_w, pane_h, TRUE);
        MoveWindow(g_edit_hex, right_x, pane_top, right_w, pane_h, TRUE);
        MoveWindow(g_lbl_status, M, h - 22, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        int code = HIWORD(wp);

        if (id == ID_BTN_LOAD) {
            run_load_or_search(false);
        } else if (id == ID_BTN_SEARCH || id == IDOK) {
            if (GetFocus() == g_edit_pid) {
                run_load_or_search(false);
            } else {
                run_load_or_search(true);
            }
        } else if (id == ID_BTN_NEXT_HIT) {
            on_next_hit();
        } else if (id == ID_CHK_HITS_ONLY) {
            populate_region_list();
            if (!g_visible_indices.empty()) {
                select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
            } else {
                g_has_selection = false;
                update_diff_combo();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        } else if (id == ID_LIST_REGIONS && code == LBN_SELCHANGE) {
            LRESULT sel = SendMessageA(g_list_regions, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && static_cast<size_t>(sel) < g_visible_indices.size()) {
                size_t reg_idx = g_visible_indices[static_cast<size_t>(sel)];
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
            }
        } else if (id == ID_BTN_PREV_PAGE) {
            if (g_has_selection && g_view_offset >= VIEW_PAGE_SIZE) {
                g_view_offset -= VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        } else if (id == ID_BTN_NEXT_PAGE) {
            if (g_has_selection && g_selected_region < g_regions.size() &&
                g_view_offset + VIEW_PAGE_SIZE < g_regions[g_selected_region].size) {
                g_view_offset += VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        } else if (id == ID_BTN_SNAP) {
            on_take_snapshot();
        } else if (id == ID_BTN_CLEAR_SNAPS) {
            on_clear_snapshots();
        } else if (id == ID_COMBO_DIFF && code == CBN_SELCHANGE) {
            invalidate_hex_cache();
            display_selected_region(static_cast<SIZE_T>(-1));
        } else if (id == ID_CHK_HEARTBEAT) {
            bool checked = (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (checked) {
                if (g_has_selection && g_selected_region < g_regions.size()) {
                    RegionInfo& reg = g_regions[g_selected_region];
                    if (reg.snapshots.empty()) {
                        on_take_snapshot();
                    }
                }
                SetTimer(hwnd, IDT_HEARTBEAT, 1000, nullptr);
                set_status("Heartbeat active (1s interval): Monitoring memory diff in real time...");
            } else {
                KillTimer(hwnd, IDT_HEARTBEAT);
                set_status("Heartbeat stopped.");
            }
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == IDT_HEARTBEAT) {
            if (g_has_selection && g_selected_region < g_regions.size()) {
                display_selected_region(static_cast<SIZE_T>(-1));
            }
            return 0;
        }
        break;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_HEARTBEAT);
        close_target_proc();
        if (g_mono_font) DeleteObject(g_mono_font);
        if (g_ui_font) DeleteObject(g_ui_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int run_gui(HINSTANCE hInst, int nCmdShow) {
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = "DeadeyeHexViewer";
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconA(nullptr, IDI_APPLICATION);
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA("DeadeyeHexViewer", "Deadeye - Memory Hex Viewer & Diff Timeline",
                              WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                              1160, 720, nullptr, nullptr, hInst, nullptr);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageA(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

// ============================================================================
// 5. Unified Entry Point (CLI vs GUI Dispatcher)
// ============================================================================

int main(int argc, char* argv[]) {
    // If no arguments or explicitly "--gui", launch interactive GUI mode
    if (argc <= 1 || (argc == 2 && std::strcmp(argv[1], "--gui") == 0)) {
        HWND console_hwnd = GetConsoleWindow();
        if (console_hwnd != nullptr) {
            DWORD proc_list[2] = {};
            DWORD proc_count = GetConsoleProcessList(proc_list, 2);
            // Hide the console only if it was spawned solely for this process (e.g. from Explorer)
            if (proc_count <= 1) {
                ShowWindow(console_hwnd, SW_HIDE);
            }
        }
        return run_gui(GetModuleHandleA(nullptr), SW_SHOW);
    }

    // Otherwise, run in high-performance headless CLI scanner mode
    return run_cli(argc, argv);
}
