#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

// Distinct process exit codes required by the CLI specification.
const int EXIT_HITS_FOUND = 0;
const int EXIT_NO_HITS = 1;
const int EXIT_BAD_ARGS = 2;
const int EXIT_OPEN_FAILED = 3;

// Read at most 1 MB per ReadProcessMemory call to bound memory usage.
const SIZE_T READ_CHUNK_SIZE = 1024 * 1024;

// Holds a compiled byte pattern where mask[i] == 1 means exact match
// and mask[i] == 0 means wildcard (matches any byte).
struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

// Tracks scan totals printed at the end of a run.
struct ScanStats {
    SIZE_T regions_scanned;
    SIZE_T bytes_scanned;
    SIZE_T total_hits;
};

// Formats a Win32 error code into a human-readable string so every API
// failure reports why it failed instead of showing only a raw number.
std::string format_win32_error(DWORD err) {
    LPSTR msg_buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    // Ask Windows to allocate and populate the system error text for this code.
    DWORD len = FormatMessageA(flags, nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&msg_buf), 0, nullptr);
    if (len == 0 || msg_buf == nullptr) return "Unknown Win32 error";

    std::string result(msg_buf, len);
    // Free the buffer allocated by FormatMessageA to prevent a memory leak.
    LocalFree(msg_buf);

    while (!result.empty() && (result.back() == '\r' || result.back() == '\n' || result.back() == ' ')) {
        result.pop_back();
    }
    return result;
}

// Formats a 64-bit address or size as a "0x..." hex string.
// Keeping this in a helper avoids leaving std::cout stuck in hex mode.
std::string to_hex_string(uintptr_t value) {
    const char* digits = "0123456789ABCDEF";
    if (value == 0) {
        return "0x0";
    }

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

// Converts one hexadecimal character to its 0..15 value.
// Returns false on invalid characters so the pattern parser can reject them.
bool hex_char_to_nibble(char c, uint8_t& out) {
    if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(10 + (c - 'a')); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(10 + (c - 'A')); return true; }
    return false;
}

// Parses a hex pattern string such as "4D 5A ?? 00 03" into bytes and a mask.
// Rejects empty patterns, odd-length tokens, and invalid hex characters.
bool parse_pattern(const std::string& input, Pattern& out, std::string& err) {
    out.bytes.clear();
    out.mask.clear();

    size_t i = 0;
    while (i < input.size()) {
        while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i]))) {
            ++i;
        }
        if (i >= input.size()) {
            break;
        }

        size_t start = i;
        while (i < input.size() && !std::isspace(static_cast<unsigned char>(input[i]))) {
            ++i;
        }
        std::string token = input.substr(start, i - start);

        if (token.size() % 2 != 0) {
            err = "Odd-length token '" + token + "' in pattern.";
            return false;
        }

        for (size_t k = 0; k < token.size(); k += 2) {
            char hi_ch = token[k];
            char lo_ch = token[k + 1];

            if (hi_ch == '?' && lo_ch == '?') {
                out.bytes.push_back(0);
                out.mask.push_back(0);
            } else {
                uint8_t hi = 0;
                uint8_t lo = 0;
                if (!hex_char_to_nibble(hi_ch, hi) || !hex_char_to_nibble(lo_ch, lo)) {
                    err = "Invalid hex byte '" + token.substr(k, 2) + "' in token '" + token + "'.";
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
    return true;
}

// Searches a memory buffer for all occurrences of pattern p using a naive loop.
// Returns every starting offset within buf where the pattern matches.
std::vector<size_t> find_all(const uint8_t* buf, size_t len, const Pattern& p) {
    std::vector<size_t> hits;
    size_t pat_len = p.bytes.size();

    if (buf == nullptr || pat_len == 0 || len < pat_len) {
        return hits;
    }

    size_t limit = len - pat_len;
    for (size_t i = 0; i <= limit; ++i) {
        bool matched = true;
        for (size_t j = 0; j < pat_len; ++j) {
            if (p.mask[j] != 0 && buf[i + j] != p.bytes[j]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            hits.push_back(i);
        }
    }
    return hits;
}

// Translates a Win32 page protection bitmask into a readable PAGE_* name.
// This helps analysts spot executable or writable memory at a glance.
std::string protection_to_string(DWORD protect) {
    DWORD base = protect & 0xFF;
    std::string name;

    if (base == PAGE_NOACCESS) name = "PAGE_NOACCESS";
    else if (base == PAGE_READONLY) name = "PAGE_READONLY";
    else if (base == PAGE_READWRITE) name = "PAGE_READWRITE";
    else if (base == PAGE_WRITECOPY) name = "PAGE_WRITECOPY";
    else if (base == PAGE_EXECUTE) name = "PAGE_EXECUTE";
    else if (base == PAGE_EXECUTE_READ) name = "PAGE_EXECUTE_READ";
    else if (base == PAGE_EXECUTE_READWRITE) name = "PAGE_EXECUTE_READWRITE";
    else if (base == PAGE_EXECUTE_WRITECOPY) name = "PAGE_EXECUTE_WRITECOPY";
    else name = "PAGE_UNKNOWN(" + to_hex_string(base) + ")";

    if ((protect & PAGE_GUARD) != 0) name += "|PAGE_GUARD";
    if ((protect & PAGE_NOCACHE) != 0) name += "|PAGE_NOCACHE";
    if ((protect & PAGE_WRITECOMBINE) != 0) name += "|PAGE_WRITECOMBINE";
    return name;
}

// Translates MEMORY_BASIC_INFORMATION.Type into IMAGE, MAPPED, or PRIVATE.
// Analysts use region type to distinguish DLLs from dynamically allocated memory.
std::string region_type_to_string(DWORD type) {
    if (type == MEM_IMAGE) return "IMAGE";
    if (type == MEM_MAPPED) return "MAPPED";
    if (type == MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

// Returns true when a region is both MEM_PRIVATE and executable + writable.
// Private RWX memory is a common indicator of injected shellcode or unpacked code.
bool is_private_rwx(const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.Type != MEM_PRIVATE) {
        return false;
    }
    DWORD base = mbi.Protect & 0xFF;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

// Reads one committed region in 1 MB chunks, overlapping by (pattern_len - 1)
// bytes across chunk boundaries so patterns split across reads are still found.
void scan_region(HANDLE proc, const MEMORY_BASIC_INFORMATION& mbi, const Pattern& pat, ScanStats& stats) {
    uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    SIZE_T region_size = mbi.RegionSize;
    SIZE_T overlap = pat.bytes.size() - 1;
    SIZE_T offset = 0;
    SIZE_T prev_overlap = 0;

    stats.regions_scanned += 1;

    while (offset < region_size) {
        SIZE_T remaining = region_size - offset;
        SIZE_T to_read = (remaining < READ_CHUNK_SIZE) ? remaining : READ_CHUNK_SIZE;
        std::vector<uint8_t> buf(to_read);
        SIZE_T bytes_read = 0;

        // Copy remote process bytes into our local buffer for pattern scanning.
        BOOL ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(region_base + offset), buf.data(), to_read, &bytes_read);
        if (!ok) {
            // Query the failure reason immediately before another Win32 call clears it.
            DWORD err = GetLastError();
            std::cout << "[WARN] ReadProcessMemory failed at " << to_hex_string(region_base + offset)
                      << " (read " << bytes_read << "/" << to_read << " bytes): "
                      << format_win32_error(err) << " (err=" << err << ")\n";
        }
        if (bytes_read == 0) break;

        if (bytes_read > prev_overlap) {
            stats.bytes_scanned += (bytes_read - prev_overlap);
        }

        std::vector<size_t> hits = find_all(buf.data(), bytes_read, pat);
        for (size_t i = 0; i < hits.size(); ++i) {
            uintptr_t hit_addr = region_base + offset + hits[i];
            std::string marker = is_private_rwx(mbi) ? "[!] " : "    ";
            std::cout << marker << "HIT addr=" << to_hex_string(hit_addr)
                      << " region_base=" << to_hex_string(region_base)
                      << " region_size=" << to_hex_string(region_size)
                      << " type=" << region_type_to_string(mbi.Type)
                      << " protect=" << protection_to_string(mbi.Protect) << "\n";
            stats.total_hits += 1;
        }

        if (!ok || offset + bytes_read >= region_size || bytes_read <= overlap) break;
        offset += (bytes_read - overlap);
        prev_overlap = overlap;
    }
}

// Walks the target process's virtual address space with VirtualQueryEx and
// scans every committed, readable memory region.
bool scan_process(HANDLE proc, const Pattern& pat, ScanStats& stats) {
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (true) {
        std::memset(&mbi, 0, sizeof(mbi));
        // Query the layout and protection of the region starting at addr.
        SIZE_T queried = VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (queried == 0) {
            // Check why VirtualQueryEx stopped; ERROR_INVALID_PARAMETER marks end of user space.
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER) break;
            std::cout << "[WARN] VirtualQueryEx failed at " << to_hex_string(addr)
                      << ": " << format_win32_error(err) << " (err=" << err << ")\n";
            return false;
        }

        uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T region_size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0 && (mbi.Protect & PAGE_GUARD) == 0) {
            scan_region(proc, mbi, pat, stats);
        }

        if (region_size == 0) break;
        uintptr_t next_addr = region_base + region_size;
        if (next_addr <= addr) break;
        addr = next_addr;
    }
    return true;
}

// Parses the PID argument ("self" or a positive integer) into a Win32 DWORD.
// Returns false if the string is not "self" or a valid numeric PID.
bool parse_pid(const std::string& arg, DWORD& out_pid) {
    if (arg == "self") {
        // Retrieve our own PID so self-scans follow the exact same OpenProcess path.
        out_pid = GetCurrentProcessId();
        return true;
    }

    if (arg.empty()) {
        return false;
    }
    for (size_t i = 0; i < arg.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(arg[i]))) {
            return false;
        }
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

// Prints CLI usage instructions and exit code meanings when arguments are invalid.
void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " <pid|self> \"<hex pattern>\"\n"
              << "Example: " << prog_name << " 1234 \"4D 5A ?? 00 03\"\n"
              << "Exit codes: 0=hits found, 1=no hits, 2=bad args, 3=OpenProcess failed\n";
}

// Entry point: validates CLI args, opens the target process, runs the scan,
// prints summary statistics, closes handles, and exits with a distinct status.
int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argc > 0 ? argv[0] : "scanner.exe");
        return EXIT_BAD_ARGS;
    }

    DWORD pid = 0;
    if (!parse_pid(argv[1], pid)) {
        std::cout << "[ERROR] Invalid PID: '" << argv[1] << "'\n";
        print_usage(argv[0]);
        return EXIT_BAD_ARGS;
    }

    Pattern pat;
    std::string pat_err;
    if (!parse_pattern(argv[2], pat, pat_err)) {
        std::cout << "[ERROR] " << pat_err << "\n";
        print_usage(argv[0]);
        return EXIT_BAD_ARGS;
    }

    // Request handle with memory query and read rights on the target process.
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (proc == nullptr) {
        // Capture the error code immediately to diagnose why access was refused.
        DWORD err = GetLastError();
        std::cout << "[ERROR] OpenProcess failed for PID " << pid << ": "
                  << format_win32_error(err) << " (err=" << err << ")\n";
        if (err == ERROR_ACCESS_DENIED) {
            std::cout << "        Access denied: the target may be a Protected Process (PPL),\n"
                      << "        running as SYSTEM/elevated, or require Administrator/SeDebugPrivilege.\n";
        }
        return EXIT_OPEN_FAILED;
    }

    std::cout << "Scanning PID " << pid << " for " << pat.bytes.size() << "-byte pattern...\n";

    ScanStats stats;
    stats.regions_scanned = 0;
    stats.bytes_scanned = 0;
    stats.total_hits = 0;

    scan_process(proc, pat, stats);

    // Manually release the kernel process handle now that scanning is complete.
    if (!CloseHandle(proc)) {
        // Log if closing the handle somehow fails.
        DWORD err = GetLastError();
        std::cout << "[WARN] CloseHandle failed: " << format_win32_error(err)
                  << " (err=" << err << ")\n";
    }

    std::cout << "\n--- Summary ---\n"
              << "Regions scanned: " << stats.regions_scanned << "\n"
              << "Bytes scanned:   " << stats.bytes_scanned << "\n"
              << "Total hits:      " << stats.total_hits << "\n";

    return (stats.total_hits > 0) ? EXIT_HITS_FOUND : EXIT_NO_HITS;
}
