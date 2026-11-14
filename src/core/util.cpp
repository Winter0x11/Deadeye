// src/core/util.cpp
// Deadeye Defensive Triage Utility & Conversion Functions
#include "core/util.hpp"
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cctype>

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

std::string escape_json(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s)
    {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20)
        {
            char esc[8];
            std::snprintf(esc, sizeof(esc), "\\u%04X", c);
            out += esc;
        }
        else out += static_cast<char>(c);
    }
    return out;
}

std::string extract_json_str_val(const std::string &line, const std::string &key)
{
    size_t kpos = line.find("\"" + key + "\":");
    if (kpos == std::string::npos) return "";
    size_t colon = line.find(':', kpos);
    if (colon == std::string::npos) return "";
    size_t start = line.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return "";
    size_t end = line.find_last_not_of(" \t\r\n,");
    if (end == std::string::npos || end < start) return "";
    std::string val = line.substr(start, end - start + 1);
    if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
    {
        val = val.substr(1, val.size() - 2);
    }
    return val;
}

uint64_t fnv1a64(const uint8_t *data, size_t len)
{
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i)
    {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

double calculate_shannon_entropy(const uint8_t *data, size_t len)
{
    if (len == 0) return 0.0;
    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i)
    {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i)
    {
        if (counts[i] > 0)
        {
            double p = static_cast<double>(counts[i]) / static_cast<double>(len);
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}
