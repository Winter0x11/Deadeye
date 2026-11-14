// src/core/live_source.cpp
// Deadeye Defensive Triage Live Process MemorySource
#include "core/live_source.hpp"
#include <cstring>

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

HANDLE LiveProcessSource::get_handle()
{
    if (m_proc == nullptr && m_pid != 0)
    {
        m_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_pid);
        m_owns_handle = (m_proc != nullptr);
    }
    return m_proc;
}

LiveProcessSource::LiveProcessSource(DWORD pid, const std::string &name)
    : m_pid(pid), m_process_name(name)
{
    if (m_process_name.empty() && m_pid != 0)
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe))
            {
                do
                {
                    if (pe.th32ProcessID == m_pid)
                    {
                        char nb[MAX_PATH] = {};
                        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nb, sizeof(nb), nullptr, nullptr);
                        m_process_name = nb;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
}

LiveProcessSource::LiveProcessSource(DWORD pid, HANDLE proc, bool take_ownership, const std::string &name)
    : m_pid(pid), m_process_name(name), m_proc(proc), m_owns_handle(take_ownership)
{
}

LiveProcessSource::~LiveProcessSource()
{
    if (m_owns_handle && m_proc != nullptr)
    {
        CloseHandle(m_proc);
        m_proc = nullptr;
    }
}

std::string LiveProcessSource::describe() const
{
    std::string s = "live process: PID " + std::to_string(m_pid);
    if (!m_process_name.empty())
    {
        s += " (" + m_process_name + ")";
    }
    return s;
}

MemorySourceKind LiveProcessSource::kind() const
{
    return MemorySourceKind::Live;
}

MemorySourceCapabilities LiveProcessSource::capabilities() const
{
    MemorySourceCapabilities caps;
    caps.is_live = true;
    caps.has_protection = true;
    caps.has_allocation_info = true;
    caps.has_peb_access = true;
    caps.protection_is_synthetic = false;
    return caps;
}

DWORD LiveProcessSource::get_pid() const
{
    return m_pid;
}

HANDLE LiveProcessSource::get_raw_handle()
{
    return get_handle();
}

bool LiveProcessSource::query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err)
{
    HANDLE proc = get_handle();
    if (proc == nullptr)
    {
        DWORD err = GetLastError();
        out_err = "OpenProcess failed: " + format_win32_error(err);
        return false;
    }
    return query_process_regions(proc, out_regions, out_err);
}

SIZE_T LiveProcessSource::read(uintptr_t addr, SIZE_T len, uint8_t *out_buf)
{
    if (len == 0 || out_buf == nullptr) return 0;
    HANDLE proc = get_handle();
    if (proc == nullptr) return 0;

    SIZE_T bytes_read = 0;
    BOOL ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), out_buf, len, &bytes_read);
    if (ok && bytes_read == len)
    {
        return bytes_read;
    }

    // Page-by-page (4KB) fallback read
    static const SIZE_T PAGE_4K = 4096;
    SIZE_T total_read = 0;
    for (SIZE_T offset = 0; offset < len; offset += PAGE_4K)
    {
        SIZE_T cur_chunk = (len - offset < PAGE_4K) ? (len - offset) : PAGE_4K;
        SIZE_T p_read = 0;
        BOOL p_ok = ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr + offset),
                                      out_buf + offset, cur_chunk, &p_read);
        if (p_ok && p_read > 0)
        {
            total_read += p_read;
        }
        else
        {
            std::memset(out_buf + offset, 0, cur_chunk);
        }
    }
    return total_read;
}

bool LiveProcessSource::query_peb_modules(std::vector<LoadedModuleRange> &modules, bool &wow64_unsupported)
{
    HANDLE proc = get_handle();
    if (proc == nullptr) return false;
    return query_peb_modules_x64(proc, modules, wow64_unsupported);
}
