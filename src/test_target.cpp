// src/test_target.cpp
// Defensive malware simulation test target for Deadeye memory triage testing.
// Creates memory conditions:
//   1. Private RWX memory (PAGE_EXECUTE_READWRITE)
//   2. Write-then-flip memory (Allocated PAGE_READWRITE -> Flipped to PAGE_EXECUTE_READ)
//   3. Injected PE header in private memory (MZ/PE headers in MEM_PRIVATE)
//   4. Unlinked module (version.dll loaded & unlinked from PEB InLoadOrderModuleList)
//
// Build:
//   g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 src/test_target.cpp -o build/test_target.exe
//   cl /std:c++17 /EHsc /W4 /O2 src/test_target.cpp /Fe:build/test_target.exe

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

std::string ptr_to_hex(const void *ptr)
{
    uintptr_t value = reinterpret_cast<uintptr_t>(ptr);
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

void fill_test_pattern(std::vector<uint8_t> &buf)
{
    buf.clear();
    buf.push_back(0xDE);
    buf.push_back(0xAD);
    buf.push_back(0xBE);
    buf.push_back(0xEF);
    buf.push_back(0x13);
    buf.push_back(0x37);
    buf.push_back(0xCA);
    buf.push_back(0xFE);
}

typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

bool unlink_module_from_peb(HMODULE h_mod)
{
    if (h_mod == nullptr)
        return false;
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
    if (pfnQIP(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &ret_len) != 0 || pbi.PebBaseAddress == nullptr)
    {
        return false;
    }

    uintptr_t peb_addr = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
    uintptr_t ldr_addr = *reinterpret_cast<uintptr_t *>(peb_addr + 0x18);
    if (ldr_addr == 0)
        return false;

    LIST_ENTRY *head = reinterpret_cast<LIST_ENTRY *>(ldr_addr + 0x10);
    LIST_ENTRY *curr = head->Flink;

    while (curr != head && curr != nullptr)
    {
        uintptr_t dll_base = *reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(curr) + 0x30);
        if (dll_base == reinterpret_cast<uintptr_t>(h_mod))
        {
            curr->Blink->Flink = curr->Flink;
            curr->Flink->Blink = curr->Blink;
            return true;
        }
        curr = curr->Flink;
    }
    return false;
}

int main(int argc, char *argv[])
{
    std::string mode_arg = "all";
    if (argc > 1)
    {
        mode_arg = argv[1];
    }

    std::vector<uint8_t> heap_buf;
    fill_test_pattern(heap_buf);

    void *rwx_buf = nullptr;
    void *flip_buf = nullptr;
    void *pe_buf = nullptr;
    HMODULE h_unlinked_mod = nullptr;

    bool do_rwx = (mode_arg == "all" || mode_arg == "1" || mode_arg == "rwx");
    bool do_flip = (mode_arg == "all" || mode_arg == "2" || mode_arg == "flip");
    bool do_pe = (mode_arg == "all" || mode_arg == "3" || mode_arg == "pe");
    bool do_unlnk = (mode_arg == "all" || mode_arg == "4" || mode_arg == "unlink");

    // 1. Private RWX
    if (do_rwx)
    {
        rwx_buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (rwx_buf != nullptr)
        {
            std::memcpy(rwx_buf, heap_buf.data(), heap_buf.size());
        }
    }

    // 2. Write-then-flip (Allocated PAGE_READWRITE -> Flipped to PAGE_EXECUTE_READ)
    if (do_flip)
    {
        flip_buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (flip_buf != nullptr)
        {
            std::memcpy(flip_buf, heap_buf.data(), heap_buf.size());
            DWORD old_prot = 0;
            VirtualProtect(flip_buf, 4096, PAGE_EXECUTE_READ, &old_prot);
        }
    }

    // 3. Injected PE header in private memory (MZ/PE header in MEM_PRIVATE)
    if (do_pe)
    {
        pe_buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pe_buf != nullptr)
        {
            uint8_t *p = reinterpret_cast<uint8_t *>(pe_buf);
            p[0] = 0x4D;
            p[1] = 0x5A; // 'MZ'
            *reinterpret_cast<uint32_t *>(p + 0x3C) = 0x80;
            p[0x80] = 'P';
            p[0x81] = 'E';
            p[0x82] = 0;
            p[0x83] = 0;
            std::memcpy(p + 0x100, heap_buf.data(), heap_buf.size());
            DWORD old_prot = 0;
            VirtualProtect(pe_buf, 4096, PAGE_EXECUTE_READ, &old_prot);
        }
    }

    // 4. Unlinked module via PEB InLoadOrderModuleList
    if (do_unlnk)
    {
        h_unlinked_mod = LoadLibraryA("version.dll");
        if (h_unlinked_mod != nullptr)
        {
            unlink_module_from_peb(h_unlinked_mod);
        }
    }

    DWORD pid = GetCurrentProcessId();

    std::cout << "========================================================\n"
              << " Deadeye Defensive Triage Test Target\n"
              << "========================================================\n"
              << "PID: " << pid << "\n\n";

    std::cout << "Active Conditions & Expected Triage Findings:\n";
    std::cout << "--------------------------------------------------------\n";
    if (rwx_buf != nullptr)
    {
        std::cout << "[1] Private RWX:\n"
                  << "    Addr: " << ptr_to_hex(rwx_buf) << " (4 KB, PAGE_EXECUTE_READWRITE)\n"
                  << "    Expected Flags: PRIVATE_RWX, UNBACKED_EXEC\n"
                  << "    Expected Score: 65 (HIGH)\n\n";
    }
    if (flip_buf != nullptr)
    {
        std::cout << "[2] Write-then-Flip:\n"
                  << "    Addr: " << ptr_to_hex(flip_buf) << " (4 KB, Alloc: RW, Curr: RX)\n"
                  << "    Expected Flags: WRITE_THEN_FLIP, UNBACKED_EXEC\n"
                  << "    Expected Score: 60 (HIGH)\n\n";
    }
    if (pe_buf != nullptr)
    {
        std::cout << "[3] Injected PE Header in Private Memory:\n"
                  << "    Addr: " << ptr_to_hex(pe_buf) << " (4 KB, MEM_PRIVATE, MZ/PE)\n"
                  << "    Expected Flags: INJECTED_PE, WRITE_THEN_FLIP, UNBACKED_EXEC\n"
                  << "    Expected Score: 110 (CRIT)\n\n";
    }
    if (h_unlinked_mod != nullptr)
    {
        std::cout << "[4] Unlinked Module (Hidden via PEB):\n"
                  << "    Base: " << ptr_to_hex(reinterpret_cast<void *>(h_unlinked_mod)) << " (version.dll unlinked from InLoadOrderModuleList)\n"
                  << "    Expected Flags: UNLINKED_MODULE\n"
                  << "    Expected Score: 45 (MED)\n\n";
    }

    std::cout << "Heap buffer: " << ptr_to_hex(heap_buf.data()) << " (Pattern: DE AD BE EF 13 37 CA FE)\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "Commands:\n"
              << "  'm' -> Mutate bytes across buffers (test live heartbeat diff)\n"
              << "  'q' or Enter -> Clean up and exit\n"
              << "Waiting for input...\n";

    std::string line;
    uint32_t counter = 1;
    while (std::getline(std::cin, line))
    {
        if (line == "q" || line.empty())
        {
            break;
        }
        if (line == "m")
        {
            if (rwx_buf != nullptr)
            {
                uint8_t *b = reinterpret_cast<uint8_t *>(rwx_buf);
                b[4] ^= 0xAA;
                b[5] = static_cast<uint8_t>(counter & 0xFF);
            }
            if (flip_buf != nullptr)
            {
                DWORD old_prot = 0;
                VirtualProtect(flip_buf, 4096, PAGE_EXECUTE_READWRITE, &old_prot);
                uint8_t *b = reinterpret_cast<uint8_t *>(flip_buf);
                b[0] = static_cast<uint8_t>(b[0] + 1);
                VirtualProtect(flip_buf, 4096, PAGE_EXECUTE_READ, &old_prot);
            }
            heap_buf[0] = static_cast<uint8_t>(heap_buf[0] + 1);
            counter++;
            std::cout << "[*] Mutated memory buffers (iteration " << counter - 1 << "). Type 'm' to mutate again, Enter/q to quit:\n";
        }
    }

    if (rwx_buf != nullptr)
        VirtualFree(rwx_buf, 0, MEM_RELEASE);
    if (flip_buf != nullptr)
        VirtualFree(flip_buf, 0, MEM_RELEASE);
    if (pe_buf != nullptr)
        VirtualFree(pe_buf, 0, MEM_RELEASE);
    if (h_unlinked_mod != nullptr)
        FreeLibrary(h_unlinked_mod);

    return 0;
}
