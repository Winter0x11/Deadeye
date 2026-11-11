#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

// Formats a 64-bit pointer address as a "0x..." hex string.
// Using a helper avoids changing std::cout's formatting flags.
std::string ptr_to_hex(const void* ptr) {
    uintptr_t value = reinterpret_cast<uintptr_t>(ptr);
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

// Populates a buffer with the test pattern DE AD BE EF 13 37 CA FE at runtime.
// Building bytes individually avoids embedding a duplicate copy in .rdata.
void fill_test_pattern(std::vector<uint8_t>& buf) {
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

// Allocates both a heap copy and a VirtualAlloc RWX copy of the test pattern,
// prints its PID and addresses, and waits for Enter before freeing and exiting.
int main() {
    std::vector<uint8_t> heap_buf;
    fill_test_pattern(heap_buf);

    // Reserve and commit a private RWX page to simulate injected code memory.
    void* rwx_buf = VirtualAlloc(
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (rwx_buf == nullptr) {
        // Retrieve the Win32 error code to explain why VirtualAlloc failed.
        DWORD err = GetLastError();
        std::cout << "[ERROR] VirtualAlloc failed with err=" << err << "\n";
        return 1;
    }

    std::memcpy(rwx_buf, heap_buf.data(), heap_buf.size());

    // Reserve and commit a private RX page with a simulated PE header to test [!PE] detection
    void* pe_buf = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pe_buf != nullptr) {
        uint8_t* p = reinterpret_cast<uint8_t*>(pe_buf);
        p[0] = 0x4D; p[1] = 0x5A; // MZ
        *reinterpret_cast<uint32_t*>(p + 0x3C) = 0x80;
        p[0x80] = 'P'; p[0x81] = 'E'; p[0x82] = 0; p[0x83] = 0;
        std::memcpy(p + 0x100, heap_buf.data(), heap_buf.size());
        DWORD old_prot = 0;
        VirtualProtect(pe_buf, 4096, PAGE_EXECUTE_READ, &old_prot);
    }

    // Fetch our process ID so the user can pass it to scanner.exe.
    DWORD pid = GetCurrentProcessId();

    std::cout << "test_target running.\n";
    std::cout << "PID:         " << pid << "\n";
    std::cout << "Heap buffer: " << ptr_to_hex(heap_buf.data()) << " (PRIVATE, RW)\n";
    std::cout << "RWX buffer:  " << ptr_to_hex(rwx_buf) << " (PRIVATE, PAGE_EXECUTE_READWRITE)\n";
    if (pe_buf != nullptr) {
        std::cout << "PE buffer:   " << ptr_to_hex(pe_buf) << " (PRIVATE, PAGE_EXECUTE_READ, Injected PE Header)\n";
    }
    std::cout << "Pattern:     DE AD BE EF 13 37 CA FE\n";
    std::cout << "Commands: enter 'm' to mutate bytes, or press Enter/q to quit...\n";
    std::string line;
    uint32_t counter = 1;
    while (std::getline(std::cin, line)) {
        if (line == "q" || line.empty()) {
            break;
        }
        if (line == "m") {
            uint8_t* rwx_bytes = reinterpret_cast<uint8_t*>(rwx_buf);
            rwx_bytes[4] = static_cast<uint8_t>(rwx_bytes[4] ^ 0xAA);
            rwx_bytes[5] = static_cast<uint8_t>(counter & 0xFF);
            heap_buf[0] = static_cast<uint8_t>(heap_buf[0] + 1);
            counter++;
            std::cout << "[*] Mutated memory (iteration " << counter - 1 << "). Type 'm' to mutate again, Enter to quit:\n";
        }
    }

    // Release allocated regions back to the OS before exiting.
    VirtualFree(rwx_buf, 0, MEM_RELEASE);
    if (pe_buf != nullptr) {
        VirtualFree(pe_buf, 0, MEM_RELEASE);
    }
    return 0;
}
