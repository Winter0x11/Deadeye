// tests/test_target.cpp
// Deadeye Defensive Triage & Detection Engineering Test Target
// Simulates live malware memory behaviors:
//   1. Sleep Obfuscation (Ekko/Foliage simulation): Encrypted at rest (RW) <-> Decrypted active (RX)
//   2. Live In-Memory Unpack: Packed buffer (RW) -> Decrypted payload + C2 Strings -> (RX)
//   3. Injected PE in Private Memory: MZ/PE headers in MEM_PRIVATE with RWX
//   4. Continuous In-Place Memory Mutation: Beacon heartbeat state updates
//   5. Dynamic Allocation/Deallocation for Process-Wide Diff Testing

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <conio.h>

std::string to_hex_ptr(const void *p)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(p)));
    return std::string(buf);
}

// Simulated Memory Regions
static uint8_t *g_sleep_buf = nullptr;
static const SIZE_T SLEEP_BUF_SIZE = 64 * 1024;
static std::atomic<bool> g_sleep_is_encrypted{false};
static std::atomic<int> g_sleep_flip_count{0};

static uint8_t *g_unpack_buf = nullptr;
static const SIZE_T UNPACK_BUF_SIZE = 64 * 1024;
static std::atomic<bool> g_is_unpacked{false};

static uint8_t *g_pe_in_priv_buf = nullptr;
static const SIZE_T PE_BUF_SIZE = 64 * 1024;

static uint8_t *g_beacon_buf = nullptr;
static const SIZE_T BEACON_BUF_SIZE = 32 * 1024;
static std::atomic<uint64_t> g_beacon_seq{0};

static uint8_t *g_dynamic_buf = nullptr;
static const SIZE_T DYNAMIC_BUF_SIZE = 64 * 1024;

// Mode 5: High Entropy Executable Buffer (HIGH_ENTROPY_EXEC)
static uint8_t *g_high_ent_exec_buf = nullptr;
static const SIZE_T HIGH_ENT_EXEC_SIZE = 64 * 1024;

// Mode 6: Sleep-mask simulation with rotating 8-byte XOR key (SLEEP_MASK_SUSPECT & KEY_ROTATION_SUSPECT)
static uint8_t *g_sleepmask_rot_buf = nullptr;
static const SIZE_T SLEEPMASK_ROT_SIZE = 64 * 1024;
static std::atomic<int> g_sleepmask_rot_cycle{0};
static std::atomic<bool> g_sleepmask_is_sleeping{false};
static uint8_t g_current_xor_key[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};

// Mode 7: Decrypt-on-wake strings (DECRYPT_ON_WAKE)
static uint8_t *g_decrypt_on_wake_buf = nullptr;
static const SIZE_T DECRYPT_ON_WAKE_SIZE = 64 * 1024;
static std::atomic<bool> g_decrypt_is_decrypted{false};

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_auto_pilot{true};

// Realistic sample x64 instruction sequence
static const uint8_t X64_STUB_TEMPLATE[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08,       // mov [rsp+8], rbx
    0x48, 0x89, 0x6C, 0x24, 0x10,       // mov [rsp+16], rbp
    0x48, 0x89, 0x74, 0x24, 0x18,       // mov [rsp+24], rsi
    0x57,                               // push rdi
    0x48, 0x83, 0xEC, 0x30,             // sub rsp, 30h
    0x48, 0x8B, 0xD9,                   // mov rbx, rcx
    0xE8, 0x10, 0x00, 0x00, 0x00,       // call relative (relocation wildcard test target)
    0x48, 0x85, 0xC0,                   // test rax, rax
    0x74, 0x05,                         // jz short
    0xFF, 0x15, 0x2A, 0x10, 0x00, 0x00, // call [rip + disp32] (RIP-relative wildcard target)
    0x48, 0x83, 0xC4, 0x30,             // add rsp, 30h
    0x5F,                               // pop rdi
    0xC3                                // ret
};

// Simple rolling XOR cipher to simulate in-memory payload encryption
void xor_cipher(uint8_t *data, size_t len, uint8_t key)
{
    for (size_t i = 0; i < len; ++i)
    {
        data[i] ^= static_cast<uint8_t>(key + (i * 13) % 251);
    }
}

// 1. Setup Sleep Obfuscation region
void init_sleep_region()
{
    g_sleep_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, SLEEP_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_sleep_buf) return;

    // Fill with cleartext code template and dummy config
    std::memcpy(g_sleep_buf, X64_STUB_TEMPLATE, sizeof(X64_STUB_TEMPLATE));
    const char *cfg = "CONFIG: TARGET_AGENT=DEADEYE_TEST; AES_KEY_ID=0x4F9B; ROT_TICKS=4";
    std::memcpy(g_sleep_buf + 256, cfg, std::strlen(cfg) + 1);

    // Initial protection: Executable (Active state)
    DWORD old_prot = 0;
    VirtualProtect(g_sleep_buf, SLEEP_BUF_SIZE, PAGE_EXECUTE_READ, &old_prot);
    g_sleep_is_encrypted.store(false);
}

// Toggle sleep obfuscation: Encrypt & RW <-> Decrypt & RX
void toggle_sleep_obfuscation()
{
    if (!g_sleep_buf) return;

    DWORD old_prot = 0;
    bool currently_encrypted = g_sleep_is_encrypted.load();

    if (!currently_encrypted)
    {
        // Transition: ACTIVE -> SLEEPING
        // 1. Reprotect to RW so we can encrypt in-place
        VirtualProtect(g_sleep_buf, SLEEP_BUF_SIZE, PAGE_READWRITE, &old_prot);
        // 2. Encrypt payload memory (entropy rises, bytes scramble)
        xor_cipher(g_sleep_buf, SLEEP_BUF_SIZE, 0x5A);
        g_sleep_is_encrypted.store(true);
        g_sleep_flip_count.fetch_add(1);

        std::cout << "  [SLEEP OBFUSCATION] -> Encrypted payload memory (XOR 0x5A) | Protection: PAGE_READWRITE (Flip #"
                  << g_sleep_flip_count.load() << ")\n";
    }
    else
    {
        // Transition: SLEEPING -> ACTIVE
        // 1. Decrypt payload memory while still RW
        xor_cipher(g_sleep_buf, SLEEP_BUF_SIZE, 0x5A);
        // 2. Reprotect back to executable
        VirtualProtect(g_sleep_buf, SLEEP_BUF_SIZE, PAGE_EXECUTE_READ, &old_prot);
        g_sleep_is_encrypted.store(false);
        g_sleep_flip_count.fetch_add(1);

        std::cout << "  [WAKEUP ACTIVE]    -> Decrypted payload memory | Protection: PAGE_EXECUTE_READ (Flip #"
                  << g_sleep_flip_count.load() << ")\n";
    }
}

// 2. Setup Unpack Region (Initially RW with encrypted packed blob)
void init_unpack_region()
{
    g_unpack_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, UNPACK_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_unpack_buf) return;

    // Fill with high-entropy pseudo-random bytes (simulating packed blob)
    for (size_t i = 0; i < UNPACK_BUF_SIZE; ++i)
    {
        g_unpack_buf[i] = static_cast<uint8_t>((i * 109 + 37) ^ 0x9D);
    }
    g_is_unpacked.store(false);
}

// Perform Live Unpack: Decrypt into memory, embed C2 indicators, and flip RW -> RX
void trigger_unpack()
{
    if (!g_unpack_buf || g_is_unpacked.load()) return;

    std::cout << "\n>>> [UNPACK TRANSITION TRIGGERED] <<<\n";
    std::cout << "  * Decrypting Stage 2 payload into memory at " << to_hex_ptr(g_unpack_buf) << "...\n";

    // 1. Zero and write x64 code header
    std::memset(g_unpack_buf, 0x90, 512); // NOP sled
    std::memcpy(g_unpack_buf + 64, X64_STUB_TEMPLATE, sizeof(X64_STUB_TEMPLATE));

    // 2. Embed realistic extracted strings for Deadeye's "Revealed Strings" detection
    const char *s_url1  = "https://darkops-c2.threat-sim.net/api/v2/tasks";
    const char *s_url2  = "https://198.51.100.45:8443/beacon.php";
    const char *s_ip    = "203.0.113.88";
    const char *s_path  = "C:\\Windows\\System32\\tasks\\AdobeUpdateTelemetry.exe";
    const char *s_cmd   = "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...";
    const char *s_reg   = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetryHost";

    std::memcpy(g_unpack_buf + 600,  s_url1, std::strlen(s_url1) + 1);
    std::memcpy(g_unpack_buf + 700,  s_url2, std::strlen(s_url2) + 1);
    std::memcpy(g_unpack_buf + 800,  s_ip,   std::strlen(s_ip) + 1);
    std::memcpy(g_unpack_buf + 900,  s_path, std::strlen(s_path) + 1);
    std::memcpy(g_unpack_buf + 1050, s_cmd,  std::strlen(s_cmd) + 1);
    std::memcpy(g_unpack_buf + 1200, s_reg,  std::strlen(s_reg) + 1);

    // Also write wide UTF-16LE string
    const wchar_t *ws_c2 = L"https://backup-c2.apt-simulator.org/checkin";
    std::memcpy(g_unpack_buf + 1400, ws_c2, (wcslen(ws_c2) + 1) * sizeof(wchar_t));

    // 3. Flip protection from PAGE_READWRITE to PAGE_EXECUTE_READ
    DWORD old_prot = 0;
    VirtualProtect(g_unpack_buf, UNPACK_BUF_SIZE, PAGE_EXECUTE_READ, &old_prot);
    g_is_unpacked.store(true);

    std::cout << "  * Protection flipped: PAGE_READWRITE -> PAGE_EXECUTE_READ\n";
    std::cout << "  * Unpacked strings exposed: URLs, IPs, Cmdlines, Registry persistence.\n";
    std::cout << "  * Deadeye detection: Check Heartbeat Timeline for BEHAVIOR_UNPACK (+50 pts) and press Ctrl+U!\n\n";
}

// 3. Setup PE Header in Private Memory (Reflective Injection / Process Hollowing simulation)
void init_injected_pe_region()
{
    g_pe_in_priv_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, PE_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!g_pe_in_priv_buf) return;

    std::memset(g_pe_in_priv_buf, 0, PE_BUF_SIZE);

    // Build minimal genuine PE/COFF header
    auto *dos_hdr = reinterpret_cast<IMAGE_DOS_HEADER*>(g_pe_in_priv_buf);
    dos_hdr->e_magic = IMAGE_DOS_SIGNATURE; // 'MZ' (0x5A4D)
    dos_hdr->e_lfanew = 0x80;

    auto *nt_hdrs = reinterpret_cast<IMAGE_NT_HEADERS64*>(g_pe_in_priv_buf + dos_hdr->e_lfanew);
    nt_hdrs->Signature = IMAGE_NT_SIGNATURE; // 'PE\0\0' (0x00004550)
    nt_hdrs->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt_hdrs->FileHeader.NumberOfSections = 2;
    nt_hdrs->FileHeader.TimeDateStamp = 0x65F0C000;
    nt_hdrs->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt_hdrs->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;

    nt_hdrs->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt_hdrs->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt_hdrs->OptionalHeader.ImageBase = reinterpret_cast<uintptr_t>(g_pe_in_priv_buf);
    nt_hdrs->OptionalHeader.SectionAlignment = 0x1000;
    nt_hdrs->OptionalHeader.FileAlignment = 0x200;
    nt_hdrs->OptionalHeader.SizeOfImage = static_cast<DWORD>(PE_BUF_SIZE);
    nt_hdrs->OptionalHeader.SizeOfHeaders = 0x400;
    nt_hdrs->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

    // Section header: .text
    auto *sec1 = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<uint8_t*>(&nt_hdrs->OptionalHeader) + nt_hdrs->FileHeader.SizeOfOptionalHeader);
    std::memcpy(sec1->Name, ".text\0\0\0", 8);
    sec1->VirtualAddress = 0x1000;
    sec1->Misc.VirtualSize = 0x4000;
    sec1->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // Put some code at entry point
    std::memcpy(g_pe_in_priv_buf + 0x1000, X64_STUB_TEMPLATE, sizeof(X64_STUB_TEMPLATE));
}

// 4. Setup Live Beacon State (Mutates dynamically)
void init_beacon_region()
{
    g_beacon_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, BEACON_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_beacon_buf) return;
    std::memset(g_beacon_buf, 0, BEACON_BUF_SIZE);
}

void mutate_beacon_region()
{
    if (!g_beacon_buf) return;
    uint64_t seq = g_beacon_seq.fetch_add(1);
    DWORD tick = GetTickCount();

    char bstate[256];
    std::snprintf(bstate, sizeof(bstate), "BEACON_STATUS: ACTIVE | SEQ=%llu | TICK=%u | CIPHER_ROUND=%llu | HOST_ONLINE=TRUE",
                  static_cast<unsigned long long>(seq), static_cast<unsigned int>(tick), static_cast<unsigned long long>(seq % 16));
    std::memcpy(g_beacon_buf, bstate, std::strlen(bstate) + 1);

    // Randomize tail bytes to change FNV-1a hash and test Deadeye's Diff Proc [~MODIF]
    for (size_t i = 256; i < 512; ++i)
    {
        g_beacon_buf[i] = static_cast<uint8_t>((tick + i * 31) & 0xFF);
    }
}

// 5. Dynamic Allocation & Freeing (Diff test)
void toggle_dynamic_region()
{
    if (g_dynamic_buf == nullptr)
    {
        g_dynamic_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, DYNAMIC_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (g_dynamic_buf)
        {
            std::memset(g_dynamic_buf, 0xCC, DYNAMIC_BUF_SIZE); // INT3 debug padding
            std::memcpy(g_dynamic_buf, X64_STUB_TEMPLATE, sizeof(X64_STUB_TEMPLATE));
            std::cout << "  [+NEW REGION] Allocated new 64KB RWX staging buffer at " << to_hex_ptr(g_dynamic_buf) << "\n";
        }
    }
    else
    {
        void *freed_addr = g_dynamic_buf;
        VirtualFree(g_dynamic_buf, 0, MEM_RELEASE);
        g_dynamic_buf = nullptr;
        std::cout << "  [-FREED REGION] Released staging buffer at " << to_hex_ptr(freed_addr) << "\n";
    }
}

// 6. Setup High Entropy Executable Region (Mode 5: HIGH_ENTROPY_EXEC)
void init_high_entropy_exec_region()
{
    g_high_ent_exec_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, HIGH_ENT_EXEC_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
    if (!g_high_ent_exec_buf) return;

    // Fill with high-entropy pseudo-random bytes (Shannon entropy ~7.95)
    uint32_t seed = 0x1337BEEF;
    for (size_t i = 0; i < HIGH_ENT_EXEC_SIZE; ++i)
    {
        seed = seed * 1664525u + 1013904223u;
        g_high_ent_exec_buf[i] = static_cast<uint8_t>(seed >> 24);
    }
}

// 7. Setup Sleep-Mask Simulation with Rotating 8-byte XOR Key (Mode 6: SLEEP_MASK_SUSPECT & KEY_ROTATION_SUSPECT)
void init_sleepmask_rot_region()
{
    g_sleepmask_rot_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, SLEEPMASK_ROT_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_sleepmask_rot_buf) return;

    // Fill with high-entropy encrypted shellcode template
    uint32_t seed = 0x98765432;
    for (size_t i = 0; i < SLEEPMASK_ROT_SIZE; ++i)
    {
        seed = seed * 1103515245u + 12345u;
        g_sleepmask_rot_buf[i] = static_cast<uint8_t>(seed >> 16);
    }
    for (size_t i = 0; i < SLEEPMASK_ROT_SIZE; ++i)
    {
        g_sleepmask_rot_buf[i] ^= g_current_xor_key[i % 8];
    }

    DWORD old_prot = 0;
    VirtualProtect(g_sleepmask_rot_buf, SLEEPMASK_ROT_SIZE, PAGE_EXECUTE_READ, &old_prot);
    g_sleepmask_is_sleeping.store(false);
}

void trigger_sleepmask_rot_cycle()
{
    if (!g_sleepmask_rot_buf) return;
    DWORD old_prot = 0;
    bool sleeping = g_sleepmask_is_sleeping.load();

    if (!sleeping)
    {
        // Active -> Sleep: Flip protection to PAGE_NOACCESS
        VirtualProtect(g_sleepmask_rot_buf, SLEEPMASK_ROT_SIZE, PAGE_NOACCESS, &old_prot);
        g_sleepmask_is_sleeping.store(true);
        int cyc = g_sleepmask_rot_cycle.fetch_add(1);
        std::cout << "  [SLEEP-MASK] -> Dormant state | Protection: PAGE_NOACCESS (Cycle #" << cyc + 1 << ")\n";
    }
    else
    {
        // Sleep -> Active: Reprotect to RW to rotate XOR key, then flip back to RX
        VirtualProtect(g_sleepmask_rot_buf, SLEEPMASK_ROT_SIZE, PAGE_READWRITE, &old_prot);

        // Rotate 8-byte XOR key (delta key has period 8)
        uint8_t delta_key[8] = {0x24, 0x18, 0x5A, 0x33, 0x7E, 0x91, 0x4D, 0x82};
        for (size_t i = 0; i < SLEEPMASK_ROT_SIZE; ++i)
        {
            g_sleepmask_rot_buf[i] ^= delta_key[i % 8];
        }
        for (int k = 0; k < 8; ++k)
        {
            g_current_xor_key[k] ^= delta_key[k];
        }

        VirtualProtect(g_sleepmask_rot_buf, SLEEPMASK_ROT_SIZE, PAGE_EXECUTE_READ, &old_prot);
        g_sleepmask_is_sleeping.store(false);
        std::cout << "  [SLEEP-MASK] -> Active state | Key rotated (period 8) | Protection: PAGE_EXECUTE_READ\n";
    }
}

// 8. Setup Decrypt-on-Wake Strings Region (Mode 7: DECRYPT_ON_WAKE)
void init_decrypt_on_wake_region()
{
    g_decrypt_on_wake_buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, DECRYPT_ON_WAKE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_decrypt_on_wake_buf) return;

    // Encrypted state initially (high entropy ~7.90)
    uint32_t seed = 0xDEADBEEF;
    for (size_t i = 0; i < DECRYPT_ON_WAKE_SIZE; ++i)
    {
        seed = seed * 1664525u + 1013904223u;
        g_decrypt_on_wake_buf[i] = static_cast<uint8_t>(seed >> 24);
    }
    g_decrypt_is_decrypted.store(false);
}

void trigger_decrypt_on_wake()
{
    if (!g_decrypt_on_wake_buf) return;
    bool is_dec = g_decrypt_is_decrypted.load();

    if (!is_dec)
    {
        // Decrypt into cleartext strings (entropy drops sharply from ~7.90 to ~3.20)
        std::memset(g_decrypt_on_wake_buf, 0x20, DECRYPT_ON_WAKE_SIZE);

        const char *c2_url = "https://c2-covert-apt.darknet.org/gateway/sync";
        const char *c2_ip = "198.51.100.177";
        const char *exfil_path = "C:\\Windows\\Temp\\exfil_archive.dat";
        const char *cmd_exec = "cmd.exe /c whoami & net user & tasklist";
        const char *reg_key = "HKLM\\System\\CurrentControlSet\\Services\\DeadeyeSim";

        std::memcpy(g_decrypt_on_wake_buf + 256, c2_url, std::strlen(c2_url) + 1);
        std::memcpy(g_decrypt_on_wake_buf + 512, c2_ip, std::strlen(c2_ip) + 1);
        std::memcpy(g_decrypt_on_wake_buf + 768, exfil_path, std::strlen(exfil_path) + 1);
        std::memcpy(g_decrypt_on_wake_buf + 1024, cmd_exec, std::strlen(cmd_exec) + 1);
        std::memcpy(g_decrypt_on_wake_buf + 1280, reg_key, std::strlen(reg_key) + 1);

        const wchar_t *w_domain = L"internal-ad.corp-defense.network";
        std::memcpy(g_decrypt_on_wake_buf + 1536, w_domain, (wcslen(w_domain) + 1) * sizeof(wchar_t));

        DWORD old_prot = 0;
        VirtualProtect(g_decrypt_on_wake_buf, DECRYPT_ON_WAKE_SIZE, PAGE_EXECUTE_READ, &old_prot);
        g_decrypt_is_decrypted.store(true);

        std::cout << "\n>>> [DECRYPT-ON-WAKE TRIGGERED] <<<\n";
        std::cout << "  * Decrypted cleartext C2 strings (Entropy dropped: 7.90 -> 3.20)\n";
        std::cout << "  * Protection flipped to PAGE_EXECUTE_READ\n";
        std::cout << "  * Deadeye detection: Check Behavior View (Ctrl+3) for DECRYPT_ON_WAKE (+35 pts)\n";
        std::cout << "    and Strings View (Ctrl+4) with 'New since baseline' (F6)!\n\n";
    }
    else
    {
        // Re-encrypt buffer back to high entropy
        DWORD old_prot = 0;
        VirtualProtect(g_decrypt_on_wake_buf, DECRYPT_ON_WAKE_SIZE, PAGE_READWRITE, &old_prot);
        uint32_t seed = 0xCAFEBABE;
        for (size_t i = 0; i < DECRYPT_ON_WAKE_SIZE; ++i)
        {
            seed = seed * 1664525u + 1013904223u;
            g_decrypt_on_wake_buf[i] = static_cast<uint8_t>(seed >> 24);
        }
        VirtualProtect(g_decrypt_on_wake_buf, DECRYPT_ON_WAKE_SIZE, PAGE_EXECUTE_READ, &old_prot);
        g_decrypt_is_decrypted.store(false);
        std::cout << "  [RE-ENCRYPTED] Buffer returned to encrypted state (H >= 7.90).\n";
    }
}

void print_banner(DWORD pid)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "======================================================================\n";
    std::cout << "       DEADEYE MALWARE SIMULATION & DETECTION TEST TARGET             \n";
    std::cout << "======================================================================\n";
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "  >>> TARGET PID: " << pid << " <<<\n";
    SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "  (Paste this PID into Deadeye or run 'Triage Findings' to inspect)\n";
    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "Active Simulated Memory Regions:\n";
    std::cout << "  [1] Sleep Obfuscation Region:  " << to_hex_ptr(g_sleep_buf) << " (64 KB, RW <-> RX oscillating)\n";
    std::cout << "  [2] Dynamic Unpack Region:     " << to_hex_ptr(g_unpack_buf) << " (64 KB, packed -> cleartext + IOCs)\n";
    std::cout << "  [3] Injected PE in Private:    " << to_hex_ptr(g_pe_in_priv_buf) << " (64 KB, MZ/PE in MEM_PRIVATE)\n";
    std::cout << "  [4] Live Beacon State:         " << to_hex_ptr(g_beacon_buf) << " (32 KB, in-place mutating)\n";
    std::cout << "  [5] High Entropy Executable:   " << to_hex_ptr(g_high_ent_exec_buf) << " (64 KB, H ~ 7.95, RX)\n";
    std::cout << "  [6] Sleep-Mask Rotating XOR:   " << to_hex_ptr(g_sleepmask_rot_buf) << " (64 KB, period 8 XOR key, NOACCESS <-> RX)\n";
    std::cout << "  [7] Decrypt-On-Wake Region:    " << to_hex_ptr(g_decrypt_on_wake_buf) << " (64 KB, H 7.9 -> 3.2 drop + C2 strings)\n";
    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "Controls:\n";
    std::cout << "  [A] Toggle Auto-pilot loop (Sleep cycling, Key rotation, Beacon mutations) [Currently: ON]\n";
    std::cout << "  [1] Trigger Live Unpack Transition (Reveals C2 strings, flips RW->RX)\n";
    std::cout << "  [2] Trigger Sleep Obfuscation Cycle (Encrypt/Decrypt payload)\n";
    std::cout << "  [3] Toggle Dynamic Staging Buffer (Allocates [+NEW] or Frees [-FREED])\n";
    std::cout << "  [4] Mutate Beacon Memory Now\n";
    std::cout << "  [5] Re-randomize High Entropy Executable Buffer (H >= 7.90)\n";
    std::cout << "  [6] Trigger Sleep-Mask Rotating XOR Cycle (NOACCESS <-> RX, Key Period 8)\n";
    std::cout << "  [7] Trigger Decrypt-On-Wake Transition (Sharp entropy drop + C2 strings)\n";
    std::cout << "  [Q] Exit Test Target\n";
    std::cout << "======================================================================\n\n";
}

int main(int argc, char *argv[])
{
    if (argc > 1 && (std::strcmp(argv[1], "0") == 0 || std::strcmp(argv[1], "noauto") == 0 || std::strcmp(argv[1], "pause") == 0))
    {
        g_auto_pilot.store(false);
    }

    DWORD pid = GetCurrentProcessId();

    init_sleep_region();
    init_unpack_region();
    init_injected_pe_region();
    init_beacon_region();
    init_high_entropy_exec_region();
    init_sleepmask_rot_region();
    init_decrypt_on_wake_region();

    print_banner(pid);

    // Background worker thread for auto-pilot behaviors
    std::thread worker([&]() {
        int tick_counter = 0;
        while (g_running.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            tick_counter++;

            if (!g_auto_pilot.load()) continue;

            // Mutate beacon state every 1.5s
            if (tick_counter % 3 == 0)
            {
                mutate_beacon_region();
            }

            // Auto sleep obfuscation cycle every 4s
            if (tick_counter % 8 == 0)
            {
                toggle_sleep_obfuscation();
            }

            // Auto sleep-mask rotating key cycle every 3s
            if (tick_counter % 6 == 0)
            {
                trigger_sleepmask_rot_cycle();
            }

            // Auto unpack trigger after 10 seconds if not already triggered
            if (tick_counter == 20 && !g_is_unpacked.load())
            {
                trigger_unpack();
            }
        }
    });

    // Console input loop
    while (g_running.load())
    {
        if (_kbhit())
        {
            int ch = _getch();
            if (ch == 'q' || ch == 'Q')
            {
                g_running.store(false);
                break;
            }
            else if (ch == 'a' || ch == 'A')
            {
                bool ap = !g_auto_pilot.load();
                g_auto_pilot.store(ap);
                std::cout << ">>> Auto-pilot is now " << (ap ? "[ENABLED]" : "[PAUSED]") << "\n";
            }
            else if (ch == '1')
            {
                trigger_unpack();
            }
            else if (ch == '2')
            {
                toggle_sleep_obfuscation();
            }
            else if (ch == '3')
            {
                toggle_dynamic_region();
            }
            else if (ch == '4')
            {
                mutate_beacon_region();
                std::cout << "  [MUTATED] Beacon heartbeat memory mutated.\n";
            }
            else if (ch == '5')
            {
                init_high_entropy_exec_region();
                std::cout << "  [RE-SEEDED] High entropy executable region refreshed.\n";
            }
            else if (ch == '6')
            {
                trigger_sleepmask_rot_cycle();
            }
            else if (ch == '7')
            {
                trigger_decrypt_on_wake();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    if (worker.joinable())
    {
        worker.join();
    }

    // Cleanup
    if (g_sleep_buf) VirtualFree(g_sleep_buf, 0, MEM_RELEASE);
    if (g_unpack_buf) VirtualFree(g_unpack_buf, 0, MEM_RELEASE);
    if (g_pe_in_priv_buf) VirtualFree(g_pe_in_priv_buf, 0, MEM_RELEASE);
    if (g_beacon_buf) VirtualFree(g_beacon_buf, 0, MEM_RELEASE);
    if (g_dynamic_buf) VirtualFree(g_dynamic_buf, 0, MEM_RELEASE);
    if (g_high_ent_exec_buf) VirtualFree(g_high_ent_exec_buf, 0, MEM_RELEASE);
    if (g_sleepmask_rot_buf) VirtualFree(g_sleepmask_rot_buf, 0, MEM_RELEASE);
    if (g_decrypt_on_wake_buf) VirtualFree(g_decrypt_on_wake_buf, 0, MEM_RELEASE);

    std::cout << "Test target exited cleanly.\n";
    return 0;
}
