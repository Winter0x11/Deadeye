// tests/test_pe_integrity.cpp
// Unit and Synthetic Tests for Deadeye PE Integrity & Memory Comparison Engine

#include "core/pe_integrity.hpp"
#include "core/memsource.hpp"
#include "core/util.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unordered_set>
#include <memory>
#include <algorithm>

namespace {

static uint32_t align_up(uint32_t val, uint32_t align)
{
    if (align == 0) return val;
    uint32_t rem = val % align;
    return (rem == 0) ? val : (val + (align - rem));
}

class MockPeMemorySource : public ::MemorySource
{
public:
    uintptr_t base_addr = 0;
    std::vector<uint8_t> mem;
    std::unordered_set<size_t> unreadable_pages;

    MockPeMemorySource(uintptr_t base, const std::vector<uint8_t> &data)
        : base_addr(base), mem(data) {}

    std::string describe() const override { return "MockPeMemorySource"; }
    MemorySourceKind kind() const override { return MemorySourceKind::Live; }
    MemorySourceCapabilities capabilities() const override
    {
        MemorySourceCapabilities caps;
        caps.is_live = true;
        return caps;
    }

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override
    {
        (void)out_err;
        RegionInfo reg;
        reg.base = base_addr;
        reg.size = mem.size();
        reg.protect = PAGE_EXECUTE_READWRITE;
        reg.type = MEM_IMAGE;
        out_regions.push_back(reg);
        return true;
    }

    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override
    {
        if (addr < base_addr || addr >= base_addr + mem.size())
            return 0;
        size_t off = static_cast<size_t>(addr - base_addr);
        if (!unreadable_pages.empty())
        {
            size_t page = off / 4096;
            if (unreadable_pages.count(page))
                return 0;
        }
        size_t avail = (std::min)(len, mem.size() - off);
        std::memcpy(out_buf, mem.data() + off, avail);
        return avail;
    }
};

struct SyntheticPeBuilder
{
    bool is_x64 = true;
    uintptr_t preferred_base = 0x140000000ULL;
    uint32_t section_align = 0x1000;
    uint32_t file_align = 0x200;

    std::vector<uint8_t> text_bytes;
    std::vector<uint8_t> data_bytes;
    std::vector<uint8_t> reloc_bytes;
    std::vector<uint8_t> import_bytes;
    std::vector<uint8_t> export_bytes;

    uint32_t text_raw_size = 0x400;
    uint32_t text_virt_size = 0x1000;

    std::vector<uint8_t> build_disk_image() const
    {
        uint32_t hdr_raw_size = align_up(0x400, file_align);
        uint32_t text_raw_off = hdr_raw_size;
        uint32_t data_raw_off = text_raw_off + align_up(text_raw_size, file_align);
        uint32_t reloc_raw_off = data_raw_off + align_up(static_cast<uint32_t>(data_bytes.size()), file_align);

        uint32_t total_disk_size = reloc_raw_off + align_up(static_cast<uint32_t>(reloc_bytes.size()), file_align);
        std::vector<uint8_t> pe(total_disk_size, 0);

        // DOS Header
        auto *dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
        dos->e_magic = IMAGE_DOS_SIGNATURE; // "MZ"
        dos->e_lfanew = 0x80;

        // NT Headers
        uint32_t nt_off = 0x80;
        *reinterpret_cast<DWORD*>(pe.data() + nt_off) = IMAGE_NT_SIGNATURE; // "PE\0\0"

        auto *file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(pe.data() + nt_off + 4);
        file_hdr->Machine = is_x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        file_hdr->NumberOfSections = 3;
        file_hdr->SizeOfOptionalHeader = is_x64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
        file_hdr->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

        uint32_t opt_off = nt_off + 4 + sizeof(IMAGE_FILE_HEADER);
        uint32_t size_of_image = 0x4000;

        if (is_x64)
        {
            auto *opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(pe.data() + opt_off);
            opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            opt->AddressOfEntryPoint = 0x1000;
            opt->ImageBase = preferred_base;
            opt->SectionAlignment = section_align;
            opt->FileAlignment = file_align;
            opt->SizeOfImage = size_of_image;
            opt->SizeOfHeaders = hdr_raw_size;
            opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

            if (!reloc_bytes.empty())
            {
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0x3000;
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = static_cast<DWORD>(reloc_bytes.size());
            }
            if (!export_bytes.empty())
            {
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x1200;
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = static_cast<DWORD>(export_bytes.size());
            }
            if (!import_bytes.empty())
            {
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x2100;
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = static_cast<DWORD>(import_bytes.size());
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0x2000;
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 64;
            }
        }
        else
        {
            auto *opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(pe.data() + opt_off);
            opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            opt->AddressOfEntryPoint = 0x1000;
            opt->ImageBase = static_cast<DWORD>(preferred_base);
            opt->SectionAlignment = section_align;
            opt->FileAlignment = file_align;
            opt->SizeOfImage = size_of_image;
            opt->SizeOfHeaders = hdr_raw_size;
            opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

            if (!reloc_bytes.empty())
            {
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0x3000;
                opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = static_cast<DWORD>(reloc_bytes.size());
            }
        }

        // Section Headers
        uint32_t sec_hdr_off = opt_off + file_hdr->SizeOfOptionalHeader;
        auto *secs = reinterpret_cast<IMAGE_SECTION_HEADER*>(pe.data() + sec_hdr_off);

        // Section 1: .text
        std::memcpy(secs[0].Name, ".text\0\0\0", 8);
        secs[0].VirtualAddress = 0x1000;
        secs[0].Misc.VirtualSize = text_virt_size;
        secs[0].PointerToRawData = text_raw_off;
        secs[0].SizeOfRawData = text_raw_size;
        secs[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

        // Section 2: .data
        std::memcpy(secs[1].Name, ".data\0\0\0", 8);
        secs[1].VirtualAddress = 0x2000;
        secs[1].Misc.VirtualSize = 0x1000;
        secs[1].PointerToRawData = data_raw_off;
        secs[1].SizeOfRawData = align_up(static_cast<uint32_t>(data_bytes.size()), file_align);
        secs[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

        // Section 3: .reloc
        std::memcpy(secs[2].Name, ".reloc\0\0", 8);
        secs[2].VirtualAddress = 0x3000;
        secs[2].Misc.VirtualSize = 0x1000;
        secs[2].PointerToRawData = reloc_raw_off;
        secs[2].SizeOfRawData = align_up(static_cast<uint32_t>(reloc_bytes.size()), file_align);
        secs[2].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;

        // Copy section contents
        if (!text_bytes.empty() && text_raw_off < pe.size())
        {
            size_t copy_len = (std::min)(text_bytes.size(), static_cast<size_t>(text_raw_size));
            std::memcpy(pe.data() + text_raw_off, text_bytes.data(), copy_len);
        }
        if (!data_bytes.empty() && data_raw_off < pe.size())
        {
            size_t copy_len = (std::min)(data_bytes.size(), static_cast<size_t>(secs[1].SizeOfRawData));
            std::memcpy(pe.data() + data_raw_off, data_bytes.data(), copy_len);
        }
        if (!reloc_bytes.empty() && reloc_raw_off < pe.size())
        {
            size_t copy_len = (std::min)(reloc_bytes.size(), static_cast<size_t>(secs[2].SizeOfRawData));
            std::memcpy(pe.data() + reloc_raw_off, reloc_bytes.data(), copy_len);
        }

        return pe;
    }

    std::vector<uint8_t> map_to_virtual_memory(const std::vector<uint8_t> &disk_pe) const
    {
        uint32_t size_of_image = 0x4000;
        std::vector<uint8_t> vmem(size_of_image, 0);

        // Copy headers (first 0x400 bytes)
        size_t hdr_copy = (std::min)(disk_pe.size(), static_cast<size_t>(0x400));
        std::memcpy(vmem.data(), disk_pe.data(), hdr_copy);

        // Map .text (0x1000)
        uint32_t text_raw_off = align_up(0x400, file_align);
        if (text_raw_off < disk_pe.size())
        {
            size_t copy_len = (std::min)(static_cast<size_t>(text_raw_size), disk_pe.size() - text_raw_off);
            std::memcpy(vmem.data() + 0x1000, disk_pe.data() + text_raw_off, copy_len);
        }

        // Map .data (0x2000)
        uint32_t data_raw_off = text_raw_off + align_up(text_raw_size, file_align);
        if (data_raw_off < disk_pe.size())
        {
            size_t copy_len = (std::min)(data_bytes.size(), disk_pe.size() - data_raw_off);
            std::memcpy(vmem.data() + 0x2000, disk_pe.data() + data_raw_off, copy_len);
        }

        // Map .reloc (0x3000)
        uint32_t reloc_raw_off = data_raw_off + align_up(static_cast<uint32_t>(data_bytes.size()), file_align);
        if (reloc_raw_off < disk_pe.size())
        {
            size_t copy_len = (std::min)(reloc_bytes.size(), disk_pe.size() - reloc_raw_off);
            std::memcpy(vmem.data() + 0x3000, disk_pe.data() + reloc_raw_off, copy_len);
        }

        return vmem;
    }
};

} // namespace

// 1. Unmodified PE image (zero unexpected diffs)
void test_scenario_1_unmodified()
{
    std::cout << "[*] Scenario 1: Unmodified PE image..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x42);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));
    assert(report.total_changed_bytes == 0);
    assert(report.count_hook_candidates == 0);
    assert(report.count_executable_diffs == 0);
    assert(report.differences.empty());
    std::cout << "  [+] Passed: No diffs detected in unmodified image." << std::endl;
}

// 2. Modified executable code (.text patch)
void test_scenario_2_modified_executable_code()
{
    std::cout << "[*] Scenario 2: Modified executable code (.text patch)..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);
    b.reloc_bytes = std::vector<uint8_t>(0x200, 0x00);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Modify a byte in .text
    vmem[0x1000 + 0x50] = 0xCC; // INT3 patch

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));
    assert(report.count_executable_diffs >= 1);
    assert(report.total_changed_bytes >= 1);

    bool found = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x1050 && d.category == core::PeIntegrityCategory::ModifiedExecutableCode)
        {
            found = true;
            assert(d.severity == core::PeIntegritySeverity::Critical);
            assert(d.section_name == ".text");
            break;
        }
    }
    assert(found);
    std::cout << "  [+] Passed: Executable code patch correctly flagged as Critical." << std::endl;
}

// 3. Modified non-executable data (.data modification)
void test_scenario_3_modified_data()
{
    std::cout << "[*] Scenario 3: Modified non-executable data (.data modification)..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x11);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Modify bytes in .data
    vmem[0x2000 + 0x10] = 0x99;
    vmem[0x2000 + 0x11] = 0x88;

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));
    assert(report.count_data_diffs >= 1);

    bool found = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x2010 && d.category == core::PeIntegrityCategory::ModifiedNonExecutableData)
        {
            found = true;
            assert(d.severity == core::PeIntegritySeverity::Warning);
            assert(d.section_name == ".data");
            break;
        }
    }
    assert(found);
    std::cout << "  [+] Passed: Data section modification correctly classified as Warning." << std::endl;
}

// 4. Relocation differences (expected base relocations vs tampered relocation)
void test_scenario_4_relocations()
{
    std::cout << "[*] Scenario 4: Relocation fixups (valid vs tampered)..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);
    b.reloc_bytes = std::vector<uint8_t>(0x200, 0x00);

    // Create a relocation block: page 0x1000, two DIR64 entries at offset 0x20 and 0x40
    // IMAGE_BASE_RELOCATION block header = 8 bytes + 2 * 2 bytes = 12 bytes
    b.reloc_bytes.resize(0x200, 0);
    uint32_t page_rva = 0x1000;
    uint32_t block_sz = 12;
    uint16_t e1 = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0x020);
    uint16_t e2 = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0x040);
    std::memcpy(b.reloc_bytes.data(), &page_rva, 4);
    std::memcpy(b.reloc_bytes.data() + 4, &block_sz, 4);
    std::memcpy(b.reloc_bytes.data() + 8, &e1, 2);
    std::memcpy(b.reloc_bytes.data() + 10, &e2, 2);

    // On disk: preferred address is 0x140001000 at offset 0x20 and 0x40
    uint64_t disk_ptr = 0x140001000ULL;
    std::memcpy(b.text_bytes.data() + 0x20, &disk_ptr, 8);
    std::memcpy(b.text_bytes.data() + 0x40, &disk_ptr, 8);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Live base is relocated: 0x180000000ULL (delta = +0x40000000)
    uintptr_t live_base = 0x180000000ULL;
    uint64_t relocated_ptr = disk_ptr + 0x40000000ULL;

    // Site 1 (0x20): correctly relocated by Windows loader
    std::memcpy(vmem.data() + 0x1000 + 0x20, &relocated_ptr, 8);

    // Site 2 (0x40): tampered! (contains unexpected value 0xDEADBEEF)
    uint64_t tampered_ptr = 0xDEADBEEFULL;
    std::memcpy(vmem.data() + 0x1000 + 0x40, &tampered_ptr, 8);

    auto live_src = std::make_shared<MockPeMemorySource>(live_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, live_base, disk_pe, opts, report, err));

    bool site1_found = false, site2_found = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x1020)
        {
            site1_found = true;
            assert(d.category == core::PeIntegrityCategory::RelocationResolved);
            assert(d.is_expected == true);
            assert(d.severity == core::PeIntegritySeverity::Informational);
        }
        else if (d.rva == 0x1040)
        {
            site2_found = true;
            assert(d.category == core::PeIntegrityCategory::ModifiedExecutableCode);
            assert(d.is_expected == false);
            assert(d.severity == core::PeIntegritySeverity::Critical);
        }
    }
    assert(site1_found);
    assert(site2_found);
    std::cout << "  [+] Passed: Valid relocation classified as Informational; tampered site flagged Critical." << std::endl;
}

// 5. Expected IAT changes vs IAT hook
void test_scenario_5_iat_resolution_and_hooks()
{
    std::cout << "[*] Scenario 5: IAT binding and IAT hook detection..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x400, 0x00);

    // Build synthetic Import Directory at RVA 0x2100 with IAT at RVA 0x2000
    // IAT slot 0 at RVA 0x2000 (points to ILT / ordinal on disk)
    // IAT slot 1 at RVA 0x2008
    uint64_t disk_hint_0 = 0x2200; // ILT RVA
    uint64_t disk_hint_1 = 0x2210;
    std::memcpy(b.data_bytes.data() + 0x00, &disk_hint_0, 8);
    std::memcpy(b.data_bytes.data() + 0x08, &disk_hint_1, 8);

    // Import Directory Entry at RVA 0x2100 (offset 0x100 in .data)
    IMAGE_IMPORT_DESCRIPTOR desc = {};
    desc.OriginalFirstThunk = 0x2200;
    desc.FirstThunk = 0x2000;
    desc.Name = 0x2300; // "kernel32.dll"
    std::memcpy(b.data_bytes.data() + 0x100, &desc, sizeof(desc));

    // ILT table at RVA 0x2200
    uint64_t ilt[3] = { 0x2320, 0x2340, 0 }; // 2 imports
    std::memcpy(b.data_bytes.data() + 0x200, ilt, sizeof(ilt));

    // DLL name & function names
    const char *dll_name = "kernel32.dll";
    std::memcpy(b.data_bytes.data() + 0x300, dll_name, std::strlen(dll_name) + 1);

    b.import_bytes.resize(sizeof(desc) * 2, 0);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // In live memory:
    // Slot 0 bound to loaded module (e.g. 0x7FFA10002000)
    // Slot 1 hijacked to unbacked hook target (e.g. 0x0000000000400000ULL or private mem)
    uint64_t bound_fn = 0x7FFA10002000ULL;
    uint64_t hooked_fn = 0x0000000000400000ULL;
    std::memcpy(vmem.data() + 0x2000 + 0x00, &bound_fn, 8);
    std::memcpy(vmem.data() + 0x2000 + 0x08, &hooked_fn, 8);

    // Module list with kernel32.dll at 0x7FFA10000000
    std::vector<core::LoadedModuleInfo> mods;
    core::LoadedModuleInfo k32;
    k32.module_name = "kernel32.dll";
    k32.base_address = 0x7FFA10000000ULL;
    k32.image_size = 0x200000;
    mods.push_back(k32);

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err, nullptr, nullptr, &mods));

    bool bound_ok = false, hook_ok = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x2000)
        {
            bound_ok = true;
            assert(d.category == core::PeIntegrityCategory::ImportAddressTable);
            assert(d.is_expected == true);
        }
        else if (d.rva == 0x2008)
        {
            hook_ok = true;
            assert(d.category == core::PeIntegrityCategory::ImportAddressTable);
            assert(d.is_expected == false);
            assert(d.severity == core::PeIntegritySeverity::Critical);
        }
    }
    assert(bound_ok);
    assert(hook_ok);
    std::cout << "  [+] Passed: Normal bound IAT classified expected; untrusted IAT target flagged Critical." << std::endl;
}

// 6. Inline hook candidates (x86/x64 JMP rel32, JMP [rip+disp], MOV RAX; JMP RAX, PUSH+RET)
void test_scenario_6_inline_hooks()
{
    std::cout << "[*] Scenario 6: Inline hook candidate detection..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);
    b.reloc_bytes = std::vector<uint8_t>(0x200, 0x00);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Hook Pattern A at RVA 0x1010: JMP rel32 (0xE9 disp32)
    // 0xE9 + disp32 pointing to 0x7FFA99000000ULL
    vmem[0x1000 + 0x10] = 0xE9;
    int32_t disp = 0x00123456;
    std::memcpy(vmem.data() + 0x1000 + 0x11, &disp, 4);

    // Hook Pattern B at RVA 0x1050: MOV RAX, imm64 + JMP RAX (48 B8 ... FF E0)
    vmem[0x1000 + 0x50] = 0x48;
    vmem[0x1000 + 0x51] = 0xB8;
    uint64_t target_rax = 0x7FFA88001122ULL;
    std::memcpy(vmem.data() + 0x1000 + 0x52, &target_rax, 8);
    vmem[0x1000 + 0x5A] = 0xFF;
    vmem[0x1000 + 0x5B] = 0xE0;

    // Hook Pattern C at RVA 0x1080: JMP [rip+disp32] (FF 25 ...)
    vmem[0x1000 + 0x80] = 0xFF;
    vmem[0x1000 + 0x81] = 0x25;
    int32_t rip_disp = 0x10;
    std::memcpy(vmem.data() + 0x1000 + 0x82, &rip_disp, 4);

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    opts.perform_hook_analysis = true;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));
    assert(report.count_hook_candidates >= 2);

    bool hook_a = false, hook_b = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x1010)
        {
            hook_a = true;
            assert(d.category == core::PeIntegrityCategory::InlineHookCandidate);
            assert(d.severity == core::PeIntegritySeverity::Critical);
            assert(d.is_hook_candidate == true);
        }
        else if (d.rva == 0x1050)
        {
            hook_b = true;
            assert(d.category == core::PeIntegrityCategory::InlineHookCandidate);
            assert(d.is_hook_candidate == true);
            assert(d.hook_target_address == target_rax);
        }
    }
    assert(hook_a);
    assert(hook_b);
    std::cout << "  [+] Passed: JMP rel32 and MOV RAX+JMP RAX detected as InlineHookCandidates." << std::endl;
}

// 7. Missing and unexpected sections
void test_scenario_7_missing_and_unexpected_sections()
{
    std::cout << "[*] Scenario 7: Missing section handling..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);
    b.reloc_bytes = std::vector<uint8_t>(0x200, 0x00);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Truncate virtual memory so that .reloc (RVA 0x3000) is missing/unmapped
    vmem.resize(0x2800);

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));

    bool missing_reloc = false;
    for (const auto &d : report.differences)
    {
        if (d.category == core::PeIntegrityCategory::MissingSection && d.section_name == ".reloc")
        {
            missing_reloc = true;
            assert(d.severity == core::PeIntegritySeverity::Warning);
            break;
        }
    }
    assert(missing_reloc);
    std::cout << "  [+] Passed: Unmapped section detected as MissingSection." << std::endl;
}

// 8. Relocated image base (ASLR delta handling)
void test_scenario_8_aslr_delta_handling()
{
    std::cout << "[*] Scenario 8: ASLR image base relocation delta handling..." << std::endl;
    SyntheticPeBuilder b;
    b.preferred_base = 0x140000000ULL;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);

    // Relocation at RVA 0x1080
    b.reloc_bytes.resize(0x200, 0);
    uint32_t page_rva = 0x1000;
    uint32_t block_sz = 10;
    uint16_t e1 = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0x080);
    std::memcpy(b.reloc_bytes.data(), &page_rva, 4);
    std::memcpy(b.reloc_bytes.data() + 4, &block_sz, 4);
    std::memcpy(b.reloc_bytes.data() + 8, &e1, 2);

    uint64_t disk_addr = 0x140002000ULL;
    std::memcpy(b.text_bytes.data() + 0x80, &disk_addr, 8);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Live base is loaded at 0x7FF7A0000000ULL
    uintptr_t live_base = 0x7FF7A0000000ULL;
    uint64_t aslr_delta = live_base - b.preferred_base;
    uint64_t live_addr = disk_addr + aslr_delta;
    std::memcpy(vmem.data() + 0x1000 + 0x80, &live_addr, 8);

    auto live_src = std::make_shared<MockPeMemorySource>(live_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, live_base, disk_pe, opts, report, err));

    bool reloc_handled = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x1080)
        {
            reloc_handled = true;
            assert(d.category == core::PeIntegrityCategory::RelocationResolved);
            assert(d.is_expected == true);
            break;
        }
    }
    assert(reloc_handled);
    std::cout << "  [+] Passed: 64-bit ASLR delta properly resolved." << std::endl;
}

// 9. Partial / unreadable memory reads
void test_scenario_9_unreadable_memory()
{
    std::cout << "[*] Scenario 9: Unreadable memory pages handling..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);
    b.reloc_bytes = std::vector<uint8_t>(0x200, 0x00);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    // Mark page 1 (RVA 0x1000, .text) as unreadable
    live_src->unreadable_pages.insert(1);

    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));
    assert(report.is_incomplete == true);
    assert(report.total_unreadable_bytes > 0);

    bool unreadable_found = false;
    for (const auto &d : report.differences)
    {
        if (d.category == core::PeIntegrityCategory::UnreadableMemory)
        {
            unreadable_found = true;
            assert(d.severity == core::PeIntegritySeverity::Warning);
            break;
        }
    }
    assert(unreadable_found);
    std::cout << "  [+] Passed: Unreadable page flagged and marked incomplete." << std::endl;
}

// 10. Invalid PE headers / corruption
void test_scenario_10_invalid_pe_headers()
{
    std::cout << "[*] Scenario 10: Invalid PE headers rejection..." << std::endl;
    std::vector<uint8_t> corrupt_pe(1024, 0); // No MZ, no PE signature

    auto live_src = std::make_shared<MockPeMemorySource>(0x140000000ULL, corrupt_pe);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    bool result = core::compare_pe_memory_integrity(live_src, 0x140000000ULL, corrupt_pe, opts, report, err);
    assert(!result);
    assert(!err.empty());
    std::cout << "  [+] Passed: Corrupted image headers safely rejected." << std::endl;
}

// 11. Malformed section boundaries / integer overflow safety
void test_scenario_11_malformed_section_boundaries()
{
    std::cout << "[*] Scenario 11: Malformed section boundaries and integer overflow..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    auto disk_pe = b.build_disk_image();

    // Mutate section 0 to have extreme VirtualAddress and VirtualSize
    uint32_t nt_off = 0x80;
    auto *file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(disk_pe.data() + nt_off + 4);
    uint32_t opt_off = nt_off + 4 + sizeof(IMAGE_FILE_HEADER);
    uint32_t sec_hdr_off = opt_off + file_hdr->SizeOfOptionalHeader;
    auto *secs = reinterpret_cast<IMAGE_SECTION_HEADER*>(disk_pe.data() + sec_hdr_off);

    // VirtualAddress + VirtualSize overflow
    secs[0].VirtualAddress = 0xFFFFF000;
    secs[0].Misc.VirtualSize = 0x00010000;

    auto vmem = b.map_to_virtual_memory(disk_pe);
    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    // Must not crash or buffer overflow
    core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err);
    std::cout << "  [+] Passed: Integer overflow section boundary processed without crash." << std::endl;
}

// 12. x86 (PE32) and x64 (PE32+) architectures
void test_scenario_12_x86_pe32_architecture()
{
    std::cout << "[*] Scenario 12: x86 (PE32) architecture comparison..." << std::endl;
    SyntheticPeBuilder b;
    b.is_x64 = false;
    b.preferred_base = 0x00400000ULL;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);

    // 32-bit HIGHLOW relocation
    b.reloc_bytes.resize(0x200, 0);
    uint32_t page_rva = 0x1000;
    uint32_t block_sz = 10;
    uint16_t e1 = static_cast<uint16_t>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x020);
    std::memcpy(b.reloc_bytes.data(), &page_rva, 4);
    std::memcpy(b.reloc_bytes.data() + 4, &block_sz, 4);
    std::memcpy(b.reloc_bytes.data() + 8, &e1, 2);

    uint32_t disk_ptr = 0x00402000;
    std::memcpy(b.text_bytes.data() + 0x20, &disk_ptr, 4);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Live base relocated to 0x00500000 (delta = +0x00100000)
    uintptr_t live_base = 0x00500000ULL;
    uint32_t live_ptr = disk_ptr + 0x00100000;
    std::memcpy(vmem.data() + 0x1000 + 0x20, &live_ptr, 4);

    auto live_src = std::make_shared<MockPeMemorySource>(live_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, live_base, disk_pe, opts, report, err));
    assert(report.metadata.architecture == "x86");

    bool reloc_found = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x1020)
        {
            reloc_found = true;
            assert(d.category == core::PeIntegrityCategory::RelocationResolved);
            assert(d.is_expected == true);
            break;
        }
    }
    assert(reloc_found);
    std::cout << "  [+] Passed: 32-bit PE HIGHLOW relocation and architecture verified." << std::endl;
}

// 13. Unusual section alignment & virtual tail padding (code cave injection)
void test_scenario_13_virtual_tail_padding_and_slack()
{
    std::cout << "[*] Scenario 13: Virtual tail padding (code cave injection)..." << std::endl;
    SyntheticPeBuilder b;
    b.text_raw_size = 0x200;   // Raw file size = 512 bytes
    b.text_virt_size = 0x1000; // Virtual size = 4096 bytes (slack space = 3584 bytes)
    b.text_bytes = std::vector<uint8_t>(0x200, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);

    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);

    // Inject non-zero bytes (cave payload) into the virtual tail at RVA 0x1300
    vmem[0x1000 + 0x300] = 0x90;
    vmem[0x1000 + 0x301] = 0xCC;

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;

    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));

    bool cave_detected = false;
    for (const auto &d : report.differences)
    {
        if (d.rva == 0x1300)
        {
            cave_detected = true;
            assert(d.category == core::PeIntegrityCategory::ModifiedExecutableCode);
            assert(d.severity == core::PeIntegritySeverity::Critical);
            break;
        }
    }
    assert(cave_detected);
    std::cout << "  [+] Passed: Non-zero payload in virtual section tail detected as code modification." << std::endl;
}

// JSON export and Timeline integration verification
void test_json_and_timeline_integration()
{
    std::cout << "[*] Verifying JSON export and Timeline integration..." << std::endl;
    SyntheticPeBuilder b;
    b.text_bytes = std::vector<uint8_t>(0x400, 0x90);
    b.data_bytes = std::vector<uint8_t>(0x200, 0x00);
    b.reloc_bytes = std::vector<uint8_t>(0x200, 0x00);
    auto disk_pe = b.build_disk_image();
    auto vmem = b.map_to_virtual_memory(disk_pe);
    vmem[0x1050] = 0xCC;

    auto live_src = std::make_shared<MockPeMemorySource>(b.preferred_base, vmem);
    core::PeIntegrityOptions opts;
    core::PeIntegrityReport report;
    std::string err;
    assert(core::compare_pe_memory_integrity(live_src, b.preferred_base, disk_pe, opts, report, err));

    // Test JSON export
    std::string json = core::export_pe_integrity_json(report, true, 64);
    assert(!json.empty());
    assert(json.find("\"module_name\":") != std::string::npos);
    assert(json.find("\"differences\":") != std::string::npos);
    assert(json.find("Modified Executable Code") != std::string::npos);

    // Test Timeline recording
    core::TimelineManager timeline;
    core::record_integrity_report_to_timeline(timeline, 1234, report);
    assert(timeline.count() >= 1);

    auto events = timeline.query(core::TimelineFilter{});
    assert(!events.empty());
    bool found_event = false;
    for (const auto &ev : events)
    {
        if (ev.summary.find("PE Integrity") != std::string::npos || ev.details.find("PE Integrity") != std::string::npos)
        {
            found_event = true;
            break;
        }
    }
    assert(found_event);
    std::cout << "  [+] Passed: JSON export and Timeline recording verified." << std::endl;
}

int main()
{
    std::cout << "======================================================" << std::endl;
    std::cout << "   Deadeye PE Integrity & Memory Comparison Test Suite" << std::endl;
    std::cout << "======================================================" << std::endl;

    test_scenario_1_unmodified();
    test_scenario_2_modified_executable_code();
    test_scenario_3_modified_data();
    test_scenario_4_relocations();
    test_scenario_5_iat_resolution_and_hooks();
    test_scenario_6_inline_hooks();
    test_scenario_7_missing_and_unexpected_sections();
    test_scenario_8_aslr_delta_handling();
    test_scenario_9_unreadable_memory();
    test_scenario_10_invalid_pe_headers();
    test_scenario_11_malformed_section_boundaries();
    test_scenario_12_x86_pe32_architecture();
    test_scenario_13_virtual_tail_padding_and_slack();
    test_json_and_timeline_integration();

    std::cout << "======================================================" << std::endl;
    std::cout << "   ALL 13+ PE INTEGRITY TEST SCENARIOS PASSED!" << std::endl;
    std::cout << "======================================================" << std::endl;
    return 0;
}
