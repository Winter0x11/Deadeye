// tests/generate_test_pe.cpp
// Generates crafted test PE binaries to exercise Deadeye's loader layout,
// base relocations, section alignment, synthetic protection, and static heuristics.

#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <random>
#include <windows.h>

static uint32_t align_up(uint32_t val, uint32_t align)
{
    if (align == 0) return val;
    uint32_t rem = val % align;
    return (rem == 0) ? val : (val + (align - rem));
}

void build_test_pe_sample(const std::string &filepath, bool trigger_ep_outside)
{
    const uint32_t section_align = 0x1000;
    const uint32_t file_align = 0x200;
    const uint32_t header_size = align_up(0x400, file_align); // 0x400

    // Prepare section raw data buffers
    // 1. .text (normal executable code)
    std::vector<uint8_t> text_raw(file_align, 0x90); // NOP sled + ret
    text_raw[0] = 0x48; text_raw[1] = 0x31; text_raw[2] = 0xC0; // xor rax, rax
    text_raw[3] = 0xC3;                                         // ret

    // 2. .maltext (W+X section)
    std::vector<uint8_t> maltext_raw(file_align, 0xCC); // INT3 sled
    maltext_raw[0] = 0x90; maltext_raw[1] = 0xC3;

    // 3. .packed (high-entropy executable section, entropy ~ 7.95)
    std::vector<uint8_t> packed_raw(file_align * 4, 0); // 2048 bytes
    std::mt19937 rng(1337);
    for (size_t i = 0; i < packed_raw.size(); ++i)
    {
        packed_raw[i] = static_cast<uint8_t>(rng() & 0xFF);
    }

    // 4. .reloc (base relocation block for testing)
    // Structure of IMAGE_BASE_RELOCATION: VirtualAddress (4B), SizeOfBlock (4B), TypeOffset (2B each)
    std::vector<uint8_t> reloc_raw(file_align, 0);
    uint32_t reloc_page_rva = 0x1000;
    // 1 entry: Type 10 (IMAGE_REL_BASED_DIR64) at offset 0x10
    uint16_t entry1 = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0x010);
    uint16_t entry2 = static_cast<uint16_t>((IMAGE_REL_BASED_ABSOLUTE << 12) | 0x000); // padding
    uint32_t block_size = sizeof(uint32_t) * 2 + sizeof(uint16_t) * 2; // 12 bytes

    std::memcpy(reloc_raw.data(), &reloc_page_rva, 4);
    std::memcpy(reloc_raw.data() + 4, &block_size, 4);
    std::memcpy(reloc_raw.data() + 8, &entry1, 2);
    std::memcpy(reloc_raw.data() + 10, &entry2, 2);

    // Section layout calculations
    uint32_t rva_text = 0x1000;
    uint32_t raw_text_off = header_size;

    uint32_t rva_maltext = rva_text + align_up(static_cast<uint32_t>(text_raw.size()), section_align);
    uint32_t raw_maltext_off = raw_text_off + static_cast<uint32_t>(text_raw.size());

    uint32_t rva_packed = rva_maltext + align_up(static_cast<uint32_t>(maltext_raw.size()), section_align);
    uint32_t raw_packed_off = raw_maltext_off + static_cast<uint32_t>(maltext_raw.size());

    uint32_t rva_reloc = rva_packed + align_up(static_cast<uint32_t>(packed_raw.size()), section_align);
    uint32_t raw_reloc_off = raw_packed_off + static_cast<uint32_t>(packed_raw.size());

    uint32_t size_of_image = rva_reloc + align_up(static_cast<uint32_t>(reloc_raw.size()), section_align);

    // DOS Header
    IMAGE_DOS_HEADER dos = {};
    dos.e_magic = IMAGE_DOS_SIGNATURE; // "MZ"
    dos.e_lfanew = 0x80;

    // NT Headers
    DWORD nt_signature = IMAGE_NT_SIGNATURE; // "PE\0\0"

    IMAGE_FILE_HEADER file_hdr = {};
    file_hdr.Machine = IMAGE_FILE_MACHINE_AMD64; // 0x8664
    file_hdr.NumberOfSections = 4;
    file_hdr.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file_hdr.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    IMAGE_OPTIONAL_HEADER64 opt_hdr = {};
    opt_hdr.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; // 0x20B
    opt_hdr.MajorLinkerVersion = 14;
    opt_hdr.MinorLinkerVersion = 0;
    opt_hdr.SizeOfCode = static_cast<uint32_t>(text_raw.size() + maltext_raw.size() + packed_raw.size());
    opt_hdr.SizeOfInitializedData = static_cast<uint32_t>(reloc_raw.size());
    opt_hdr.AddressOfEntryPoint = trigger_ep_outside ? (rva_reloc + 0x20) : (rva_text + 0x00); // Trigger EP outside exec
    opt_hdr.BaseOfCode = rva_text;
    opt_hdr.ImageBase = 0x0000000140000000ULL;
    opt_hdr.SectionAlignment = section_align;
    opt_hdr.FileAlignment = file_align;
    opt_hdr.MajorOperatingSystemVersion = 6;
    opt_hdr.MinorOperatingSystemVersion = 0;
    opt_hdr.MajorSubsystemVersion = 6;
    opt_hdr.MinorSubsystemVersion = 0;
    opt_hdr.SizeOfImage = size_of_image;
    opt_hdr.SizeOfHeaders = header_size;
    opt_hdr.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt_hdr.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    opt_hdr.SizeOfStackReserve = 0x100000;
    opt_hdr.SizeOfStackCommit = 0x1000;
    opt_hdr.SizeOfHeapReserve = 0x100000;
    opt_hdr.SizeOfHeapCommit = 0x1000;
    opt_hdr.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // Relocation directory entry (Index 5)
    opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = rva_reloc;
    opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = block_size;

    // Section 1: .text (RX)
    IMAGE_SECTION_HEADER sec_text = {};
    std::memcpy(sec_text.Name, ".text\0\0\0", 8);
    sec_text.Misc.VirtualSize = 0x80;
    sec_text.VirtualAddress = rva_text;
    sec_text.SizeOfRawData = static_cast<uint32_t>(text_raw.size());
    sec_text.PointerToRawData = raw_text_off;
    sec_text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // Section 2: .maltext (W+X) -> Triggers STATIC_WX_SECTION (+50)
    IMAGE_SECTION_HEADER sec_maltext = {};
    std::memcpy(sec_maltext.Name, ".maltext", 8);
    sec_maltext.Misc.VirtualSize = 0x100;
    sec_maltext.VirtualAddress = rva_maltext;
    sec_maltext.SizeOfRawData = static_cast<uint32_t>(maltext_raw.size());
    sec_maltext.PointerToRawData = raw_maltext_off;
    sec_maltext.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;

    // Section 3: .packed (Executable with entropy ~7.95) -> Triggers STATIC_EXEC_HIGH_ENTROPY (+40)
    IMAGE_SECTION_HEADER sec_packed = {};
    std::memcpy(sec_packed.Name, ".packed\0", 8);
    sec_packed.Misc.VirtualSize = 0x800;
    sec_packed.VirtualAddress = rva_packed;
    sec_packed.SizeOfRawData = static_cast<uint32_t>(packed_raw.size());
    sec_packed.PointerToRawData = raw_packed_off;
    sec_packed.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // Section 4: .reloc (R)
    IMAGE_SECTION_HEADER sec_reloc = {};
    std::memcpy(sec_reloc.Name, ".reloc\0\0", 8);
    sec_reloc.Misc.VirtualSize = block_size;
    sec_reloc.VirtualAddress = rva_reloc;
    sec_reloc.SizeOfRawData = static_cast<uint32_t>(reloc_raw.size());
    sec_reloc.PointerToRawData = raw_reloc_off;
    sec_reloc.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;

    // Overlay (4096 bytes appended after last section) -> Triggers STATIC_NONTRIVIAL_OVERLAY (+25)
    std::vector<uint8_t> overlay(4096, 0xEE);
    const char *overlay_marker = "DEADEYE_MALWARE_EMBEDDED_C2_CONFIG_OVERLAY_PAYLOAD_TEST";
    std::memcpy(overlay.data(), overlay_marker, std::strlen(overlay_marker));

    // Write file
    std::ofstream out(filepath, std::ios::binary);
    if (!out)
    {
        std::cerr << "Failed to open output file: " << filepath << "\n";
        return;
    }

    // Write Headers buffer (padded to header_size)
    std::vector<uint8_t> hdr_buf(header_size, 0);
    std::memcpy(hdr_buf.data(), &dos, sizeof(dos));
    std::memcpy(hdr_buf.data() + dos.e_lfanew, &nt_signature, sizeof(nt_signature));
    size_t cur = dos.e_lfanew + sizeof(nt_signature);
    std::memcpy(hdr_buf.data() + cur, &file_hdr, sizeof(file_hdr));
    cur += sizeof(file_hdr);
    std::memcpy(hdr_buf.data() + cur, &opt_hdr, sizeof(opt_hdr));
    cur += sizeof(opt_hdr);
    std::memcpy(hdr_buf.data() + cur, &sec_text, sizeof(sec_text));
    cur += sizeof(sec_text);
    std::memcpy(hdr_buf.data() + cur, &sec_maltext, sizeof(sec_maltext));
    cur += sizeof(sec_maltext);
    std::memcpy(hdr_buf.data() + cur, &sec_packed, sizeof(sec_packed));
    cur += sizeof(sec_packed);
    std::memcpy(hdr_buf.data() + cur, &sec_reloc, sizeof(sec_reloc));

    out.write(reinterpret_cast<const char*>(hdr_buf.data()), hdr_buf.size());

    // Write Section raw data
    out.write(reinterpret_cast<const char*>(text_raw.data()), text_raw.size());
    out.write(reinterpret_cast<const char*>(maltext_raw.data()), maltext_raw.size());
    out.write(reinterpret_cast<const char*>(packed_raw.data()), packed_raw.size());
    out.write(reinterpret_cast<const char*>(reloc_raw.data()), reloc_raw.size());

    // Write Overlay data
    out.write(reinterpret_cast<const char*>(overlay.data()), overlay.size());
    out.close();

    std::cout << "[+] Created crafted test PE: " << filepath
              << " (" << (hdr_buf.size() + text_raw.size() + maltext_raw.size() + packed_raw.size() + reloc_raw.size() + overlay.size())
              << " bytes, overlay: " << overlay.size() << " bytes)\n";
}

int main()
{
    std::cout << "Building Deadeye test PE binaries...\n\n";

    // 1. Primary test sample: W+X section, high-entropy packed section, non-trivial overlay
    build_test_pe_sample("build/test_malware_sample.exe", false);

    // 2. Anomaly test sample: Entry point located outside executable sections (.reloc), plus W+X & overlay
    build_test_pe_sample("build/test_ep_outside.exe", true);

    std::cout << "\nTest binaries generated successfully in build/!\n";
    return 0;
}
