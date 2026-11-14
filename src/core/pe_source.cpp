// src/core/pe_source.cpp
// Deadeye Defensive Triage Mapped PE & Raw File MemorySource
#include "core/pe_source.hpp"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cstdio>

uintptr_t MappedPeSource::align_up_val(uintptr_t val, uintptr_t alignment)
{
    if (alignment <= 1) return val;
    uintptr_t rem = val % alignment;
    return (rem == 0) ? val : (val + (alignment - rem));
}

DWORD MappedPeSource::characteristics_to_protect(DWORD ch)
{
    bool r = (ch & IMAGE_SCN_MEM_READ) != 0;
    bool w = (ch & IMAGE_SCN_MEM_WRITE) != 0;
    bool x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;

    if (x)
    {
        if (w) return PAGE_EXECUTE_READWRITE;
        if (r) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static uint8_t* get_mapped_mutable_ptr_internal(std::vector<MappedPeSource::MappedSegment> &segments,
                                                uintptr_t target_vaddr, size_t needed_bytes)
{
    for (auto &seg : segments)
    {
        if (target_vaddr >= seg.vaddr && target_vaddr + needed_bytes <= seg.vaddr + seg.vsize)
        {
            size_t offset_in_seg = static_cast<size_t>(target_vaddr - seg.vaddr);
            if (offset_in_seg + needed_bytes <= seg.data.size())
            {
                return seg.data.data() + offset_in_seg;
            }
        }
    }
    return nullptr;
}

static void apply_base_relocations_internal(MappedPeSource *source,
                                           std::vector<MappedPeSource::MappedSegment> &segments,
                                           uintptr_t effective_base,
                                           PeSummaryInfo &summary,
                                           uint32_t reloc_rva, uint32_t reloc_size, int64_t delta)
{
    std::vector<uint8_t> reloc_buf(reloc_size);
    if (source->read(effective_base + reloc_rva, reloc_size, reloc_buf.data()) < sizeof(IMAGE_BASE_RELOCATION))
    {
        return;
    }

    size_t cursor = 0;
    while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= reloc_size)
    {
        const auto *block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reloc_buf.data() + cursor);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || cursor + block->SizeOfBlock > reloc_size)
        {
            break;
        }

        uint32_t block_rva = block->VirtualAddress;
        size_t entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        const uint16_t *entries = reinterpret_cast<const uint16_t*>(reloc_buf.data() + cursor + sizeof(IMAGE_BASE_RELOCATION));

        for (size_t i = 0; i < entry_count; ++i)
        {
            uint16_t entry = entries[i];
            uint16_t type = (entry >> 12);
            uint16_t offset = (entry & 0x0FFF);

            uintptr_t target_vaddr = effective_base + block_rva + offset;

            if (type == IMAGE_REL_BASED_ABSOLUTE)
            {
                continue;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                uint8_t *ptr = get_mapped_mutable_ptr_internal(segments, target_vaddr, 4);
                if (ptr)
                {
                    int32_t val = 0;
                    std::memcpy(&val, ptr, sizeof(val));
                    val += static_cast<int32_t>(delta);
                    std::memcpy(ptr, &val, sizeof(val));
                    summary.reloc_fixup_count++;
                }
            }
            else if (type == IMAGE_REL_BASED_DIR64)
            {
                uint8_t *ptr = get_mapped_mutable_ptr_internal(segments, target_vaddr, 8);
                if (ptr)
                {
                    int64_t val = 0;
                    std::memcpy(&val, ptr, sizeof(val));
                    val += delta;
                    std::memcpy(ptr, &val, sizeof(val));
                    summary.reloc_fixup_count++;
                }
            }
            else
            {
                summary.reloc_skipped_count++;
            }
        }

        cursor += block->SizeOfBlock;
    }
}

static void rebuild_cached_regions_internal(const std::vector<MappedPeSource::MappedSegment> &segments,
                                           uintptr_t effective_base,
                                           std::vector<RegionInfo> &cached_regions)
{
    cached_regions.clear();
    for (const auto &seg : segments)
    {
        RegionInfo reg;
        reg.base = seg.vaddr;
        reg.size = seg.vsize;
        reg.type = MEM_IMAGE;
        reg.protect = seg.protect;
        reg.alloc_base = effective_base;
        reg.alloc_protect = PAGE_READONLY;
        reg.last_entropy = seg.entropy;
        reg.entropy = seg.entropy;
        reg.section_name = seg.name;

        cached_regions.push_back(reg);
    }
}

std::shared_ptr<MappedPeSource> MappedPeSource::open(
    const std::string &filepath,
    uintptr_t override_base,
    bool apply_relocations,
    std::string &out_err)
{
    out_err.clear();
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        out_err = "Could not open file: " + filepath;
        return nullptr;
    }

    uint64_t file_size = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (file_size == 0)
    {
        out_err = "File is empty (0 bytes).";
        return nullptr;
    }

    static const uint64_t MAX_PE_FILE_SIZE = 256ULL * 1024ULL * 1024ULL;
    if (file_size > MAX_PE_FILE_SIZE)
    {
        out_err = "File size (" + std::to_string(file_size / (1024 * 1024)) +
                  " MB) exceeds the 256 MB safety cap.";
        return nullptr;
    }

    std::vector<uint8_t> raw_bytes(static_cast<size_t>(file_size));
    file.read(reinterpret_cast<char*>(raw_bytes.data()), static_cast<std::streamsize>(file_size));
    if (!file)
    {
        out_err = "Failed to read binary data from: " + filepath;
        return nullptr;
    }

    if (file_size < sizeof(IMAGE_DOS_HEADER))
    {
        out_err = "File too small to contain a valid DOS header (" + std::to_string(file_size) + " bytes).";
        return nullptr;
    }

    const auto *dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_bytes.data());
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        out_err = "Invalid DOS header signature (expected 'MZ').";
        return nullptr;
    }

    if (dos_hdr->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        static_cast<uint64_t>(dos_hdr->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > file_size)
    {
        out_err = "Corrupt PE header: e_lfanew offset (0x" + to_hex_string(static_cast<uint32_t>(dos_hdr->e_lfanew)) +
                  ") points outside valid file bounds.";
        return nullptr;
    }

    const size_t pe_offset = static_cast<size_t>(dos_hdr->e_lfanew);
    const DWORD nt_sig = *reinterpret_cast<const DWORD*>(raw_bytes.data() + pe_offset);
    if (nt_sig != IMAGE_NT_SIGNATURE)
    {
        out_err = "Invalid NT header signature (expected 'PE\\0\\0').";
        return nullptr;
    }

    const auto *file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(raw_bytes.data() + pe_offset + sizeof(DWORD));
    if (file_hdr->NumberOfSections > 96)
    {
        out_err = "NumberOfSections (" + std::to_string(file_hdr->NumberOfSections) +
                  ") exceeds safety limit (maximum 96 sections allowed).";
        return nullptr;
    }

    const size_t opt_offset = pe_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (opt_offset + file_hdr->SizeOfOptionalHeader > file_size)
    {
        out_err = "OptionalHeader extends past end of file.";
        return nullptr;
    }

    if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        out_err = "SizeOfOptionalHeader is too small to contain valid PE optional headers.";
        return nullptr;
    }

    const uint16_t opt_magic = *reinterpret_cast<const uint16_t*>(raw_bytes.data() + opt_offset);
    bool is_64 = false;
    if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        is_64 = true;
    }
    else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        is_64 = false;
    }
    else
    {
        char hx[16];
        std::snprintf(hx, sizeof(hx), "0x%04X", opt_magic);
        out_err = "Unsupported PE OptionalHeader Magic " + std::string(hx) + "; expected PE32 or PE32+.";
        return nullptr;
    }

    uintptr_t orig_image_base = 0;
    uint32_t section_align = 0;
    uint32_t file_align = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t entry_point_rva = 0;
    uint16_t subsystem = 0;
    uint32_t num_rva_and_sizes = 0;
    const IMAGE_DATA_DIRECTORY *data_dirs = nullptr;

    if (is_64)
    {
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
        {
            out_err = "SizeOfOptionalHeader is smaller than sizeof(IMAGE_OPTIONAL_HEADER64).";
            return nullptr;
        }
        const auto *opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(raw_bytes.data() + opt_offset);
        orig_image_base = static_cast<uintptr_t>(opt64->ImageBase);
        section_align = opt64->SectionAlignment;
        file_align = opt64->FileAlignment;
        size_of_image = opt64->SizeOfImage;
        size_of_headers = opt64->SizeOfHeaders;
        entry_point_rva = opt64->AddressOfEntryPoint;
        subsystem = opt64->Subsystem;
        num_rva_and_sizes = opt64->NumberOfRvaAndSizes;
        data_dirs = opt64->DataDirectory;
    }
    else
    {
        const auto *opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(raw_bytes.data() + opt_offset);
        orig_image_base = static_cast<uintptr_t>(opt32->ImageBase);
        section_align = opt32->SectionAlignment;
        file_align = opt32->FileAlignment;
        size_of_image = opt32->SizeOfImage;
        size_of_headers = opt32->SizeOfHeaders;
        entry_point_rva = opt32->AddressOfEntryPoint;
        subsystem = opt32->Subsystem;
        num_rva_and_sizes = opt32->NumberOfRvaAndSizes;
        data_dirs = opt32->DataDirectory;
    }

    (void)file_align;
    if (section_align == 0)
    {
        out_err = "Invalid SectionAlignment (0).";
        return nullptr;
    }

    if (size_of_image > MAX_PE_FILE_SIZE)
    {
        out_err = "SizeOfImage (" + std::to_string(size_of_image / (1024 * 1024)) +
                  " MB) exceeds the 256 MB safety cap.";
        return nullptr;
    }

    uintptr_t eff_base = (override_base != 0) ? override_base : orig_image_base;
    if (eff_base == 0)
    {
        eff_base = 0x0000000140000000ULL;
    }

    auto src = std::make_shared<MappedPeSource>();
    src->m_filepath = filepath;
    size_t last_slash = filepath.find_last_of("\\/");
    src->m_filename = (last_slash != std::string::npos) ? filepath.substr(last_slash + 1) : filepath;
    src->m_effective_base = eff_base;
    src->m_apply_relocations = apply_relocations;

    PeSummaryInfo &summary = src->m_summary;
    summary.is_pe = true;
    summary.is_pe32_plus = is_64;
    summary.machine = file_hdr->Machine;
    summary.image_base = orig_image_base;
    summary.effective_base = eff_base;
    summary.entry_point_rva = entry_point_rva;
    summary.section_count = file_hdr->NumberOfSections;
    summary.file_size = file_size;
    summary.subsystem = subsystem;

    switch (file_hdr->Machine)
    {
        case IMAGE_FILE_MACHINE_AMD64: summary.machine_name = "x64 (AMD64)"; break;
        case IMAGE_FILE_MACHINE_I386:  summary.machine_name = "x86 (I386)"; break;
        case IMAGE_FILE_MACHINE_ARM64: summary.machine_name = "ARM64"; break;
        case IMAGE_FILE_MACHINE_ARM:   summary.machine_name = "ARM"; break;
        default: summary.machine_name = "Machine 0x" + to_hex_string(file_hdr->Machine); break;
    }

    switch (subsystem)
    {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:     summary.subsystem_name = "Windows GUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:     summary.subsystem_name = "Windows Console (CUI)"; break;
        case IMAGE_SUBSYSTEM_NATIVE:          summary.subsystem_name = "Native (Driver)"; break;
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: summary.subsystem_name = "EFI Application"; break;
        default: summary.subsystem_name = "Subsystem " + std::to_string(subsystem); break;
    }

    // 1. Build Headers Segment
    SIZE_T aligned_hdr_vsize = static_cast<SIZE_T>(align_up_val(size_of_headers, section_align));
    MappedSegment hdr_seg;
    hdr_seg.name = "Headers";
    hdr_seg.vaddr = eff_base;
    hdr_seg.vsize = aligned_hdr_vsize;
    hdr_seg.protect = PAGE_READONLY;
    hdr_seg.characteristics = IMAGE_SCN_MEM_READ;
    hdr_seg.is_header = true;
    hdr_seg.data.resize(aligned_hdr_vsize, 0);

    SIZE_T copy_hdr_len = std::min<SIZE_T>(size_of_headers, static_cast<SIZE_T>(file_size));
    std::memcpy(hdr_seg.data.data(), raw_bytes.data(), copy_hdr_len);
    hdr_seg.entropy = calculate_buffer_entropy(hdr_seg.data.data(), copy_hdr_len);
    src->m_segments.push_back(std::move(hdr_seg));

    // 2. Build Section Segments
    const size_t sec_table_offset = opt_offset + file_hdr->SizeOfOptionalHeader;
    if (sec_table_offset + file_hdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > file_size)
    {
        summary.parse_warning = "Section header table truncated at EOF.";
    }

    uint64_t max_raw_section_end = copy_hdr_len;

    for (WORD i = 0; i < file_hdr->NumberOfSections; ++i)
    {
        size_t cur_sec_off = sec_table_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (cur_sec_off + sizeof(IMAGE_SECTION_HEADER) > file_size)
            break;

        const auto *sec_hdr = reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw_bytes.data() + cur_sec_off);

        char sec_name_buf[9] = {};
        std::memcpy(sec_name_buf, sec_hdr->Name, 8);

        MappedSegment sec_seg;
        sec_seg.name = sec_name_buf;
        sec_seg.vaddr = eff_base + sec_hdr->VirtualAddress;
        sec_seg.characteristics = sec_hdr->Characteristics;
        sec_seg.protect = characteristics_to_protect(sec_hdr->Characteristics);
        sec_seg.is_header = false;

        SIZE_T raw_vsize = (sec_hdr->Misc.VirtualSize != 0) ? sec_hdr->Misc.VirtualSize : sec_hdr->SizeOfRawData;
        SIZE_T aligned_vsize = static_cast<SIZE_T>(align_up_val(raw_vsize, section_align));
        sec_seg.vsize = aligned_vsize;
        sec_seg.data.resize(aligned_vsize, 0);

        if (sec_hdr->PointerToRawData < file_size && sec_hdr->SizeOfRawData > 0)
        {
            uint64_t raw_end = static_cast<uint64_t>(sec_hdr->PointerToRawData) + sec_hdr->SizeOfRawData;
            if (raw_end > max_raw_section_end)
            {
                max_raw_section_end = raw_end;
            }

            SIZE_T to_copy = std::min<SIZE_T>(sec_hdr->SizeOfRawData, raw_vsize);
            if (static_cast<uint64_t>(sec_hdr->PointerToRawData) + to_copy > file_size)
            {
                to_copy = static_cast<SIZE_T>(file_size - sec_hdr->PointerToRawData);
            }
            std::memcpy(sec_seg.data.data(), raw_bytes.data() + sec_hdr->PointerToRawData, to_copy);
            sec_seg.entropy = calculate_buffer_entropy(sec_seg.data.data(), to_copy);
        }

        if (entry_point_rva >= sec_hdr->VirtualAddress &&
            entry_point_rva < sec_hdr->VirtualAddress + raw_vsize)
        {
            summary.entry_point_section = sec_seg.name;
        }

        src->m_segments.push_back(std::move(sec_seg));
    }

    if (file_size > max_raw_section_end)
    {
        summary.overlay_offset = max_raw_section_end;
        summary.overlay_size = file_size - max_raw_section_end;
    }

    bool ep_in_exec = false;
    if (entry_point_rva != 0)
    {
        for (const auto &seg : src->m_segments)
        {
            if (!seg.is_header && (seg.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            {
                uintptr_t ep_abs = eff_base + entry_point_rva;
                if (ep_abs >= seg.vaddr && ep_abs < seg.vaddr + seg.vsize)
                {
                    ep_in_exec = true;
                    break;
                }
            }
        }
    }
    summary.ep_outside_exec_sections = (entry_point_rva != 0 && !ep_in_exec);

    int64_t delta = static_cast<int64_t>(eff_base) - static_cast<int64_t>(orig_image_base);
    if (apply_relocations && delta != 0 && num_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
    {
        const auto &reloc_dir = data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0)
        {
            summary.has_relocations = true;
            apply_base_relocations_internal(src.get(), src->m_segments, eff_base, summary,
                                           reloc_dir.VirtualAddress, reloc_dir.Size, delta);
        }
    }

    rebuild_cached_regions_internal(src->m_segments, eff_base, src->m_cached_regions);
    return src;
}

std::string MappedPeSource::describe() const
{
    char bbuf[32];
    std::snprintf(bbuf, sizeof(bbuf), "0x%016llX", static_cast<unsigned long long>(m_effective_base));
    return "mapped PE: " + m_filename + ", base " + bbuf;
}

MemorySourceKind MappedPeSource::kind() const
{
    return MemorySourceKind::MappedPe;
}

MemorySourceCapabilities MappedPeSource::capabilities() const
{
    MemorySourceCapabilities caps;
    caps.is_live = false;
    caps.has_protection = true;
    caps.has_allocation_info = true;
    caps.has_peb_access = false;
    caps.protection_is_synthetic = true;
    return caps;
}

uintptr_t MappedPeSource::get_base_address() const
{
    return m_effective_base;
}

std::string MappedPeSource::get_file_path() const
{
    return m_filepath;
}

bool MappedPeSource::get_pe_summary(PeSummaryInfo &out_info) const
{
    out_info = m_summary;
    return true;
}

bool MappedPeSource::query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err)
{
    out_err.clear();
    out_regions = m_cached_regions;
    return true;
}

SIZE_T MappedPeSource::read(uintptr_t addr, SIZE_T len, uint8_t *out_buf)
{
    if (len == 0 || out_buf == nullptr) return 0;
    std::memset(out_buf, 0, len);

    SIZE_T total_read = 0;
    uintptr_t cur_addr = addr;
    SIZE_T rem = len;

    while (rem > 0)
    {
        bool found_seg = false;
        for (const auto &seg : m_segments)
        {
            if (cur_addr >= seg.vaddr && cur_addr < seg.vaddr + seg.vsize)
            {
                found_seg = true;
                size_t seg_offset = static_cast<size_t>(cur_addr - seg.vaddr);
                size_t avail = seg.vsize - seg_offset;
                size_t to_copy = std::min<size_t>(rem, avail);

                if (seg_offset < seg.data.size())
                {
                    size_t data_copy = std::min<size_t>(to_copy, seg.data.size() - seg_offset);
                    std::memcpy(out_buf + (cur_addr - addr), seg.data.data() + seg_offset, data_copy);
                    total_read += data_copy;
                }

                cur_addr += to_copy;
                rem -= to_copy;
                break;
            }
        }

        if (!found_seg)
        {
            uintptr_t next_seg_vaddr = UINTPTR_MAX;
            for (const auto &seg : m_segments)
            {
                if (seg.vaddr > cur_addr && seg.vaddr < next_seg_vaddr)
                {
                    next_seg_vaddr = seg.vaddr;
                }
            }

            if (next_seg_vaddr == UINTPTR_MAX || next_seg_vaddr >= cur_addr + rem)
            {
                break;
            }

            size_t gap_len = static_cast<size_t>(next_seg_vaddr - cur_addr);
            cur_addr += gap_len;
            rem -= gap_len;
        }
    }

    return total_read;
}

const std::vector<MappedPeSource::MappedSegment>& MappedPeSource::get_segments() const
{
    return m_segments;
}

RawFileSource::RawFileSource(const std::string &filepath, uintptr_t base_addr, std::vector<uint8_t> &&bytes)
    : m_filepath(filepath), m_base(base_addr), m_bytes(std::move(bytes))
{
    size_t last_slash = filepath.find_last_of("\\/");
    m_filename = (last_slash != std::string::npos) ? filepath.substr(last_slash + 1) : filepath;

    RegionInfo reg;
    reg.base = m_base;
    reg.size = m_bytes.size();
    reg.type = MEM_PRIVATE;
    reg.protect = PAGE_READONLY;
    reg.alloc_base = m_base;
    reg.alloc_protect = PAGE_READONLY;
    reg.last_entropy = calculate_buffer_entropy(m_bytes.data(), m_bytes.size());

    m_cached_regions.push_back(reg);
}

std::shared_ptr<RawFileSource> RawFileSource::open(
    const std::string &filepath,
    uintptr_t base_addr,
    std::string &out_err)
{
    out_err.clear();
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        out_err = "Could not open file: " + filepath;
        return nullptr;
    }

    uint64_t file_size = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (file_size == 0)
    {
        out_err = "File is empty (0 bytes).";
        return nullptr;
    }

    static const uint64_t MAX_RAW_FILE_SIZE = 256ULL * 1024ULL * 1024ULL;
    if (file_size > MAX_RAW_FILE_SIZE)
    {
        out_err = "File size (" + std::to_string(file_size / (1024 * 1024)) +
                  " MB) exceeds the 256 MB safety cap.";
        return nullptr;
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(file_size));
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(file_size));
    if (!file)
    {
        out_err = "Failed to read binary data from: " + filepath;
        return nullptr;
    }

    if (base_addr == 0)
    {
        base_addr = 0x0000000100000000ULL;
    }

    return std::make_shared<RawFileSource>(filepath, base_addr, std::move(bytes));
}

std::string RawFileSource::describe() const
{
    char bbuf[32];
    std::snprintf(bbuf, sizeof(bbuf), "0x%016llX", static_cast<unsigned long long>(m_base));
    return "raw file: " + m_filename + ", base " + bbuf + " (" + std::to_string(m_bytes.size()) + " bytes)";
}

MemorySourceKind RawFileSource::kind() const
{
    return MemorySourceKind::RawFile;
}

MemorySourceCapabilities RawFileSource::capabilities() const
{
    MemorySourceCapabilities caps;
    caps.is_live = false;
    caps.has_protection = false;
    caps.has_allocation_info = false;
    caps.has_peb_access = false;
    caps.protection_is_synthetic = true;
    return caps;
}

uintptr_t RawFileSource::get_base_address() const
{
    return m_base;
}

std::string RawFileSource::get_file_path() const
{
    return m_filepath;
}

bool RawFileSource::query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err)
{
    out_err.clear();
    out_regions = m_cached_regions;
    return true;
}

SIZE_T RawFileSource::read(uintptr_t addr, SIZE_T len, uint8_t *out_buf)
{
    if (len == 0 || out_buf == nullptr) return 0;
    std::memset(out_buf, 0, len);

    if (addr >= m_base && addr < m_base + m_bytes.size())
    {
        size_t offset = static_cast<size_t>(addr - m_base);
        size_t avail = m_bytes.size() - offset;
        size_t to_copy = std::min<size_t>(len, avail);
        std::memcpy(out_buf, m_bytes.data() + offset, to_copy);
        return to_copy;
    }
    return 0;
}

bool get_pe_default_base(const std::string &filepath, uintptr_t &out_base, bool &out_is_pe)
{
    out_base = 0x140000000ULL;
    out_is_pe = false;
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;
    IMAGE_DOS_HEADER dos = {};
    if (!file.read(reinterpret_cast<char*>(&dos), sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (dos.e_lfanew <= 0 || dos.e_lfanew > 64 * 1024 * 1024)
        return false;
    file.seekg(dos.e_lfanew, std::ios::beg);
    DWORD nt_sig = 0;
    if (!file.read(reinterpret_cast<char*>(&nt_sig), sizeof(nt_sig)) || nt_sig != IMAGE_NT_SIGNATURE)
        return false;
    IMAGE_FILE_HEADER file_hdr = {};
    if (!file.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr)))
        return false;
    out_is_pe = true;
    uint16_t opt_magic = 0;
    if (!file.read(reinterpret_cast<char*>(&opt_magic), sizeof(opt_magic)))
        return true;
    if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        file.seekg(dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), std::ios::beg);
        IMAGE_OPTIONAL_HEADER64 opt64 = {};
        if (file.read(reinterpret_cast<char*>(&opt64), sizeof(opt64)))
            out_base = static_cast<uintptr_t>(opt64.ImageBase);
    }
    else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        file.seekg(dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), std::ios::beg);
        IMAGE_OPTIONAL_HEADER32 opt32 = {};
        if (file.read(reinterpret_cast<char*>(&opt32), sizeof(opt32)))
            out_base = static_cast<uintptr_t>(opt32.ImageBase);
    }
    return true;
}
