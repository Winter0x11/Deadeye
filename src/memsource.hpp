// src/memsource.hpp
// Deadeye MemorySource Abstraction & PE Loader Subsystem
// Pure core forensic memory abstractions: LiveProcessSource, MappedPeSource, RawFileSource
// Zero external dependencies, pure standard C++17 and native Win32.

#ifndef DEADEYE_MEMSOURCE_HPP
#define DEADEYE_MEMSOURCE_HPP

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "core/util.hpp"

// ----------------------------------------------------------------------------
// Core Types & Enumerations
// ----------------------------------------------------------------------------

enum class MemorySourceKind
{
    Live,
    MappedPe,
    RawFile
};

struct MemorySourceCapabilities
{
    bool is_live = false;                 // Dynamic live process (threads, handles)
    bool has_protection = false;          // True hardware page protection
    bool has_allocation_info = false;     // AllocationBase & AllocationProtect present
    bool has_peb_access = false;          // PEB InLoadOrderModuleList queryable
    bool protection_is_synthetic = false; // Synthetic protection derived from file metadata
};

struct PeSummaryInfo
{
    bool is_pe = false;
    bool is_pe32_plus = false;            // false = PE32 (32-bit), true = PE32+ (64-bit)
    uint16_t machine = 0;
    std::string machine_name;             // "x64 (AMD64)", "x86 (I386)", etc.
    uint16_t subsystem = 0;
    std::string subsystem_name;           // "Windows GUI", "Windows CUI", etc.
    uintptr_t image_base = 0;             // ImageBase declared in OptionalHeader
    uintptr_t effective_base = 0;         // Virtual base where image is mapped
    uint32_t entry_point_rva = 0;
    std::string entry_point_section;      // Section containing EP (e.g. ".text")
    bool ep_outside_exec_sections = false;// True if EP is outside all executable sections
    size_t section_count = 0;
    uint64_t file_size = 0;
    uint64_t overlay_offset = 0;
    uint64_t overlay_size = 0;            // Bytes past last section raw end
    bool has_relocations = false;
    size_t reloc_fixup_count = 0;
    size_t reloc_skipped_count = 0;
    std::string parse_warning;
};


// ----------------------------------------------------------------------------
// Abstract Base Interface: MemorySource
// ----------------------------------------------------------------------------

class MemorySource
{
public:
    virtual ~MemorySource() = default;

    virtual std::string describe() const = 0;
    virtual MemorySourceKind kind() const = 0;
    virtual MemorySourceCapabilities capabilities() const = 0;
    virtual bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) = 0;
    virtual SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) = 0;

    // Optional metadata accessors
    virtual DWORD get_pid() const { return 0; }
    virtual uintptr_t get_base_address() const { return 0; }
    virtual std::string get_file_path() const { return ""; }
    virtual bool get_pe_summary(PeSummaryInfo &out_info) const { (void)out_info; return false; }
    virtual bool query_peb_modules(std::vector<LoadedModuleRange> &modules, bool &wow64_unsupported)
    {
        modules.clear();
        wow64_unsupported = false;
        return false;
    }

    // Extension point for .dedump / memory dumping
    virtual bool dump_region_to_file(size_t region_idx, const std::string &filepath, std::string &out_err)
    {
        (void)region_idx; (void)filepath;
        out_err = "Memory dumping is reserved for future implementation.";
        return false;
    }
};

// ----------------------------------------------------------------------------
// Implementation: LiveProcessSource
// ----------------------------------------------------------------------------

class LiveProcessSource : public MemorySource
{
private:
    DWORD m_pid = 0;
    std::string m_process_name;
    HANDLE m_proc = nullptr;
    bool m_owns_handle = false;

    HANDLE get_handle()
    {
        if (m_proc == nullptr && m_pid != 0)
        {
            m_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_pid);
            m_owns_handle = (m_proc != nullptr);
        }
        return m_proc;
    }

public:
    LiveProcessSource(DWORD pid, const std::string &name = "")
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

    LiveProcessSource(DWORD pid, HANDLE proc, bool take_ownership, const std::string &name = "")
        : m_pid(pid), m_process_name(name), m_proc(proc), m_owns_handle(take_ownership)
    {
    }

    ~LiveProcessSource() override
    {
        if (m_owns_handle && m_proc != nullptr)
        {
            CloseHandle(m_proc);
            m_proc = nullptr;
        }
    }

    std::string describe() const override
    {
        std::string s = "live process: PID " + std::to_string(m_pid);
        if (!m_process_name.empty())
        {
            s += " (" + m_process_name + ")";
        }
        return s;
    }

    MemorySourceKind kind() const override
    {
        return MemorySourceKind::Live;
    }

    MemorySourceCapabilities capabilities() const override
    {
        MemorySourceCapabilities caps;
        caps.is_live = true;
        caps.has_protection = true;
        caps.has_allocation_info = true;
        caps.has_peb_access = true;
        caps.protection_is_synthetic = false;
        return caps;
    }

    DWORD get_pid() const override
    {
        return m_pid;
    }

    HANDLE get_raw_handle()
    {
        return get_handle();
    }

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override
    {
        out_regions.clear();
        out_err.clear();

        HANDLE proc = get_handle();
        if (proc == nullptr)
        {
            DWORD err = GetLastError();
            out_err = "OpenProcess failed: " + format_win32_error(err);
            return false;
        }

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
                    out_err = format_win32_error(err);
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

    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override
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

    bool query_peb_modules(std::vector<LoadedModuleRange> &modules, bool &wow64_unsupported) override
    {
        HANDLE proc = get_handle();
        if (proc == nullptr) return false;
        return query_peb_modules_x64(proc, modules, wow64_unsupported);
    }
};

// ----------------------------------------------------------------------------
// Implementation: MappedPeSource
// ----------------------------------------------------------------------------

class MappedPeSource : public MemorySource
{
public:
    struct MappedSegment
    {
        std::string name;
        uintptr_t vaddr = 0;
        SIZE_T vsize = 0;
        DWORD protect = 0;
        DWORD characteristics = 0;
        std::vector<uint8_t> data;
        bool is_header = false;
        double entropy = 0.0;
    };

private:
    std::string m_filepath;
    std::string m_filename;
    uintptr_t m_effective_base = 0;
    bool m_apply_relocations = false;
    PeSummaryInfo m_summary;
    std::vector<MappedSegment> m_segments;
    std::vector<RegionInfo> m_cached_regions;

    static uintptr_t align_up_val(uintptr_t val, uintptr_t alignment)
    {
        if (alignment <= 1) return val;
        uintptr_t rem = val % alignment;
        return (rem == 0) ? val : (val + (alignment - rem));
    }

    static DWORD characteristics_to_protect(DWORD ch)
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

public:
    MappedPeSource() = default;

    static std::shared_ptr<MappedPeSource> open(
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

        // Cap at 256 MB for security and memory safety
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

        // Validate DOS header
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
        if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // 0x20B
        {
            is_64 = true;
        }
        else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // 0x10B
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

        // Extract OptionalHeader fields
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

        // Initialize PE Summary
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
        // SizeOfHeaders mapped at base, aligned up to SectionAlignment
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

            // Loader VirtualSize logic: if Misc.VirtualSize == 0, use SizeOfRawData
            SIZE_T raw_vsize = (sec_hdr->Misc.VirtualSize != 0) ? sec_hdr->Misc.VirtualSize : sec_hdr->SizeOfRawData;
            SIZE_T aligned_vsize = static_cast<SIZE_T>(align_up_val(raw_vsize, section_align));
            sec_seg.vsize = aligned_vsize;

            sec_seg.data.resize(aligned_vsize, 0);

            // Copy raw data from file
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

            // Check if Entry Point resides in this section
            if (entry_point_rva >= sec_hdr->VirtualAddress &&
                entry_point_rva < sec_hdr->VirtualAddress + raw_vsize)
            {
                summary.entry_point_section = sec_seg.name;
            }

            src->m_segments.push_back(std::move(sec_seg));
        }

        // Overlay evaluation
        if (file_size > max_raw_section_end)
        {
            summary.overlay_offset = max_raw_section_end;
            summary.overlay_size = file_size - max_raw_section_end;
        }

        // Validate Entry Point execution rights
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

        // 3. Apply Base Relocations if requested and delta != 0
        int64_t delta = static_cast<int64_t>(eff_base) - static_cast<int64_t>(orig_image_base);
        if (apply_relocations && delta != 0 && num_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
        {
            const auto &reloc_dir = data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0)
            {
                summary.has_relocations = true;
                src->apply_base_relocations(reloc_dir.VirtualAddress, reloc_dir.Size, delta);
            }
        }

        // Precompute cached RegionInfo entries
        src->rebuild_cached_regions();
        return src;
    }

private:
    uint8_t* get_mapped_mutable_ptr(uintptr_t target_vaddr, size_t needed_bytes)
    {
        for (auto &seg : m_segments)
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

    void apply_base_relocations(uint32_t reloc_rva, uint32_t reloc_size, int64_t delta)
    {
        // Read raw relocation bytes from mapped memory
        std::vector<uint8_t> reloc_buf(reloc_size);
        if (read(m_effective_base + reloc_rva, reloc_size, reloc_buf.data()) < sizeof(IMAGE_BASE_RELOCATION))
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

                uintptr_t target_vaddr = m_effective_base + block_rva + offset;

                if (type == IMAGE_REL_BASED_ABSOLUTE) // 0: padding
                {
                    continue;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) // 3: 32-bit fixup
                {
                    uint8_t *ptr = get_mapped_mutable_ptr(target_vaddr, 4);
                    if (ptr)
                    {
                        int32_t val = 0;
                        std::memcpy(&val, ptr, sizeof(val));
                        val += static_cast<int32_t>(delta);
                        std::memcpy(ptr, &val, sizeof(val));
                        m_summary.reloc_fixup_count++;
                    }
                }
                else if (type == IMAGE_REL_BASED_DIR64) // 10: 64-bit fixup
                {
                    uint8_t *ptr = get_mapped_mutable_ptr(target_vaddr, 8);
                    if (ptr)
                    {
                        int64_t val = 0;
                        std::memcpy(&val, ptr, sizeof(val));
                        val += delta;
                        std::memcpy(ptr, &val, sizeof(val));
                        m_summary.reloc_fixup_count++;
                    }
                }
                else
                {
                    m_summary.reloc_skipped_count++;
                }
            }

            cursor += block->SizeOfBlock;
        }
    }

    void rebuild_cached_regions()
    {
        m_cached_regions.clear();
        for (const auto &seg : m_segments)
        {
            RegionInfo reg;
            reg.base = seg.vaddr;
            reg.size = seg.vsize;
            reg.type = MEM_IMAGE;
            reg.protect = seg.protect;
            reg.alloc_base = m_effective_base;
            reg.alloc_protect = PAGE_READONLY;
            reg.last_entropy = seg.entropy;
            reg.entropy = seg.entropy;
            reg.section_name = seg.name;

            m_cached_regions.push_back(reg);
        }
    }

public:
    std::string describe() const override
    {
        char bbuf[32];
        std::snprintf(bbuf, sizeof(bbuf), "0x%016llX", static_cast<unsigned long long>(m_effective_base));
        return "mapped PE: " + m_filename + ", base " + bbuf;
    }

    MemorySourceKind kind() const override
    {
        return MemorySourceKind::MappedPe;
    }

    MemorySourceCapabilities capabilities() const override
    {
        MemorySourceCapabilities caps;
        caps.is_live = false;
        caps.has_protection = true;
        caps.has_allocation_info = true;
        caps.has_peb_access = false;
        caps.protection_is_synthetic = true; // Section Characteristics mapped to Win32 protect
        return caps;
    }

    uintptr_t get_base_address() const override
    {
        return m_effective_base;
    }

    std::string get_file_path() const override
    {
        return m_filepath;
    }

    bool get_pe_summary(PeSummaryInfo &out_info) const override
    {
        out_info = m_summary;
        return true;
    }

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override
    {
        out_err.clear();
        out_regions = m_cached_regions;
        return true;
    }

    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override
    {
        if (len == 0 || out_buf == nullptr) return 0;
        std::memset(out_buf, 0, len);

        SIZE_T total_read = 0;
        uintptr_t cur_addr = addr;
        SIZE_T rem = len;

        while (rem > 0)
        {
            // Find which segment covers cur_addr
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
                // Unmapped gap: find next segment starting after cur_addr
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
                    // Remainder is entirely within unmapped gap
                    break;
                }

                size_t gap_len = static_cast<size_t>(next_seg_vaddr - cur_addr);
                cur_addr += gap_len;
                rem -= gap_len;
            }
        }

        return total_read;
    }

    const std::vector<MappedSegment>& get_segments() const
    {
        return m_segments;
    }
};

// ----------------------------------------------------------------------------
// Implementation: RawFileSource
// ----------------------------------------------------------------------------

class RawFileSource : public MemorySource
{
private:
    std::string m_filepath;
    std::string m_filename;
    uintptr_t m_base = 0;
    std::vector<uint8_t> m_bytes;
    std::vector<RegionInfo> m_cached_regions;

public:
    RawFileSource(const std::string &filepath, uintptr_t base_addr, std::vector<uint8_t> &&bytes)
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

    static std::shared_ptr<RawFileSource> open(
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

    std::string describe() const override
    {
        char bbuf[32];
        std::snprintf(bbuf, sizeof(bbuf), "0x%016llX", static_cast<unsigned long long>(m_base));
        return "raw file: " + m_filename + ", base " + bbuf + " (" + std::to_string(m_bytes.size()) + " bytes)";
    }

    MemorySourceKind kind() const override
    {
        return MemorySourceKind::RawFile;
    }

    MemorySourceCapabilities capabilities() const override
    {
        MemorySourceCapabilities caps;
        caps.is_live = false;
        caps.has_protection = false;
        caps.has_allocation_info = false;
        caps.has_peb_access = false;
        caps.protection_is_synthetic = true;
        return caps;
    }

    uintptr_t get_base_address() const override
    {
        return m_base;
    }

    std::string get_file_path() const override
    {
        return m_filepath;
    }

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override
    {
        out_err.clear();
        out_regions = m_cached_regions;
        return true;
    }

    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override
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
};

#endif // DEADEYE_MEMSOURCE_HPP
