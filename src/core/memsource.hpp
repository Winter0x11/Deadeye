// src/core/memsource.hpp
// Deadeye Defensive Triage MemorySource Abstraction
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include "core/util.hpp"
#include "core/pattern.hpp"

// Snapshot of a memory page for timeline diffing.
struct Snapshot
{
    std::vector<uint8_t> data;
    uintptr_t base = 0;
    SIZE_T view_offset = 0;
    DWORD timestamp_ms = 0;
    std::string label;
};

struct MemoryTransition
{
    DWORD timestamp_ms = 0;
    DWORD old_protect = 0;
    DWORD new_protect = 0;
    double old_entropy = 0.0;
    double new_entropy = 0.0;
    uint64_t old_hash = 0;
    uint64_t new_hash = 0;
    bool is_unpack = false;
    bool is_sleep_cycle = false;
};

// Metadata, detection heuristics, hit offsets, and snapshot timeline for a memory region.
struct RegionInfo
{
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD type = 0;
    DWORD protect = 0;
    uintptr_t alloc_base = 0;
    DWORD alloc_protect = 0;
    bool is_unbacked_exec = false;
    bool is_pe_in_private = false;
    bool private_rwx = false;
    bool write_then_flip = false;
    bool is_unlinked_image = false;
    std::vector<SIZE_T> hits;
    bool hits_truncated = false;
    std::vector<Snapshot> snapshots;

    // Static Analysis Metadata
    std::string section_name;
    double entropy = 0.0;
    double avg_entropy = -1.0;
    double max_entropy = -1.0;
    std::string entropy_ascii_profile;
    bool entropy_sampled = false;

    // Behavioral Timeline & Detections
    DWORD last_protect = 0;
    double last_entropy = 0.0;
    uint64_t last_hash = 0;
    int flip_count = 0;
    std::vector<DWORD> protect_history;
    std::vector<double> entropy_history;
    std::vector<MemoryTransition> transitions;
    bool behavior_unpack_detected = false;
    bool sleep_obfuscation_detected = false;
};

// Range of a loaded module enumerated from the PEB loader list.
struct LoadedModuleRange
{
    uintptr_t base = 0;
    SIZE_T size = 0;
    std::wstring name;
};

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

std::string format_pe_summary(const PeSummaryInfo &pe);

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

SIZE_T scan_chunk_robust(MemorySource *source, uintptr_t chunk_addr, SIZE_T to_read,
                         const Pattern *pat, std::vector<uint8_t> &chunk_buf,
                         SIZE_T chunk_offset_in_reg, std::vector<SIZE_T> &out_hits,
                         size_t max_hits, bool &out_truncated, bool &out_has_pe);
