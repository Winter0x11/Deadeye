// src/core/pe_source.hpp
// Deadeye Defensive Triage Mapped PE & Raw File MemorySource
#pragma once

#include "core/memsource.hpp"

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

    static uintptr_t align_up_val(uintptr_t val, uintptr_t alignment);
    static DWORD characteristics_to_protect(DWORD ch);

public:
    MappedPeSource() = default;

    static std::shared_ptr<MappedPeSource> open(
        const std::string &filepath,
        uintptr_t override_base,
        bool apply_relocations,
        std::string &out_err);

    std::string describe() const override;
    MemorySourceKind kind() const override;
    MemorySourceCapabilities capabilities() const override;
    uintptr_t get_base_address() const override;
    std::string get_file_path() const override;
    bool get_pe_summary(PeSummaryInfo &out_info) const override;

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override;
    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override;
    const std::vector<MappedSegment>& get_segments() const;
};

class RawFileSource : public MemorySource
{
private:
    std::string m_filepath;
    std::string m_filename;
    uintptr_t m_base = 0;
    std::vector<uint8_t> m_bytes;
    std::vector<RegionInfo> m_cached_regions;

public:
    RawFileSource(const std::string &filepath, uintptr_t base_addr, std::vector<uint8_t> &&bytes);

    static std::shared_ptr<RawFileSource> open(
        const std::string &filepath,
        uintptr_t base_addr,
        std::string &out_err);

    std::string describe() const override;
    MemorySourceKind kind() const override;
    MemorySourceCapabilities capabilities() const override;
    uintptr_t get_base_address() const override;
    std::string get_file_path() const override;

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override;
    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override;
};

bool get_pe_default_base(const std::string &filepath, uintptr_t &out_base, bool &out_is_pe);
