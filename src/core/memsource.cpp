// src/core/memsource.cpp
// Deadeye Defensive Triage MemorySource Helpers
#include "core/memsource.hpp"
#include <sstream>
#include <cstdio>

std::string format_pe_summary(const PeSummaryInfo &pe)
{
    std::ostringstream ss;
    ss << "Machine: " << pe.machine_name << " | Subsystem: " << pe.subsystem_name << " | ";
    char ib_buf[32];
    std::snprintf(ib_buf, sizeof(ib_buf), "0x%016llX", static_cast<unsigned long long>(pe.image_base));
    ss << "ImageBase: " << ib_buf << " | ";
    char ep_buf[32];
    std::snprintf(ep_buf, sizeof(ep_buf), "+0x%X", pe.entry_point_rva);
    ss << "Entry Point: " << ep_buf << " (" << (pe.entry_point_section.empty() ? "None" : pe.entry_point_section) << ")";
    if (pe.ep_outside_exec_sections)
    {
        ss << " [!] OUTSIDE EXEC";
    }
    ss << " | Sections: " << pe.section_count;
    ss << " | Overlay: " << pe.overlay_size << " bytes";
    ss << " | IAT: Unresolved (raw on-disk thunks)";
    if (pe.effective_base != pe.image_base)
    {
        ss << " | Relocs: " << pe.reloc_fixup_count << " applied";
        if (pe.reloc_skipped_count > 0)
        {
            ss << " (" << pe.reloc_skipped_count << " skipped)";
        }
    }
    return ss.str();
}

SIZE_T scan_chunk_robust(MemorySource *source, uintptr_t chunk_addr, SIZE_T to_read,
                         const Pattern *pat, std::vector<uint8_t> &chunk_buf,
                         SIZE_T chunk_offset_in_reg, std::vector<SIZE_T> &out_hits,
                         size_t max_hits, bool &out_truncated, bool &out_has_pe)
{
    if (to_read == 0 || source == nullptr)
        return 0;
    if (chunk_buf.size() < to_read)
        chunk_buf.resize(to_read);

    SIZE_T bytes_read = source->read(chunk_addr, to_read, chunk_buf.data());
    if (bytes_read == 0)
        return 0;

    if (chunk_offset_in_reg == 0 && has_pe_header(chunk_buf.data(), bytes_read))
    {
        out_has_pe = true;
    }

    if (pat != nullptr && !pat->bytes.empty())
    {
        std::vector<size_t> hits = find_all(chunk_buf.data(), bytes_read, *pat);
        for (size_t h : hits)
        {
            if (out_hits.size() < max_hits)
            {
                out_hits.push_back(chunk_offset_in_reg + h);
            }
            else
            {
                out_truncated = true;
                break;
            }
        }
    }

    return bytes_read;
}
