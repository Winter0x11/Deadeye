// src/core/snapshot.cpp
// Deadeye Process Memory Snapshot Storage & Comparison Engine
#include "core/snapshot.hpp"
#include "core/util.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace core {

#pragma pack(push, 1)
struct DiskSnapshotHeader
{
    uint32_t magic = SNAPSHOT_MAGIC;
    uint32_t version = SNAPSHOT_FORMAT_VERSION;
    uint32_t metadata_len = 0;
    uint32_t region_count = 0;
    uint64_t total_payload_bytes = 0;
    uint64_t header_checksum = 0;
};

struct DiskRegionHeader
{
    uint64_t base_address = 0;
    uint64_t region_size = 0;
    uint32_t state = 0;
    uint32_t type = 0;
    uint32_t protect = 0;
    uint32_t alloc_protect = 0;
    uint64_t alloc_base = 0;
    uint64_t bytes_captured = 0;
    uint8_t status = 0;
    uint8_t is_partial = 0;
    uint16_t reserved = 0;
    uint64_t checksum = 0;
    uint64_t payload_offset = 0;
    char section_name[16] = {};
};
#pragma pack(pop)

const SnapshotRegion* ProcessSnapshot::find_region(uintptr_t base_address) const
{
    for (const auto &reg : regions)
    {
        if (reg.base_address == base_address)
            return &reg;
    }
    return nullptr;
}

static std::string format_time_iso(uint64_t unix_sec)
{
    std::time_t t = static_cast<std::time_t>(unix_sec);
    std::tm tm_buf = {};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
    return buf;
}

bool capture_snapshot(
    std::shared_ptr<MemorySource> source,
    const SnapshotCaptureOptions &options,
    ProcessSnapshot &out_snapshot,
    std::string &out_err,
    HANDLE proc_handle)
{
    out_err.clear();
    if (!source)
    {
        out_err = "Invalid memory source.";
        return false;
    }

    std::vector<RegionInfo> all_regions;
    if (!source->query_regions(all_regions, out_err))
    {
        if (out_err.empty()) out_err = "Failed to query process memory regions.";
        return false;
    }

    auto now = std::chrono::system_clock::now();
    uint64_t unix_sec = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());

    SnapshotMetadata meta;
    meta.timestamp_unix_sec = unix_sec;
    meta.timestamp_str = format_time_iso(unix_sec);
    meta.pid = (source->capabilities().is_live) ? source->get_pid() : 0;
    meta.name = options.name.empty() ? ("Snapshot " + meta.timestamp_str) : options.name;

    char id_buf[64];
    std::snprintf(id_buf, sizeof(id_buf), "snap_%08lX_%llu", static_cast<unsigned long>(meta.pid), static_cast<unsigned long long>(unix_sec));
    meta.id = id_buf;

    meta.architecture = "x64";
    meta.process_name = source->describe();

    // Query live process metadata when handle is available
    if (proc_handle != nullptr)
    {
        FILETIME ft_create, ft_exit, ft_kernel, ft_user;
        if (GetProcessTimes(proc_handle, &ft_create, &ft_exit, &ft_kernel, &ft_user))
        {
            meta.process_creation_time = ft_create;
        }

        BOOL is_wow64 = FALSE;
        if (IsWow64Process(proc_handle, &is_wow64) && is_wow64)
        {
            meta.architecture = "x86 (WOW64)";
        }

        char path_buf[MAX_PATH] = {};
        DWORD path_len = sizeof(path_buf);
        if (QueryFullProcessImageNameA(proc_handle, 0, path_buf, &path_len) && path_len > 0)
        {
            meta.executable_path = path_buf;
        }
    }

    std::vector<RegionInfo> targets;
    if (!options.target_region_bases.empty())
    {
        for (uintptr_t target_base : options.target_region_bases)
        {
            for (const auto &reg : all_regions)
            {
                if (reg.base == target_base)
                {
                    targets.push_back(reg);
                    break;
                }
            }
        }
    }
    else
    {
        if (!options.capture_all_readable)
        {
            out_err = "No regions selected. Enabling capture of all readable regions requires explicit safeguard confirmation.";
            return false;
        }

        for (const auto &reg : all_regions)
        {
            if (!(reg.protect & PAGE_NOACCESS) && !(reg.protect & PAGE_GUARD))
            {
                targets.push_back(reg);
            }
        }
    }

    if (targets.empty())
    {
        out_err = "No committed readable regions found matching selection.";
        return false;
    }

    out_snapshot.metadata = meta;
    out_snapshot.regions.clear();

    SIZE_T total_captured = 0;
    bool overall_partial = false;

    for (const auto &reg : targets)
    {
        if (total_captured >= options.max_bytes_cap)
        {
            overall_partial = true;
            break;
        }

        SnapshotRegion sreg;
        sreg.base_address = reg.base;
        sreg.region_size = reg.size;
        sreg.state = reg.type; // committed
        sreg.type = reg.type;
        sreg.protect = reg.protect;
        sreg.alloc_protect = reg.alloc_protect;
        sreg.alloc_base = reg.alloc_base;
        sreg.section_name = reg.section_name;

        SIZE_T to_capture = reg.size;
        if (total_captured + to_capture > options.max_bytes_cap)
        {
            to_capture = options.max_bytes_cap - total_captured;
            sreg.is_partial = true;
            overall_partial = true;
        }

        sreg.data.resize(to_capture, 0);
        SIZE_T n_read = source->read(reg.base, to_capture, sreg.data.data());
        sreg.bytes_captured = n_read;

        if (n_read < to_capture)
        {
            sreg.data.resize(n_read);
            sreg.is_partial = true;
            overall_partial = true;
            sreg.status = (n_read > 0) ? SnapshotCaptureStatus::Partial : SnapshotCaptureStatus::Failed;
        }
        else
        {
            sreg.status = sreg.is_partial ? SnapshotCaptureStatus::Partial : SnapshotCaptureStatus::Complete;
        }

        sreg.checksum = fnv1a64(sreg.data.data(), sreg.data.size());
        total_captured += n_read;

        out_snapshot.regions.push_back(std::move(sreg));
    }

    out_snapshot.metadata.is_partial_capture = overall_partial;
    out_snapshot.metadata.total_bytes_captured = total_captured;
    out_snapshot.metadata.total_regions = out_snapshot.regions.size();

    return true;
}

static std::string serialize_metadata_json(const SnapshotMetadata &m)
{
    std::ostringstream ss;
    ss << "{\n"
       << "  \"id\": \"" << escape_json(m.id) << "\",\n"
       << "  \"name\": \"" << escape_json(m.name) << "\",\n"
       << "  \"timestamp_unix\": " << m.timestamp_unix_sec << ",\n"
       << "  \"timestamp_str\": \"" << escape_json(m.timestamp_str) << "\",\n"
       << "  \"pid\": " << m.pid << ",\n"
       << "  \"process_name\": \"" << escape_json(m.process_name) << "\",\n"
       << "  \"executable_path\": \"" << escape_json(m.executable_path) << "\",\n"
       << "  \"creation_time_low\": " << m.process_creation_time.dwLowDateTime << ",\n"
       << "  \"creation_time_high\": " << m.process_creation_time.dwHighDateTime << ",\n"
       << "  \"architecture\": \"" << escape_json(m.architecture) << "\",\n"
       << "  \"total_regions\": " << m.total_regions << ",\n"
       << "  \"total_bytes_captured\": " << m.total_bytes_captured << ",\n"
       << "  \"is_partial\": " << (m.is_partial_capture ? "true" : "false") << "\n"
       << "}";
    return ss.str();
}

static bool deserialize_metadata_json(const std::string &json, SnapshotMetadata &m)
{
    m.id = extract_json_str_val(json, "id");
    m.name = extract_json_str_val(json, "name");
    m.timestamp_str = extract_json_str_val(json, "timestamp_str");
    m.process_name = extract_json_str_val(json, "process_name");
    m.executable_path = extract_json_str_val(json, "executable_path");
    m.architecture = extract_json_str_val(json, "architecture");

    auto get_num = [&](const std::string &k, uint64_t def = 0) -> uint64_t {
        size_t p = json.find("\"" + k + "\":");
        if (p == std::string::npos) return def;
        p = json.find(':', p);
        if (p == std::string::npos) return def;
        p++;
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) p++;
        try {
            return std::stoull(json.substr(p));
        } catch (...) {
            return def;
        }
    };

    m.timestamp_unix_sec = get_num("timestamp_unix");
    m.pid = static_cast<DWORD>(get_num("pid"));
    m.process_creation_time.dwLowDateTime = static_cast<DWORD>(get_num("creation_time_low"));
    m.process_creation_time.dwHighDateTime = static_cast<DWORD>(get_num("creation_time_high"));
    m.total_regions = static_cast<size_t>(get_num("total_regions"));
    m.total_bytes_captured = static_cast<SIZE_T>(get_num("total_bytes_captured"));

    size_t part_p = json.find("\"is_partial\":");
    if (part_p != std::string::npos)
    {
        m.is_partial_capture = (json.find("true", part_p) != std::string::npos &&
                                json.find("true", part_p) < json.find('\n', part_p));
    }
    return !m.id.empty();
}

bool save_snapshot_to_file(
    const ProcessSnapshot &snapshot,
    const std::string &filepath,
    std::string &out_err)
{
    out_err.clear();
    std::ofstream out(filepath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        out_err = "Could not open file for writing: " + filepath;
        return false;
    }

    std::string meta_json = serialize_metadata_json(snapshot.metadata);

    DiskSnapshotHeader hdr;
    hdr.magic = SNAPSHOT_MAGIC;
    hdr.version = SNAPSHOT_FORMAT_VERSION;
    hdr.metadata_len = static_cast<uint32_t>(meta_json.size());
    hdr.region_count = static_cast<uint32_t>(snapshot.regions.size());

    uint64_t total_payload = 0;
    for (const auto &reg : snapshot.regions)
    {
        total_payload += reg.data.size();
    }
    hdr.total_payload_bytes = total_payload;
    hdr.header_checksum = fnv1a64(reinterpret_cast<const uint8_t*>(meta_json.data()), meta_json.size());

    // Write header
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

    // Write metadata JSON
    out.write(meta_json.data(), meta_json.size());

    // Calculate payload start offset
    uint64_t current_payload_offset = sizeof(hdr) + meta_json.size() + (sizeof(DiskRegionHeader) * snapshot.regions.size());

    // Write region table
    for (const auto &reg : snapshot.regions)
    {
        DiskRegionHeader dr;
        dr.base_address = reg.base_address;
        dr.region_size = reg.region_size;
        dr.state = reg.state;
        dr.type = reg.type;
        dr.protect = reg.protect;
        dr.alloc_protect = reg.alloc_protect;
        dr.alloc_base = reg.alloc_base;
        dr.bytes_captured = reg.data.size();
        dr.status = static_cast<uint8_t>(reg.status);
        dr.is_partial = reg.is_partial ? 1 : 0;
        dr.checksum = reg.checksum;
        dr.payload_offset = current_payload_offset;

        std::memset(dr.section_name, 0, sizeof(dr.section_name));
        if (!reg.section_name.empty())
        {
            size_t n = std::min<size_t>(sizeof(dr.section_name) - 1, reg.section_name.size());
            std::memcpy(dr.section_name, reg.section_name.data(), n);
        }

        out.write(reinterpret_cast<const char*>(&dr), sizeof(dr));
        current_payload_offset += reg.data.size();
    }

    // Write byte payloads
    for (const auto &reg : snapshot.regions)
    {
        if (!reg.data.empty())
        {
            out.write(reinterpret_cast<const char*>(reg.data.data()), reg.data.size());
        }
    }

    if (!out)
    {
        out_err = "Failed to write complete snapshot data to: " + filepath;
        return false;
    }
    return true;
}

bool load_snapshot_from_file(
    const std::string &filepath,
    ProcessSnapshot &out_snapshot,
    std::string &out_err)
{
    out_err.clear();
    std::ifstream in(filepath, std::ios::binary | std::ios::ate);
    if (!in.is_open())
    {
        out_err = "Could not open snapshot file: " + filepath;
        return false;
    }

    uint64_t file_size = static_cast<uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    if (file_size < sizeof(DiskSnapshotHeader))
    {
        out_err = "Snapshot file is corrupt or truncated (smaller than minimum header size).";
        return false;
    }

    DiskSnapshotHeader hdr;
    in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (!in)
    {
        out_err = "Failed to read snapshot header.";
        return false;
    }

    if (hdr.magic != SNAPSHOT_MAGIC)
    {
        out_err = "Invalid snapshot file format (signature magic mismatch).";
        return false;
    }

    if (hdr.version > SNAPSHOT_FORMAT_VERSION)
    {
        out_err = "Unsupported snapshot version (" + std::to_string(hdr.version) +
                  "). This build supports up to version " + std::to_string(SNAPSHOT_FORMAT_VERSION) + ".";
        return false;
    }

    uint64_t min_expected = sizeof(hdr) + hdr.metadata_len + (static_cast<uint64_t>(hdr.region_count) * sizeof(DiskRegionHeader));
    if (file_size < min_expected)
    {
        out_err = "Snapshot file is corrupt or truncated (file size " + std::to_string(file_size) +
                  " bytes is less than metadata and table table size " + std::to_string(min_expected) + " bytes).";
        return false;
    }

    // Read metadata JSON
    std::string meta_json(hdr.metadata_len, '\0');
    in.read(&meta_json[0], hdr.metadata_len);
    if (!in)
    {
        out_err = "Failed to read snapshot metadata JSON.";
        return false;
    }

    // Verify metadata checksum
    uint64_t computed_chk = fnv1a64(reinterpret_cast<const uint8_t*>(meta_json.data()), meta_json.size());
    if (computed_chk != hdr.header_checksum)
    {
        out_err = "Snapshot integrity check failed: metadata checksum mismatch.";
        return false;
    }

    if (!deserialize_metadata_json(meta_json, out_snapshot.metadata))
    {
        out_err = "Failed to parse snapshot metadata JSON.";
        return false;
    }

    // Read region table
    std::vector<DiskRegionHeader> disk_regions(hdr.region_count);
    in.read(reinterpret_cast<char*>(disk_regions.data()), hdr.region_count * sizeof(DiskRegionHeader));
    if (!in)
    {
        out_err = "Failed to read snapshot region table.";
        return false;
    }

    out_snapshot.regions.clear();
    out_snapshot.regions.reserve(hdr.region_count);

    for (const auto &dr : disk_regions)
    {
        SnapshotRegion sreg;
        sreg.base_address = static_cast<uintptr_t>(dr.base_address);
        sreg.region_size = static_cast<SIZE_T>(dr.region_size);
        sreg.state = dr.state;
        sreg.type = dr.type;
        sreg.protect = dr.protect;
        sreg.alloc_protect = dr.alloc_protect;
        sreg.alloc_base = static_cast<uintptr_t>(dr.alloc_base);
        sreg.bytes_captured = static_cast<SIZE_T>(dr.bytes_captured);
        sreg.status = static_cast<SnapshotCaptureStatus>(dr.status);
        sreg.is_partial = (dr.is_partial != 0);
        sreg.checksum = dr.checksum;
        sreg.section_name = dr.section_name;

        if (dr.bytes_captured > 0)
        {
            if (dr.payload_offset + dr.bytes_captured > file_size)
            {
                out_err = "Snapshot file is corrupt: region payload at 0x" + to_hex_string(dr.base_address) +
                          " extends past end of file.";
                return false;
            }

            in.seekg(static_cast<std::streamoff>(dr.payload_offset), std::ios::beg);
            sreg.data.resize(static_cast<size_t>(dr.bytes_captured));
            in.read(reinterpret_cast<char*>(sreg.data.data()), dr.bytes_captured);
            if (!in)
            {
                out_err = "Failed to read payload data for region at 0x" + to_hex_string(dr.base_address);
                return false;
            }

            // Verify payload checksum
            uint64_t actual_chk = fnv1a64(sreg.data.data(), sreg.data.size());
            if (actual_chk != dr.checksum)
            {
                out_err = "Snapshot integrity error: checksum mismatch for region at 0x" + to_hex_string(dr.base_address);
                return false;
            }
        }

        out_snapshot.regions.push_back(std::move(sreg));
    }

    return true;
}

// ----------------------------------------------------------------------------
// Snapshot Comparison Implementation
// ----------------------------------------------------------------------------

bool compare_snapshots(
    const ProcessSnapshot &snap_a,
    const ProcessSnapshot &snap_b,
    SnapshotCompareReport &out_report,
    std::string &out_err)
{
    out_err.clear();
    out_report = {};
    out_report.snapshot_a_id = snap_a.metadata.id;
    out_report.snapshot_a_name = snap_a.metadata.name;
    out_report.snapshot_b_id = snap_b.metadata.id;
    out_report.snapshot_b_name = snap_b.metadata.name;

    out_report.pid_match = (snap_a.metadata.pid != 0 && snap_a.metadata.pid == snap_b.metadata.pid);

    bool has_creation_a = (snap_a.metadata.process_creation_time.dwLowDateTime != 0 || snap_a.metadata.process_creation_time.dwHighDateTime != 0);
    bool has_creation_b = (snap_b.metadata.process_creation_time.dwLowDateTime != 0 || snap_b.metadata.process_creation_time.dwHighDateTime != 0);

    if (has_creation_a && has_creation_b)
    {
        out_report.creation_time_match =
            (snap_a.metadata.process_creation_time.dwLowDateTime == snap_b.metadata.process_creation_time.dwLowDateTime &&
             snap_a.metadata.process_creation_time.dwHighDateTime == snap_b.metadata.process_creation_time.dwHighDateTime);
    }
    else
    {
        out_report.creation_time_match = out_report.pid_match;
    }

    if (!out_report.pid_match)
    {
        out_report.compatibility_warnings.push_back("Different process IDs: " + std::to_string(snap_a.metadata.pid) +
                                                    " vs " + std::to_string(snap_b.metadata.pid));
    }
    if (has_creation_a && has_creation_b && !out_report.creation_time_match)
    {
        out_report.compatibility_warnings.push_back("Process instance creation time mismatch (likely PID reuse across different process lifespans).");
    }

    // Map regions by base address
    std::unordered_map<uintptr_t, const SnapshotRegion*> map_a;
    for (const auto &reg : snap_a.regions)
    {
        map_a[reg.base_address] = &reg;
    }

    std::unordered_map<uintptr_t, const SnapshotRegion*> map_b;
    for (const auto &reg : snap_b.regions)
    {
        map_b[reg.base_address] = &reg;
    }

    std::vector<uintptr_t> all_bases;
    for (const auto &p : map_a) all_bases.push_back(p.first);
    for (const auto &p : map_b)
    {
        if (map_a.find(p.first) == map_a.end())
            all_bases.push_back(p.first);
    }
    std::sort(all_bases.begin(), all_bases.end());

    for (uintptr_t base : all_bases)
    {
        auto it_a = map_a.find(base);
        auto it_b = map_b.find(base);

        RegionDiffResult rdiff;
        rdiff.base_address = base;

        if (it_a != map_a.end() && it_b == map_b.end())
        {
            // Region in A, missing from B (Removed / Deallocated)
            const auto &reg_a = *it_a->second;
            rdiff.region_size = reg_a.region_size;
            rdiff.old_protect = reg_a.protect;
            rdiff.old_type = reg_a.type;
            rdiff.overall_status = DiffByteStatus::Removed;
            rdiff.summary = "Region was deallocated or freed in Snapshot B.";
            out_report.count_removed_regions++;
            out_report.region_diffs.push_back(std::move(rdiff));
            continue;
        }

        if (it_a == map_a.end() && it_b != map_b.end())
        {
            // Region not in A, appeared in B (Added)
            const auto &reg_b = *it_b->second;
            rdiff.region_size = reg_b.region_size;
            rdiff.new_protect = reg_b.protect;
            rdiff.new_type = reg_b.type;
            rdiff.overall_status = DiffByteStatus::Added;
            rdiff.total_changed_bytes = reg_b.bytes_captured;
            rdiff.summary = "New region allocated in Snapshot B.";
            out_report.count_added_regions++;
            out_report.total_changed_bytes += reg_b.bytes_captured;
            out_report.region_diffs.push_back(std::move(rdiff));
            continue;
        }

        // Region present in both snapshots
        const auto &reg_a = *it_a->second;
        const auto &reg_b = *it_b->second;

        rdiff.region_size = std::max(reg_a.region_size, reg_b.region_size);
        rdiff.old_protect = reg_a.protect;
        rdiff.new_protect = reg_b.protect;
        rdiff.old_type = reg_a.type;
        rdiff.new_type = reg_b.type;
        rdiff.old_partial = reg_a.is_partial;
        rdiff.new_partial = reg_b.is_partial;

        if (reg_a.protect != reg_b.protect)
        {
            rdiff.protection_changed = true;
        }
        if (reg_a.type != reg_b.type)
        {
            rdiff.type_changed = true;
        }

        const size_t comp_len = std::min(reg_a.data.size(), reg_b.data.size());
        size_t changed_bytes = 0;

        // Byte-level differential scan
        size_t diff_start = 0;
        bool in_diff = false;

        for (size_t i = 0; i < comp_len; ++i)
        {
            if (reg_a.data[i] != reg_b.data[i])
            {
                changed_bytes++;
                if (!in_diff)
                {
                    in_diff = true;
                    diff_start = i;
                }
            }
            else
            {
                if (in_diff)
                {
                    in_diff = false;
                    ChangedByteRange range;
                    range.base_address = base;
                    range.offset_in_region = diff_start;
                    range.length = i - diff_start;
                    range.old_bytes.assign(reg_a.data.begin() + diff_start, reg_a.data.begin() + i);
                    range.new_bytes.assign(reg_b.data.begin() + diff_start, reg_b.data.begin() + i);
                    rdiff.changed_ranges.push_back(std::move(range));
                }
            }
        }

        if (in_diff)
        {
            ChangedByteRange range;
            range.base_address = base;
            range.offset_in_region = diff_start;
            range.length = comp_len - diff_start;
            range.old_bytes.assign(reg_a.data.begin() + diff_start, reg_a.data.begin() + comp_len);
            range.new_bytes.assign(reg_b.data.begin() + diff_start, reg_b.data.begin() + comp_len);
            rdiff.changed_ranges.push_back(std::move(range));
        }

        // Account for length difference if one capture was smaller
        if (reg_a.data.size() != reg_b.data.size())
        {
            size_t extra = std::max(reg_a.data.size(), reg_b.data.size()) - comp_len;
            changed_bytes += extra;
            ChangedByteRange range;
            range.base_address = base;
            range.offset_in_region = comp_len;
            range.length = extra;
            if (reg_a.data.size() > comp_len)
            {
                range.old_bytes.assign(reg_a.data.begin() + comp_len, reg_a.data.end());
            }
            else
            {
                range.new_bytes.assign(reg_b.data.begin() + comp_len, reg_b.data.end());
            }
            rdiff.changed_ranges.push_back(std::move(range));
        }

        rdiff.total_changed_bytes = changed_bytes;
        rdiff.content_changed = (changed_bytes > 0);

        if (rdiff.content_changed || rdiff.protection_changed || rdiff.type_changed)
        {
            rdiff.overall_status = DiffByteStatus::Modified;
            out_report.count_modified_regions++;
            out_report.total_changed_bytes += changed_bytes;

            std::string desc;
            if (rdiff.content_changed)
            {
                desc += std::to_string(changed_bytes) + " bytes modified (" +
                        std::to_string(rdiff.changed_ranges.size()) + " ranges)";
            }
            if (rdiff.protection_changed)
            {
                if (!desc.empty()) desc += "; ";
                desc += "Protect changed " + prot_short(rdiff.old_protect) + " -> " + prot_short(rdiff.new_protect);
            }
            if (rdiff.type_changed)
            {
                if (!desc.empty()) desc += "; ";
                desc += "Type changed " + type_short(rdiff.old_type) + " -> " + type_short(rdiff.new_type);
            }
            if (rdiff.old_partial || rdiff.new_partial)
            {
                if (!desc.empty()) desc += "; ";
                desc += "[Partial Capture]";
            }
            rdiff.summary = desc;
        }
        else
        {
            rdiff.overall_status = DiffByteStatus::Unchanged;
            rdiff.summary = "Identical bytes and protection.";
            out_report.count_unchanged_regions++;
        }

        out_report.region_diffs.push_back(std::move(rdiff));
    }

    return true;
}

} // namespace core
