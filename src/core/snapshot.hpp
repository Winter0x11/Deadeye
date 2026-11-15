// src/core/snapshot.hpp
// Deadeye Process Memory Snapshot Storage & Comparison Engine
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>

#include "core/memsource.hpp"

namespace core {

inline constexpr uint32_t SNAPSHOT_MAGIC = 0x50414E53; // "SNAP" in LE
inline constexpr uint32_t SNAPSHOT_FORMAT_VERSION = 1;

enum class SnapshotCaptureStatus : uint8_t
{
    Complete = 0,
    Partial = 1,
    Failed = 2
};

struct SnapshotRegion
{
    uintptr_t base_address = 0;
    SIZE_T region_size = 0;
    DWORD state = MEM_COMMIT;
    DWORD type = MEM_PRIVATE;
    DWORD protect = PAGE_READONLY;
    DWORD alloc_protect = PAGE_READONLY;
    uintptr_t alloc_base = 0;
    std::string section_name;

    SnapshotCaptureStatus status = SnapshotCaptureStatus::Complete;
    SIZE_T bytes_captured = 0;
    bool is_partial = false;
    uint64_t checksum = 0;

    std::vector<uint8_t> data;
};

struct SnapshotMetadata
{
    std::string id;
    std::string name;
    uint64_t timestamp_unix_sec = 0;
    std::string timestamp_str;
    DWORD pid = 0;
    std::string process_name;
    std::string executable_path;
    FILETIME process_creation_time = {};
    std::string architecture;
    bool is_partial_capture = false;
    SIZE_T total_bytes_captured = 0;
    size_t total_regions = 0;
};

struct ProcessSnapshot
{
    SnapshotMetadata metadata;
    std::vector<SnapshotRegion> regions;

    const SnapshotRegion* find_region(uintptr_t base_address) const;
};

struct SnapshotCaptureOptions
{
    std::string name;
    std::vector<uintptr_t> target_region_bases; // Empty means all readable committed regions
    bool capture_all_readable = false;          // Explicit safeguard required when target_region_bases is empty
    SIZE_T max_bytes_cap = 256 * 1024 * 1024;   // 256 MB safety cap
    SIZE_T chunk_size = 1024 * 1024;            // 1 MB chunk reading
};

// Captures a snapshot from an active MemorySource
bool capture_snapshot(
    std::shared_ptr<MemorySource> source,
    const SnapshotCaptureOptions &options,
    ProcessSnapshot &out_snapshot,
    std::string &out_err,
    HANDLE proc_handle = nullptr);

// Serialization to .desnap format
bool save_snapshot_to_file(
    const ProcessSnapshot &snapshot,
    const std::string &filepath,
    std::string &out_err);

// Deserialization from .desnap format with integrity checks
bool load_snapshot_from_file(
    const std::string &filepath,
    ProcessSnapshot &out_snapshot,
    std::string &out_err);

// ----------------------------------------------------------------------------
// Snapshot Comparison & Differential Analysis
// ----------------------------------------------------------------------------

enum class DiffByteStatus : uint8_t
{
    Unchanged = 0,
    Modified = 1,
    Added = 2,
    Removed = 3,
    Inaccessible = 4
};

struct ChangedByteRange
{
    uintptr_t base_address = 0;
    SIZE_T offset_in_region = 0;
    SIZE_T length = 0;
    std::vector<uint8_t> old_bytes;
    std::vector<uint8_t> new_bytes;
};

struct RegionDiffResult
{
    uintptr_t base_address = 0;
    SIZE_T region_size = 0;
    DWORD old_protect = 0;
    DWORD new_protect = 0;
    DWORD old_type = 0;
    DWORD new_type = 0;
    DiffByteStatus overall_status = DiffByteStatus::Unchanged;

    bool protection_changed = false;
    bool type_changed = false;
    bool content_changed = false;
    bool old_partial = false;
    bool new_partial = false;

    SIZE_T total_changed_bytes = 0;
    std::vector<ChangedByteRange> changed_ranges;
    std::string summary;
};

struct SnapshotCompareReport
{
    std::string snapshot_a_id;
    std::string snapshot_a_name;
    std::string snapshot_b_id;
    std::string snapshot_b_name;

    bool pid_match = false;
    bool creation_time_match = false;
    std::vector<std::string> compatibility_warnings;

    size_t count_unchanged_regions = 0;
    size_t count_modified_regions = 0;
    size_t count_added_regions = 0;
    size_t count_removed_regions = 0;
    SIZE_T total_changed_bytes = 0;

    std::vector<RegionDiffResult> region_diffs;
};

// Compares two snapshots at the byte level
bool compare_snapshots(
    const ProcessSnapshot &snap_a,
    const ProcessSnapshot &snap_b,
    SnapshotCompareReport &out_report,
    std::string &out_err);

} // namespace core
