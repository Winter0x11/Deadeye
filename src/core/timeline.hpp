// src/core/timeline.hpp
// Deadeye Memory Investigation Timeline Engine
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <memory>
#include <functional>

namespace core {

enum class TimelineCategory : uint32_t
{
    None             = 0,
    Lifecycle        = (1 << 0), // Region first observed, deallocation inferred
    Protection       = (1 << 1), // Protection changes (RW->RX, RX->RW, etc.)
    Content          = (1 << 2), // Content modified, unpack detected
    Entropy          = (1 << 3), // Significant entropy shifts
    SnapshotDiff     = (1 << 4), // Snapshot taken, diff generated
    All              = 0xFFFFFFFF
};

inline TimelineCategory operator|(TimelineCategory a, TimelineCategory b)
{
    return static_cast<TimelineCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline TimelineCategory operator&(TimelineCategory a, TimelineCategory b)
{
    return static_cast<TimelineCategory>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

enum class TimelineEventType : uint32_t
{
    RegionObserved,       // Region first detected in memory map
    RegionDisappeared,    // Region no longer observed (deallocation inferred)
    ProtectionChanged,    // Page protection altered (e.g. VirtualProtect)
    ExecPermGained,       // Region transitioned from non-executable to executable
    ExecPermLost,         // Region transitioned from executable to non-executable
    ContentChanged,       // Bytes modified within region
    EntropyShift,         // Shannon entropy shifted significantly (>= 1.5 bits)
    SleepCycleDetected,   // Periodic protection oscillation
    SnapshotCaptured,     // Process snapshot acquired
    DiffGenerated         // Differential comparison executed
};

struct TimelineEvent
{
    uint64_t id = 0;
    uint64_t timestamp_ms = 0;
    std::string timestamp_str; // "HH:MM:SS.mmm"
    DWORD pid = 0;
    uintptr_t base_address = 0;
    SIZE_T region_size = 0;

    DWORD old_protect = 0;
    DWORD new_protect = 0;
    DWORD old_type = 0;
    DWORD new_type = 0;
    DWORD old_state = 0;
    DWORD new_state = 0;

    double old_entropy = -1.0;
    double new_entropy = -1.0;

    TimelineCategory category = TimelineCategory::None;
    TimelineEventType event_type = TimelineEventType::RegionObserved;

    std::string summary;
    std::string details;
    std::string snapshot_id; // Associated snapshot ID if relevant
};

struct TimelineFilter
{
    TimelineCategory category_mask = TimelineCategory::All;
    uintptr_t min_address = 0;
    uintptr_t max_address = UINTPTR_MAX;
    DWORD protect_filter = 0; // 0 = any
    uint64_t start_time_ms = 0;
    uint64_t end_time_ms = UINT64_MAX;
    std::string text_query;
    bool sort_ascending = true;
};

class TimelineManager
{
private:
    mutable std::mutex m_mutex;
    std::deque<TimelineEvent> m_events;
    uint64_t m_next_id = 1;
    size_t m_max_capacity = 10000;

public:
    TimelineManager(size_t max_capacity = 10000);
    ~TimelineManager() = default;

    TimelineManager(const TimelineManager &) = delete;
    TimelineManager &operator=(const TimelineManager &) = delete;

    void set_capacity(size_t cap);
    size_t get_capacity() const;
    void clear();
    size_t count() const;

    uint64_t record_event(TimelineEvent evt);

    // Convenience event factories
    uint64_t record_region_observed(DWORD pid, uintptr_t base, SIZE_T size, DWORD protect, DWORD type, double entropy = -1.0);
    uint64_t record_region_disappeared(DWORD pid, uintptr_t base, SIZE_T size, DWORD old_protect, DWORD old_type);
    uint64_t record_protection_changed(DWORD pid, uintptr_t base, SIZE_T size, DWORD old_protect, DWORD new_protect, DWORD type, const std::string &note = "");
    uint64_t record_content_changed(DWORD pid, uintptr_t base, SIZE_T size, DWORD protect, DWORD type, SIZE_T changed_bytes, const std::string &note = "");
    uint64_t record_entropy_shift(DWORD pid, uintptr_t base, SIZE_T size, DWORD protect, DWORD type, double old_ent, double new_ent, const std::string &note = "");
    uint64_t record_snapshot_captured(DWORD pid, const std::string &snap_id, const std::string &snap_name, size_t regions, SIZE_T bytes);
    uint64_t record_diff_generated(DWORD pid, const std::string &desc, size_t modified_regions, SIZE_T changed_bytes);

    // Query and filtering
    std::vector<TimelineEvent> query(const TimelineFilter &filter) const;
    bool get_event_by_id(uint64_t id, TimelineEvent &out_evt) const;

    // JSON export
    std::string export_json(const TimelineFilter &filter) const;
};

std::string format_timeline_category(TimelineCategory cat);
std::string format_timeline_event_type(TimelineEventType type);

} // namespace core
