// src/core/timeline.cpp
// Deadeye Memory Investigation Timeline Engine
#include "core/timeline.hpp"
#include "core/util.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdio>

namespace core {

static uint64_t current_time_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static std::string format_time_ms_string(uint64_t ms)
{
    time_t sec = static_cast<time_t>(ms / 1000);
    uint32_t remainder_ms = static_cast<uint32_t>(ms % 1000);
    std::tm tm_buf = {};
#if defined(_WIN32)
    localtime_s(&tm_buf, &sec);
#else
    localtime_r(&sec, &tm_buf);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03u",
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, remainder_ms);
    return std::string(buf);
}

std::string format_timeline_category(TimelineCategory cat)
{
    switch (cat)
    {
    case TimelineCategory::Lifecycle: return "Lifecycle";
    case TimelineCategory::Protection: return "Protection";
    case TimelineCategory::Content: return "Content";
    case TimelineCategory::Entropy: return "Entropy";
    case TimelineCategory::SnapshotDiff: return "Snapshot/Diff";
    default: return "General";
    }
}

std::string format_timeline_event_type(TimelineEventType type)
{
    switch (type)
    {
    case TimelineEventType::RegionObserved: return "Region Observed";
    case TimelineEventType::RegionDisappeared: return "Region Disappeared (Deallocation Inferred)";
    case TimelineEventType::ProtectionChanged: return "Protection Changed";
    case TimelineEventType::ExecPermGained: return "W->X Execution Perm Gained";
    case TimelineEventType::ExecPermLost: return "X->W Execution Perm Lost";
    case TimelineEventType::ContentChanged: return "Content Changed";
    case TimelineEventType::EntropyShift: return "Entropy Shift";
    case TimelineEventType::SleepCycleDetected: return "Sleep Cycle Oscillation";
    case TimelineEventType::SnapshotCaptured: return "Snapshot Captured";
    case TimelineEventType::DiffGenerated: return "Diff Generated";
    default: return "Event";
    }
}

TimelineManager::TimelineManager(size_t max_capacity)
    : m_max_capacity(max_capacity)
{
}

void TimelineManager::set_capacity(size_t cap)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_max_capacity = (cap < 100) ? 100 : cap;
    while (m_events.size() > m_max_capacity)
    {
        m_events.pop_front();
    }
}

size_t TimelineManager::get_capacity() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_max_capacity;
}

void TimelineManager::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
}

size_t TimelineManager::count() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events.size();
}

uint64_t TimelineManager::record_event(TimelineEvent evt)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (evt.id == 0)
    {
        evt.id = m_next_id++;
    }
    if (evt.timestamp_ms == 0)
    {
        evt.timestamp_ms = current_time_ms();
    }
    if (evt.timestamp_str.empty())
    {
        evt.timestamp_str = format_time_ms_string(evt.timestamp_ms);
    }

    if (m_events.size() >= m_max_capacity)
    {
        m_events.pop_front();
    }
    m_events.push_back(std::move(evt));
    return m_events.back().id;
}

uint64_t TimelineManager::record_region_observed(DWORD pid, uintptr_t base, SIZE_T size, DWORD protect, DWORD type, double entropy)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.base_address = base;
    evt.region_size = size;
    evt.new_protect = protect;
    evt.new_type = type;
    evt.new_entropy = entropy;
    evt.category = TimelineCategory::Lifecycle;
    evt.event_type = TimelineEventType::RegionObserved;

    char buf[128];
    std::snprintf(buf, sizeof(buf), "Region first observed: 0x%016llX (%s, %s, %s)",
                  static_cast<unsigned long long>(base),
                  fmt_size_short(size).c_str(),
                  type_short(type).c_str(),
                  prot_short(protect).c_str());
    evt.summary = buf;
    evt.details = "Committed memory region detected during process query.";
    return record_event(evt);
}

uint64_t TimelineManager::record_region_disappeared(DWORD pid, uintptr_t base, SIZE_T size, DWORD old_protect, DWORD old_type)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.base_address = base;
    evt.region_size = size;
    evt.old_protect = old_protect;
    evt.old_type = old_type;
    evt.category = TimelineCategory::Lifecycle;
    evt.event_type = TimelineEventType::RegionDisappeared;

    char buf[128];
    std::snprintf(buf, sizeof(buf), "Region no longer observed: 0x%016llX (%s, %s) - deallocation inferred",
                  static_cast<unsigned long long>(base),
                  fmt_size_short(size).c_str(),
                  prot_short(old_protect).c_str());
    evt.summary = buf;
    evt.details = "Region missing from virtual memory map query; deallocation or protection change inferred between observations.";
    return record_event(evt);
}

uint64_t TimelineManager::record_protection_changed(DWORD pid, uintptr_t base, SIZE_T size, DWORD old_protect, DWORD new_protect, DWORD type, const std::string &note)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.base_address = base;
    evt.region_size = size;
    evt.old_protect = old_protect;
    evt.new_protect = new_protect;
    evt.new_type = type;
    evt.old_type = type;
    evt.category = TimelineCategory::Protection;

    bool was_exec = is_executable_protect(old_protect);
    bool now_exec = is_executable_protect(new_protect);

    if (!was_exec && now_exec)
    {
        evt.event_type = TimelineEventType::ExecPermGained;
    }
    else if (was_exec && !now_exec)
    {
        evt.event_type = TimelineEventType::ExecPermLost;
    }
    else
    {
        evt.event_type = TimelineEventType::ProtectionChanged;
    }

    char buf[160];
    std::snprintf(buf, sizeof(buf), "Protection changed at 0x%016llX: %s -> %s%s",
                  static_cast<unsigned long long>(base),
                  prot_short(old_protect).c_str(),
                  prot_short(new_protect).c_str(),
                  (!was_exec && now_exec) ? " [!] EXEC GAINED" : "");
    evt.summary = buf;
    evt.details = note.empty() ? ("Memory protection transition observed between polling cycles.") : note;
    return record_event(evt);
}

uint64_t TimelineManager::record_content_changed(DWORD pid, uintptr_t base, SIZE_T size, DWORD protect, DWORD type, SIZE_T changed_bytes, const std::string &note)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.base_address = base;
    evt.region_size = size;
    evt.new_protect = protect;
    evt.new_type = type;
    evt.category = TimelineCategory::Content;
    evt.event_type = TimelineEventType::ContentChanged;

    char buf[160];
    std::snprintf(buf, sizeof(buf), "Memory modified at 0x%016llX: %zu bytes changed",
                  static_cast<unsigned long long>(base),
                  changed_bytes);
    evt.summary = buf;
    evt.details = note.empty() ? "In-place memory mutation detected." : note;
    return record_event(evt);
}

uint64_t TimelineManager::record_entropy_shift(DWORD pid, uintptr_t base, SIZE_T size, DWORD protect, DWORD type, double old_ent, double new_ent, const std::string &note)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.base_address = base;
    evt.region_size = size;
    evt.new_protect = protect;
    evt.new_type = type;
    evt.old_entropy = old_ent;
    evt.new_entropy = new_ent;
    evt.category = TimelineCategory::Entropy;
    evt.event_type = TimelineEventType::EntropyShift;

    char buf[160];
    std::snprintf(buf, sizeof(buf), "Entropy shift at 0x%016llX: %.2f -> %.2f (delta %+.2f)",
                  static_cast<unsigned long long>(base),
                  old_ent, new_ent, new_ent - old_ent);
    evt.summary = buf;
    evt.details = note.empty() ? "Substantial Shannon entropy shift detected (consistent with encryption/decryption)." : note;
    return record_event(evt);
}

uint64_t TimelineManager::record_snapshot_captured(DWORD pid, const std::string &snap_id, const std::string &snap_name, size_t regions, SIZE_T bytes)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.snapshot_id = snap_id;
    evt.category = TimelineCategory::SnapshotDiff;
    evt.event_type = TimelineEventType::SnapshotCaptured;

    char buf[180];
    std::snprintf(buf, sizeof(buf), "Snapshot captured: '%s' (%zu regions, %s)",
                  snap_name.c_str(), regions, fmt_size_short(bytes).c_str());
    evt.summary = buf;
    evt.details = "Full memory state snapshot saved in session store with ID: " + snap_id;
    return record_event(evt);
}

uint64_t TimelineManager::record_diff_generated(DWORD pid, const std::string &desc, size_t modified_regions, SIZE_T changed_bytes)
{
    TimelineEvent evt;
    evt.pid = pid;
    evt.category = TimelineCategory::SnapshotDiff;
    evt.event_type = TimelineEventType::DiffGenerated;

    char buf[180];
    std::snprintf(buf, sizeof(buf), "Memory diff generated: %s (%zu modified regions, %s changed)",
                  desc.c_str(), modified_regions, fmt_size_short(changed_bytes).c_str());
    evt.summary = buf;
    evt.details = "Byte-level comparison completed between memory states.";
    return record_event(evt);
}

std::vector<TimelineEvent> TimelineManager::query(const TimelineFilter &filter) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<TimelineEvent> result;
    result.reserve(m_events.size());

    for (const auto &evt : m_events)
    {
        // Category mask check
        if ((static_cast<uint32_t>(evt.category) & static_cast<uint32_t>(filter.category_mask)) == 0)
            continue;

        // Address range check
        if (filter.min_address != 0 || filter.max_address != UINTPTR_MAX)
        {
            if (evt.base_address == 0)
                continue;
            uintptr_t evt_end = evt.base_address + evt.region_size;
            if (evt_end <= filter.min_address || evt.base_address >= filter.max_address)
                continue;
        }

        // Protection check
        if (filter.protect_filter != 0)
        {
            if (evt.new_protect != filter.protect_filter && evt.old_protect != filter.protect_filter)
                continue;
        }

        // Time range check
        if (evt.timestamp_ms < filter.start_time_ms || evt.timestamp_ms > filter.end_time_ms)
            continue;

        // Text query check
        if (!filter.text_query.empty())
        {
            std::string q = filter.text_query;
            std::string s1 = evt.summary;
            std::string s2 = evt.details;
            auto to_lower_char = [](unsigned char c) -> char { return static_cast<char>(std::tolower(c)); };
            std::transform(q.begin(), q.end(), q.begin(), to_lower_char);
            std::transform(s1.begin(), s1.end(), s1.begin(), to_lower_char);
            std::transform(s2.begin(), s2.end(), s2.begin(), to_lower_char);
            if (s1.find(q) == std::string::npos && s2.find(q) == std::string::npos)
                continue;
        }

        result.push_back(evt);
    }

    if (!filter.sort_ascending)
    {
        std::reverse(result.begin(), result.end());
    }

    return result;
}

bool TimelineManager::get_event_by_id(uint64_t id, TimelineEvent &out_evt) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto &evt : m_events)
    {
        if (evt.id == id)
        {
            out_evt = evt;
            return true;
        }
    }
    return false;
}

std::string TimelineManager::export_json(const TimelineFilter &filter) const
{
    std::vector<TimelineEvent> evts = query(filter);
    std::ostringstream ss;
    ss << "{\n"
       << "  \"schema\": \"deadeye-timeline-v1\",\n"
       << "  \"total_events\": " << evts.size() << ",\n"
       << "  \"events\": [\n";

    for (size_t i = 0; i < evts.size(); ++i)
    {
        const auto &e = evts[i];
        ss << "    {\n"
           << "      \"id\": " << e.id << ",\n"
           << "      \"timestamp_ms\": " << e.timestamp_ms << ",\n"
           << "      \"timestamp\": \"" << escape_json(e.timestamp_str) << "\",\n"
           << "      \"pid\": " << e.pid << ",\n"
           << "      \"category\": \"" << escape_json(format_timeline_category(e.category)) << "\",\n"
           << "      \"event_type\": \"" << escape_json(format_timeline_event_type(e.event_type)) << "\",\n"
           << "      \"base_address\": \"0x" << to_hex_string(e.base_address) << "\",\n"
           << "      \"region_size\": " << e.region_size << ",\n"
           << "      \"old_protect\": \"" << escape_json(prot_short(e.old_protect)) << "\",\n"
           << "      \"new_protect\": \"" << escape_json(prot_short(e.new_protect)) << "\",\n"
           << "      \"old_type\": \"" << escape_json(type_short(e.old_type)) << "\",\n"
           << "      \"new_type\": \"" << escape_json(type_short(e.new_type)) << "\",\n"
           << "      \"old_entropy\": " << e.old_entropy << ",\n"
           << "      \"new_entropy\": " << e.new_entropy << ",\n"
           << "      \"summary\": \"" << escape_json(e.summary) << "\",\n"
           << "      \"details\": \"" << escape_json(e.details) << "\",\n"
           << "      \"snapshot_id\": \"" << escape_json(e.snapshot_id) << "\"\n"
           << "    }" << (i + 1 < evts.size() ? "," : "") << "\n";
    }

    ss << "  ]\n}\n";
    return ss.str();
}

} // namespace core
