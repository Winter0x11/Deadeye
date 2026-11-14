// src/core/triage.hpp
// Deadeye Defensive Triage Threat Engine
#pragma once

#include "core/scoring.hpp"
#include "core/memsource.hpp"
#include "core/live_source.hpp"
#include <vector>
#include <string>
#include <memory>
#include <atomic>

// Shannon entropy profile for a single region (page-wise and aggregated)
struct PageEntropyProfile
{
    double avg_entropy = -1.0;
    double max_entropy = -1.0;
    std::string ascii_profile;
    bool is_sampled = false;
    size_t total_pages = 0;
    size_t valid_pages = 0;
};

// Triage finding for an individual region
struct TriageFinding
{
    size_t region_index = 0;
    uintptr_t base = 0;
    SIZE_T size = 0;
    uintptr_t alloc_base = 0;
    DWORD type = 0;
    DWORD protect = 0;
    DWORD alloc_protect = 0;
    int severity_score = 0;
    std::string severity_label;       // "CRIT", "HIGH", "MED", "LOW", "CLEAN"
    std::vector<std::string> flags;   // "INJECTED_PE", "UNLINKED_MODULE", "WRITE_THEN_FLIP", "PRIVATE_RWX", "UNBACKED_EXEC", "BEHAVIOR_UNPACK", "SLEEP_OBFUSCATION"
    std::vector<std::string> reasons; // Detailed explanation strings with point values
};

struct RegionEntropyJson
{
    uintptr_t base = 0;
    double avg_entropy = -1.0;
    double max_entropy = -1.0;
    std::string ascii_profile;
};

// Triage report for the entire process or memory source
struct TriageReport
{
    DWORD pid = 0;
    std::string source_description;
    MemorySourceKind source_kind = MemorySourceKind::Live;
    uintptr_t source_base = 0;
    bool protection_is_synthetic = false;
    bool wow64_unsupported = false;
    std::vector<std::string> rules_not_evaluated;
    std::vector<TriageFinding> findings;
    std::vector<RegionEntropyJson> entropy_profiles;
};

PageEntropyProfile compute_region_entropy_profile(MemorySource &source, uintptr_t base, SIZE_T size);

TriageReport run_source_triage(std::shared_ptr<MemorySource> source,
                               std::vector<RegionInfo> &regions,
                               std::atomic<bool> *abort_flag = nullptr,
                               void (*progress_cb)(SIZE_T current, SIZE_T total, void *user_data) = nullptr,
                               void *user_data = nullptr);

inline TriageReport run_process_triage(HANDLE proc, DWORD pid, std::vector<RegionInfo> &regions,
                                       std::atomic<bool> *abort_flag = nullptr,
                                       void (*progress_cb)(SIZE_T current, SIZE_T total, void *user_data) = nullptr,
                                       void *user_data = nullptr)
{
    auto live_src = std::make_shared<LiveProcessSource>(pid, proc, false);
    return run_source_triage(live_src, regions, abort_flag, progress_cb, user_data);
}
