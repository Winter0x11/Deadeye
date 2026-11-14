// src/core/json_export.hpp
// Deadeye Defensive Triage JSON Serialization
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "core/triage.hpp"
#include "core/behavior.hpp"

std::string export_triage_json(
    const TriageReport &report,
    const std::vector<WatchedRegionState> *watched_regions = nullptr,
    uint64_t partial_sample_count = 0,
    uint32_t interval_ms = 1000);
