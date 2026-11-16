// src/core/pattern.hpp
// Deadeye Defensive Triage Byte Pattern Engine
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <atomic>
#include <memory>
#include <windows.h>

inline constexpr size_t MAX_HITS_PER_REGION = 10000;

enum class PatternType
{
    HexWildcard = 0,
    AsciiString = 1,
    Utf16String = 2
};

// Compiled byte pattern: mask[i] == 1 means exact byte match, 0 means wildcard (??).
struct Pattern
{
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    PatternType type = PatternType::HexWildcard;
    bool is_case_insensitive = false;
};

// Parses hex strings like "4D 5A ?? 00 03" into bytes and a match mask.
bool parse_pattern(const std::string &input, Pattern &out, std::string &err);
bool parse_hex_pattern(const std::string &input, Pattern &out, std::string &err);
bool parse_ascii_pattern(const std::string &input, bool match_case, Pattern &out, std::string &err);
bool parse_utf16le_pattern(const std::string &input, bool match_case, Pattern &out, std::string &err);

// Searches buf[0..len) using accelerated matching.
// If max_hits > 0, stops searching once max_hits matches are accumulated.
std::vector<size_t> find_all(const uint8_t *buf, size_t len, const Pattern &p, size_t max_hits = 0);

// Search Results & Scopes
struct PatternMatchResult
{
    uintptr_t match_address = 0;
    uintptr_t region_base = 0;
    SIZE_T region_size = 0;
    DWORD protect = 0;
    DWORD type = 0;
    std::string preview_hex;
    std::string preview_ascii;
};

enum class SearchScope
{
    AllReadable = 0,
    SelectedRegion = 1,
    AddressRange = 2,
    Snapshots = 3
};

struct SearchOptions
{
    Pattern pattern;
    SearchScope scope = SearchScope::AllReadable;
    uintptr_t range_start = 0;
    uintptr_t range_end = 0;
    size_t selected_region_idx = 0;
    size_t max_results = 10000;
};

using SearchProgressCallback = std::function<void(SIZE_T bytes_scanned, SIZE_T total_bytes, size_t hits_found)>;

// Forward declarations
class MemorySource;
struct RegionInfo;
namespace core { struct ProcessSnapshot; }

std::vector<PatternMatchResult> search_memory_pattern(
    std::shared_ptr<MemorySource> source,
    const std::vector<RegionInfo> &regions,
    const SearchOptions &options,
    std::atomic<bool> *abort_flag = nullptr,
    SearchProgressCallback progress_cb = nullptr);

std::vector<PatternMatchResult> search_snapshot_pattern(
    const core::ProcessSnapshot &snapshot,
    const SearchOptions &options,
    std::atomic<bool> *abort_flag = nullptr,
    SearchProgressCallback progress_cb = nullptr);
