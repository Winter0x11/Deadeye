// src/core/behavior.hpp
// Deadeye Defensive Triage Behavior Analysis, Diffing, and YARA Generation
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <atomic>

#include "core/memsource.hpp"
#include "core/triage.hpp"
#include "core/pattern.hpp"

// Tier 1: Process-Wide Memory Diff Structures
struct ProcessRegionSnapshot
{
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD state = 0;
    DWORD type = 0;
    DWORD protect = 0;
    DWORD alloc_protect = 0;
    uintptr_t alloc_base = 0;
    uint64_t content_hash = 0;
    double entropy = 0.0;
    bool has_pe = false;
    bool is_unbacked = false;
    bool is_rwx = false;
    bool is_write_then_flip = false;
    bool is_readable = false;
};

struct ProcessSnapshotSession
{
    DWORD pid = 0;
    std::string process_name;
    std::string timestamp_str;
    SIZE_T total_committed_bytes = 0;
    std::vector<ProcessRegionSnapshot> regions;
};

enum class ProcessDiffKind
{
    Appeared,       // [NEW]
    Disappeared,    // [REMOVED]
    ProtectionChg,  // [PROT_CHG]
    ContentChg,     // [MODIFIED]
    Unchanged
};

struct ProcessDiffItem
{
    ProcessDiffKind kind = ProcessDiffKind::Unchanged;
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD type = 0;
    DWORD old_protect = 0;
    DWORD new_protect = 0;
    double old_entropy = 0.0;
    double new_entropy = 0.0;
    uint64_t old_hash = 0;
    uint64_t new_hash = 0;
    bool has_pe = false;
    bool is_rwx = false;
    bool is_unbacked = false;
    bool is_unpack = false;
    std::string summary;
};

// Tier 1: String Extraction & Categorization
struct RevealedString
{
    std::string text;
    std::string category; // "[URL] ", "[IP]  ", "[PATH]", "[CMD] ", "[REG] ", "[STR] "
    uintptr_t addr = 0;
};

// Tier 1: YARA Generation & False-Positive Testing
struct YaraWildcardResult
{
    std::string hex_pattern;
    size_t total_bytes = 0;
    size_t wildcard_count = 0;
    std::vector<std::string> wildcards_applied;
};

struct FalsePositiveMatch
{
    DWORD pid = 0;
    std::string process_name;
    uintptr_t match_addr = 0;
};

struct FalsePositiveReport
{
    size_t total_processes_checked = 0;
    size_t total_processes_scanned = 0;
    SIZE_T total_bytes_scanned = 0;
    std::vector<FalsePositiveMatch> matches;
    DWORD elapsed_ms = 0;
};

// ----------------------------------------------------------------------------
// Tier 1 Behavior Analysis: Entropy, Strings, and Time-Series Behavior Tracking
// ----------------------------------------------------------------------------

struct ExtractedStringItem
{
    uintptr_t addr = 0;
    std::string encoding; // "ASCII" or "UTF-16LE"
    size_t length = 0;
    std::string text;     // Capped to 256 chars for UI
    std::string tag_hint; // "[URL] (hint)", "[IP] (hint)", "[DOMAIN] (hint)", "[PATH] (hint)", "[REG] (hint)"
    uint64_t content_hash = 0; // 64-bit FNV-1a
    bool is_new = false;
    uintptr_t region_base = 0;
};

struct TrackedRegionKey
{
    uintptr_t base = 0;
    uintptr_t alloc_base = 0;
    uint32_t generation = 0;

    bool operator==(const TrackedRegionKey &o) const
    {
        return base == o.base && alloc_base == o.alloc_base && generation == o.generation;
    }
};

struct TrackedRegionKeyHash
{
    size_t operator()(const TrackedRegionKey &k) const
    {
        size_t h = std::hash<uintptr_t>()(k.base);
        h ^= std::hash<uintptr_t>()(k.alloc_base) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>()(k.generation) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct RegionSampleRecord
{
    uint64_t timestamp_ms = 0;
    DWORD protect = 0;
    DWORD state = 0;
    bool is_unreadable = false;
    uint64_t content_hash = 0;
    double avg_entropy = 0.0;
    double changed_fraction = 0.0; // 0.0 to 1.0 vs previous sample
    std::vector<uint8_t> sample_bytes; // Capped to 4096 bytes for XOR delta
};

inline constexpr size_t RING_BUFFER_CAP = 120;

struct WatchedRegionState
{
    TrackedRegionKey key;
    SIZE_T size = 0;
    DWORD type = 0;
    DWORD alloc_protect = 0;
    bool is_pinned = false;
    bool is_deallocated = false;

    // Ring buffer of last 120 samples
    std::vector<RegionSampleRecord> ring_samples;
    size_t total_samples = 0;

    // Behavioral Detection Findings
    int behavior_score = 0;
    std::vector<std::string> behavior_flags; // SLEEP_MASK_SUSPECT, KEY_ROTATION_SUSPECT, DECRYPT_ON_WAKE
    std::string evidence_summary;

    // Evidence Structs
    struct SleepEvidence
    {
        int cycles = 0;
        double period_ms = 0.0;
        double min_entropy = 0.0;
        double max_entropy = 0.0;
        std::string protect_seq;
    } sleep_evidence;

    struct KeyRotationEvidence
    {
        double avg_entropy = 0.0;
        double avg_changed_frac = 0.0;
        size_t xor_period = 0;
        std::vector<uint8_t> candidate_delta_key;
        std::string note;
    } key_evidence;

    struct DecryptOnWakeEvidence
    {
        double entropy_before = 0.0;
        double entropy_after = 0.0;
        size_t new_strings_count = 0;
        std::vector<std::string> sample_strings; // up to 10 strings
    } decrypt_evidence;
};

// String extraction and tagging
std::string classify_string_tag(const std::string &s);
std::string categorize_extracted_string(const std::string &s);
std::vector<RevealedString> extract_strings_from_buffer(const uint8_t *data, size_t len, uintptr_t base_addr, size_t min_len = 4);

void extract_all_strings_from_source(
    std::shared_ptr<MemorySource> source,
    const std::vector<RegionInfo> &regions,
    int selected_idx,
    size_t min_len,
    std::vector<ExtractedStringItem> &out_strings,
    const std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> *baselines = nullptr);

// Ring buffer sample management
void add_sample_to_ring(WatchedRegionState &wreg, const RegionSampleRecord &rec);

// Evaluates behavioral detections over watched region sample history
void evaluate_watched_region_detections(
    std::shared_ptr<MemorySource> source,
    WatchedRegionState &wreg,
    const std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> *baselines = nullptr);

// Context for background worker behavior tracking
struct BehaviorTrackerContext
{
    HANDLE proc = nullptr;
    std::vector<WatchedRegionState> *watched_regions = nullptr;
    std::unordered_map<uintptr_t, uint32_t> *region_generations = nullptr;
    const std::vector<RegionInfo> *regions = nullptr;
    const TriageReport *triage_report = nullptr;
    const std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> *string_baselines = nullptr;
    bool watch_all_priv_exec = false;
    size_t *rotating_idx = nullptr;
    std::atomic<uint64_t> *total_samples = nullptr;
    std::atomic<uint64_t> *partial_samples = nullptr;
    std::atomic<bool> *target_process_exited = nullptr;
};

// Core behavior tracking tick (returns true if tick executed, false if aborted/exited)
bool run_behavior_tracker_tick(
    std::shared_ptr<MemorySource> source,
    BehaviorTrackerContext &ctx);

// Process snapshot diffing and serialization
bool capture_process_snapshot_session(
    DWORD pid,
    ProcessSnapshotSession &out_session,
    std::string &out_err,
    HANDLE proc_handle = nullptr);

void compute_process_diff(
    const ProcessSnapshotSession &base,
    const ProcessSnapshotSession &cur,
    std::vector<ProcessDiffItem> &out_diffs);

bool save_process_session_to_file(
    const ProcessSnapshotSession &session,
    const std::string &filepath);

bool load_process_session_from_file(
    const std::string &filepath,
    ProcessSnapshotSession &session);

// YARA rule generation & testing
YaraWildcardResult auto_wildcard_bytes(
    const uint8_t *bytes,
    size_t len,
    uintptr_t base_addr = 0,
    DWORD pid = 0,
    const std::string &rule_name = "");

std::string generate_yara_rule_text(
    const YaraWildcardResult &wildcard_res,
    uintptr_t base_addr,
    DWORD pid,
    const std::string &rule_name);

FalsePositiveReport test_rule_false_positives(
    const Pattern &pat,
    DWORD exclude_pid);
