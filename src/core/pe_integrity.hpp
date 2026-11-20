// src/core/pe_integrity.hpp
// Deadeye Defensive Triage PE Integrity & Memory Comparison Engine
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
#include <functional>
#include <atomic>

#include "core/memsource.hpp"
#include "core/timeline.hpp"

namespace core {

enum class PeIntegrityCategory : uint32_t
{
    ModifiedExecutableCode = 0,    // Changed bytes in executable sections (.text, etc.)
    ModifiedNonExecutableData,     // Changed bytes in non-executable data (.data, .rdata non-IAT)
    InlineHookCandidate,           // Code modification near entry / matching redirect instruction
    ImportAddressTable,            // IAT entries (expected resolution or unexpected hook)
    RelocationResolved,            // Valid base relocation applied by Windows loader
    UnexpectedSection,             // Section present in memory but not in on-disk PE headers
    MissingSection,                // Section present in disk headers but not in memory
    UnreadableMemory,              // Memory page unreadable / access denied
    ExpectedLoaderModification,    // Other legitimate loader changes
    Unclassified                   // Unclassified differences
};

enum class PeIntegritySeverity : uint32_t
{
    Critical = 0,   // Potential code tampering, inline hooks, hijacked IAT
    Warning,        // Data tampering, missing sections, unreadable pages
    Informational   // Expected loader fixups, valid relocations, standard IAT binding
};

struct PeExportSymbol
{
    std::string name;
    uint16_t ordinal = 0;
    uint32_t rva = 0;
    bool is_forwarder = false;
    std::string forwarder_str;
};

struct PeImportEntry
{
    std::string dll_name;
    std::string function_name;
    uint16_t ordinal = 0;
    uint32_t iat_rva = 0;
    uint32_t ilt_rva = 0;
    uintptr_t disk_value = 0;
};

struct PeIntegrityDifference
{
    PeIntegrityCategory category = PeIntegrityCategory::Unclassified;
    PeIntegritySeverity severity = PeIntegritySeverity::Informational;
    bool is_expected = false;

    std::string section_name;
    uintptr_t virtual_address = 0;
    uint32_t rva = 0;
    uint64_t file_offset = 0;
    size_t length = 0;

    std::vector<uint8_t> disk_bytes;
    std::vector<uint8_t> live_bytes;

    bool is_hook_candidate = false;
    uintptr_t hook_target_address = 0;
    std::string hook_target_module;
    std::string hook_instruction_desc;

    std::string nearest_export_name;
    int32_t export_offset = 0;

    std::string explanation;
};

struct LoadedModuleInfo
{
    std::string module_name;
    std::string module_path;
    uintptr_t base_address = 0;
    uint32_t image_size = 0;
    bool is_main_executable = false;
    bool is_wow64 = false;
};

struct PeModuleMetadata
{
    std::string module_name;
    std::string disk_file_path;
    uintptr_t live_base_address = 0;
    uintptr_t preferred_base_address = 0;
    uint32_t image_size = 0;
    std::string architecture; // "x64" or "x86"
    uint16_t machine = 0;
    std::string disk_sha256;
    uint32_t timedatestamp = 0;
    size_t section_count = 0;
    size_t exports_count = 0;
    size_t imports_count = 0;
};

struct PeIntegrityReport
{
    DWORD target_pid = 0;
    PeModuleMetadata metadata;
    uint64_t comparison_timestamp = 0;

    uint64_t total_compared_bytes = 0;
    uint64_t total_changed_bytes = 0;
    uint64_t total_ignored_expected_bytes = 0;
    uint64_t total_unreadable_bytes = 0;
    uint64_t total_unclassified_bytes = 0;

    size_t count_executable_diffs = 0;
    size_t count_data_diffs = 0;
    size_t count_hook_candidates = 0;
    size_t count_iat_diffs = 0;
    size_t count_reloc_diffs = 0;

    std::vector<PeIntegrityDifference> differences;
    std::vector<std::string> warnings;
    bool is_incomplete = false;
};

struct PeIntegrityOptions
{
    bool include_expected_differences = true; // Still recorded, tagged is_expected=true
    bool perform_hook_analysis = true;
    size_t chunk_size = 64 * 1024; // 64 KB chunk size for memory reads
    uintptr_t preferred_base_override = 0;
};

// Module Enumeration & Resolution
bool enumerate_process_modules(DWORD pid, HANDLE proc, std::vector<LoadedModuleInfo> &out_modules, std::string &out_err);
bool resolve_disk_module_path(const LoadedModuleInfo &mod, std::string &out_disk_path);
bool verify_pe_module_match(const std::string &disk_path, HANDLE proc, uintptr_t live_base, std::string &out_err);

// Comparison Engine for Live Process Handle
bool compare_pe_integrity(
    HANDLE proc,
    uintptr_t live_base,
    const std::string &disk_path,
    const PeIntegrityOptions &options,
    PeIntegrityReport &out_report,
    std::string &out_err,
    std::atomic<bool> *abort_flag = nullptr,
    std::function<void(float progress, const std::string &status)> progress_cb = nullptr,
    const std::vector<LoadedModuleInfo> *all_modules = nullptr);

// Comparison Engine for MemorySource & Raw Bytes (Test Target & Synthetic Fixtures)
bool compare_pe_memory_integrity(
    std::shared_ptr<MemorySource> live_source,
    uintptr_t live_base,
    const std::vector<uint8_t> &disk_pe_bytes,
    const PeIntegrityOptions &options,
    PeIntegrityReport &out_report,
    std::string &out_err,
    std::atomic<bool> *abort_flag = nullptr,
    std::function<void(float progress, const std::string &status)> progress_cb = nullptr,
    const std::vector<LoadedModuleInfo> *all_modules = nullptr);

// Helpers & Formatting
std::string format_integrity_category(PeIntegrityCategory cat);
std::string format_integrity_severity(PeIntegritySeverity sev);
std::string export_pe_integrity_json(const PeIntegrityReport &report, bool include_byte_arrays = true, size_t max_bytes_cap = 256);
void record_integrity_report_to_timeline(TimelineManager &timeline, DWORD pid, const PeIntegrityReport &report);

// SHA-256 calculation
std::string compute_sha256_hex(const uint8_t *data, size_t len);

} // namespace core
