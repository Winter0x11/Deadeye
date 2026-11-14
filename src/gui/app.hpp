// src/gui/app.hpp
// Deadeye GUI Application State and Window Management
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <atomic>

#include "core/memsource.hpp"
#include "core/triage.hpp"
#include "core/behavior.hpp"
#include "core/pattern.hpp"
#include "gui/controls.hpp"

namespace gui {

inline constexpr SIZE_T CLI_CHUNK_SIZE = 1024 * 1024; // 1 MB per chunk read
inline constexpr SIZE_T VIEW_PAGE_SIZE = 64 * 1024;   // 64 KB per GUI page

// Application View Modes
enum class ViewMode
{
    TriageFindings = 0,
    MemoryMap = 1,
    BehaviorTracker = 2,
    StringsView = 3,
    ProcessDiff = 4
};

enum class WorkerTaskType
{
    MemoryMapScan = 0,
    Triage = 1,
    BehaviorTick = 2
};

struct WorkerTask
{
    HWND hwnd = nullptr;
    DWORD pid = 0;
    std::string pid_label;
    Pattern pat;
    bool use_pattern = false;
    WorkerTaskType task_type = WorkerTaskType::MemoryMapScan;
    std::shared_ptr<MemorySource> source;
};

struct WorkerResult
{
    WorkerTaskType task_type = WorkerTaskType::MemoryMapScan;
    DWORD pid = 0;
    std::string pid_label;
    Pattern pat;
    bool use_pattern = false;
    std::shared_ptr<MemorySource> source;
    bool success = false;
    DWORD error_code = 0;
    std::string error_msg;
    std::vector<RegionInfo> regions;
    TriageReport report;
    SIZE_T total_bytes = 0;
    SIZE_T total_hits = 0;
    size_t regions_with_hits = 0;
};

struct AppState
{
    // Themes & fonts & brushes
    AppTheme theme = AppTheme::Dark;
    HFONT mono_font = nullptr;
    HFONT ui_font = nullptr;
    HFONT ui_font_bold = nullptr;
    HBRUSH br_window = nullptr;
    HBRUSH br_control = nullptr;
    HACCEL haccel = nullptr;

    // Windows & Controls
    HWND hwnd_main = nullptr;
    HWND edit_pid = nullptr;
    HWND btn_attach = nullptr;
    HWND btn_load = nullptr;
    HWND btn_triage = nullptr;
    HWND edit_pattern = nullptr;
    HWND btn_search = nullptr;
    HWND btn_next_hit = nullptr;
    HWND chk_hits_only = nullptr;
    HWND chk_heartbeat = nullptr;
    HWND btn_diff_proc = nullptr;
    HWND btn_yara = nullptr;
    HWND combo_view_mode = nullptr;
    HWND combo_min_sev = nullptr;
    HWND chk_hide_clean = nullptr;
    HWND btn_export_json = nullptr;
    HWND list_regions = nullptr;
    HWND lbl_hex_info = nullptr;
    HWND btn_prev_page = nullptr;
    HWND btn_next_page = nullptr;
    HWND btn_snap = nullptr;
    HWND combo_diff = nullptr;
    HWND btn_clear_snaps = nullptr;
    HWND edit_hex = nullptr;
    HWND lbl_triage_reasons = nullptr;
    HWND lbl_status = nullptr;

    // View state & filters
    ViewMode view_mode = ViewMode::TriageFindings;
    int min_sev_filter = 0;
    bool hide_clean = false;

    // Active Target & Source
    DWORD current_pid = 0;
    std::string current_pid_label;
    HANDLE target_proc = nullptr;
    std::shared_ptr<MemorySource> current_source;
    std::vector<RegionInfo> regions;
    TriageReport triage_report;
    std::vector<size_t> visible_indices;
    size_t selected_region = 0;
    bool has_selection = false;

    // Hex view & pattern search
    Pattern active_pattern;
    bool has_pattern = false;
    SIZE_T view_offset = 0;
    size_t hit_cursor_region = 0;
    size_t hit_cursor_index = 0;
    std::string last_hex_dump;
    std::string last_hex_info;

    // Snapshots & Diff
    ProcessSnapshotSession process_baseline;
    ProcessSnapshotSession process_target;
    std::vector<ProcessDiffItem> process_diffs;
    bool has_baseline = false;
    bool has_target = false;
    std::vector<RevealedString> revealed_strings;

    // Strings subsystem
    std::vector<ExtractedStringItem> extracted_strings;
    std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> string_baselines;
    bool strings_filter_new_only = false;
    std::string strings_filter_query;
    size_t strings_min_len = 6;

    // Behavior tracker subsystem
    std::vector<WatchedRegionState> watched_regions;
    std::unordered_map<uintptr_t, uint32_t> region_generations;
    std::atomic<uint32_t> tracker_interval_ms{1000};
    std::atomic<uint64_t> tracker_total_samples{0};
    std::atomic<uint64_t> tracker_partial_samples{0};
    std::atomic<bool> tracker_active{false};
    std::atomic<bool> tracker_watch_all_priv_exec{false};
    std::atomic<bool> tracker_busy{false};
    std::atomic<bool> target_process_exited{false};
    size_t tracker_rotating_idx = 0;

    // Worker thread & async
    HANDLE h_worker_thread = nullptr;
    std::atomic<bool> scan_abort{false};
};

AppState& get_app_state();

HANDLE get_or_open_target_proc(DWORD pid);
void close_target_proc();
std::shared_ptr<MemorySource> get_active_source();
void set_status(const std::string &text);
void update_theme_brushes();
void apply_theme_switch(HWND hwnd, AppTheme new_theme);
void enable_ui_controls(BOOL enable);

void on_export_json();
void on_open_memory_source();
void on_capture_baseline();
void on_capture_diff();
void on_save_diff_session();
void on_load_diff_session();
void evaluate_memory_behavior_heartbeat();

void start_worker_task(WorkerTaskType task_type, bool require_pattern);
void on_worker_completed(WorkerResult *res);
DWORD WINAPI WorkerThreadProc(LPVOID param);

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
int run_gui(HINSTANCE hInst, int nCmdShow);

} // namespace gui
