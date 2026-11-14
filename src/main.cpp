// src/main.cpp
// Deadeye - Windows Process Memory Triage Scanner, Hex Viewer & Real-Time Diff Timeline.
// Built for defensive malware analysis and detection engineering.
// Pure Win32 GUI application (/SUBSYSTEM:WINDOWS, -mwindows) with visual triage memory theme.
//
// Build (MinGW-w64, x64):
//   windres src/deadeye.rc -O coff -o build/deadeye_res.o
//   g++ -std=c++17 -m64 -Wall -Wextra -pedantic -O2 src/main.cpp build/deadeye_res.o -o build/deadeye.exe -mwindows -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32
// Build (MSVC x64):
//   cl /std:c++17 /EHsc /W4 /O2 src/main.cpp /Fe:build/deadeye.exe /link /SUBSYSTEM:WINDOWS advapi32.lib comctl32.lib comdlg32.lib user32.lib gdi32.lib

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef IDI_APP
#define IDI_APP 101
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>
#include "core/util.hpp"
#include <commdlg.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>

#ifdef _MSC_VER
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#endif

// ============================================================================
// 1. Constants & Core Data Structures
// ============================================================================

// Memory read chunk sizes
static const SIZE_T CLI_CHUNK_SIZE = 1024 * 1024; // 1 MB per chunk read
static const SIZE_T VIEW_PAGE_SIZE = 64 * 1024;   // 64 KB per GUI page
#include "core/scoring.hpp"
#include "core/pattern.hpp"
#include "core/memsource.hpp"
#include "core/live_source.hpp"
#include "core/pe_source.hpp"
#include "core/triage.hpp"

// Control IDs for GUI child windows
#define ID_EDIT_PID 101
#define ID_BTN_LOAD 102
#define ID_EDIT_PATTERN 103
#define ID_BTN_SEARCH 104
#define ID_BTN_NEXT_HIT 105
#define ID_CHK_HITS_ONLY 106
#define ID_LIST_REGIONS 107
#define ID_EDIT_HEX 108
#define ID_BTN_PREV_PAGE 109
#define ID_BTN_NEXT_PAGE 110
#define ID_BTN_SNAP 111
#define ID_COMBO_DIFF 112
#define ID_BTN_CLEAR_SNAPS 113
#define ID_CHK_HEARTBEAT 114
#define ID_BTN_TRIAGE 115
#define ID_COMBO_VIEW_MODE 116
#define ID_COMBO_MIN_SEV 117
#define ID_CHK_HIDE_CLEAN 118
#define ID_BTN_EXPORT_JSON 119
#define ID_BTN_DIFF_PROC 121
#define ID_BTN_YARA 122
#define ID_BTN_ATTACH 123
#define IDT_HEARTBEAT 1001

// Menu Item IDs
#define IDM_FILE_OPEN_SOURCE 2001
#define IDM_FILE_TRIAGE 2002
#define IDM_FILE_EXPORT_JSON 2003
#define IDM_FILE_THEME_LIGHT 2004
#define IDM_FILE_THEME_DARK 2005
#define IDM_FILE_EXIT 2006
#define IDM_FILE_ATTACH 2007

#define IDM_EDIT_COPY_ADDR 2010
#define IDM_EDIT_COPY_HEX 2011
#define IDM_EDIT_FIND_PATTERN 2012
#define IDM_EDIT_FIND_NEXT 2013
#define IDM_EDIT_GENERATE_YARA 2014

#define IDM_VIEW_TRIAGE_FINDINGS 2020
#define IDM_VIEW_MEMORY_MAP 2021
#define IDM_VIEW_BEHAVIOR 2023
#define IDM_VIEW_STRINGS 2027
#define IDM_VIEW_PROCESS_DIFF 2022
#define IDM_VIEW_HIDE_CLEAN 2024
#define IDM_VIEW_HITS_ONLY 2025
#define IDM_VIEW_REFRESH 2026

#define IDM_TIMELINE_SNAP 2030
#define IDM_TIMELINE_CLEAR 2031
#define IDM_TIMELINE_HEARTBEAT 2032
#define IDM_TIMELINE_PREV_PAGE 2033
#define IDM_TIMELINE_NEXT_PAGE 2034

#define IDM_DIFF_CAPTURE_BASELINE 2050
#define IDM_DIFF_CAPTURE_CURRENT 2051
#define IDM_DIFF_SAVE_SESSION 2052
#define IDM_DIFF_LOAD_SESSION 2053
#define IDM_DIFF_VIEW_STRINGS 2055

#define IDM_BEHAVIOR_PIN 2060
#define IDM_BEHAVIOR_WATCH_ALL_PRIV 2061
#define IDM_BEHAVIOR_CLEAR 2062

#define IDM_STRINGS_BASELINE 2070
#define IDM_STRINGS_TOGGLE_NEW 2071
#define IDM_STRINGS_EXTRACT_SEL 2072
#define IDM_STRINGS_EXTRACT_ALL 2073

#define IDM_HELP_HEURISTICS 2040
#define IDM_HELP_ABOUT 2041
#define IDM_HELP_BEHAVIOR_LIMITS 2042

// Custom window messages for background worker thread scanning & triage
#define WM_SCAN_PROGRESS (WM_USER + 1)
#define WM_SCAN_COMPLETE (WM_USER + 2)
#define WM_TRIAGE_COMPLETE (WM_USER + 3)
#define WM_BEHAVIOR_TICK_DONE (WM_USER + 4)

#include "core/behavior.hpp"

// Application View Modes
enum class ViewMode
{
    TriageFindings = 0,
    MemoryMap = 1,
    BehaviorTracker = 2,
    StringsView = 3,
    ProcessDiff = 4
};

// Strings Subsystem State
static std::vector<ExtractedStringItem> g_extracted_strings;
static std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> g_string_baselines;
static bool g_strings_filter_new_only = false;
static std::string g_strings_filter_query;
static size_t g_strings_min_len = 6;

// Behavior Tracker Subsystem State
static std::vector<WatchedRegionState> g_watched_regions;
static std::unordered_map<uintptr_t, uint32_t> g_region_generations;
static std::atomic<uint32_t> g_tracker_interval_ms{1000};
static std::atomic<uint64_t> g_tracker_total_samples{0};
static std::atomic<uint64_t> g_tracker_partial_samples{0};
static std::atomic<bool> g_tracker_active{false};
static std::atomic<bool> g_tracker_watch_all_priv_exec{false};
static std::atomic<bool> g_tracker_busy{false};
static std::atomic<bool> g_target_process_exited{false};
static size_t g_tracker_rotating_idx = 0;

LRESULT CALLBACK AttachDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void open_attach_process_dialog(HWND hParent);

// Application Color Themes
enum class AppTheme
{
    Light = 0,
    Dark = 1
};

// Visual Theme Colors
struct ThemeColors
{
    COLORREF bg_window;
    COLORREF bg_control;
    COLORREF text_normal;
    COLORREF text_muted;

    // Visual Triage Row Highlighting Palette
    COLORREF row_crit_bg;
    COLORREF row_crit_text;
    COLORREF row_rwx_bg;
    COLORREF row_rwx_text;
    COLORREF row_pe_bg;
    COLORREF row_pe_text;
    COLORREF row_flip_bg;
    COLORREF row_flip_text;
    COLORREF row_unlinked_bg;
    COLORREF row_unlinked_text;
    COLORREF row_unbacked_bg;
    COLORREF row_unbacked_text;
    COLORREF row_priv_bg;
    COLORREF row_priv_text;
    COLORREF row_mapped_bg;
    COLORREF row_mapped_text;
    COLORREF row_image_bg;
    COLORREF row_image_text;

    // Process Diff Row Highlighting Palette
    COLORREF row_diff_new_bg;
    COLORREF row_diff_new_text;
    COLORREF row_diff_chg_bg;
    COLORREF row_diff_chg_text;
    COLORREF row_diff_mod_bg;
    COLORREF row_diff_mod_text;
    COLORREF row_diff_del_bg;
    COLORREF row_diff_del_text;

    COLORREF row_sel_bg;
    COLORREF row_sel_text;
};

// Classic Light Theme
static const ThemeColors g_theme_light = {
    RGB(240, 240, 240), // bg_window
    RGB(255, 255, 255), // bg_control
    RGB(20, 20, 20),    // text_normal
    RGB(100, 100, 100), // text_muted

    RGB(255, 180, 180), RGB(140, 0, 0),  // Crit (Alert Red)
    RGB(255, 192, 192), RGB(150, 0, 0),  // RWX (Salmon / Red Alert)
    RGB(232, 208, 255), RGB(75, 0, 130), // Injected PE (Violet Purple)
    RGB(255, 224, 185), RGB(140, 60, 0), // Write-then-flip (Peach / Orange)
    RGB(232, 208, 255), RGB(75, 0, 130), // Unlinked module (Violet Purple)
    RGB(255, 245, 180), RGB(120, 80, 0), // Unbacked exec (Light gold/yellow)
    RGB(255, 255, 225), RGB(70, 70, 0),  // MEM_PRIVATE clean (Warm Yellow)
    RGB(230, 242, 255), RGB(0, 60, 120), // MEM_MAPPED clean (Sky Blue)
    RGB(255, 255, 255), RGB(20, 20, 20), // MEM_IMAGE clean (Pure white)

    RGB(215, 245, 225), RGB(0, 100, 35),   // Diff New (Mint Green)
    RGB(255, 224, 185), RGB(140, 60, 0),   // Diff Prot Changed (Peach / Orange)
    RGB(255, 248, 195), RGB(120, 80, 0),   // Diff Modified (Amber / Gold)
    RGB(235, 235, 235), RGB(120, 120, 120), // Diff Disappeared (Muted Gray)

    RGB(51, 153, 255), RGB(255, 255, 255) // Selection (Windows blue / white text)
};

// Modern Dark Theme
static const ThemeColors g_theme_dark = {
    RGB(30, 30, 30),    // bg_window
    RGB(37, 37, 38),    // bg_control
    RGB(220, 220, 220), // text_normal
    RGB(140, 140, 140), // text_muted

    RGB(75, 20, 25), RGB(255, 140, 140), // Crit (Dark crimson)
    RGB(70, 25, 25), RGB(255, 150, 150), // RWX (Deep red)
    RGB(55, 25, 65), RGB(220, 160, 255), // Injected PE (Dark violet)
    RGB(65, 45, 20), RGB(255, 190, 120), // Write-then-flip (Dark amber)
    RGB(55, 25, 65), RGB(220, 160, 255), // Unlinked module (Dark violet)
    RGB(60, 55, 20), RGB(255, 230, 130), // Unbacked exec (Dark gold)
    RGB(42, 42, 30), RGB(240, 240, 170), // MEM_PRIVATE (Muted yellow tint)
    RGB(25, 40, 55), RGB(170, 210, 255), // MEM_MAPPED (Muted blue tint)
    RGB(37, 37, 38), RGB(220, 220, 220), // MEM_IMAGE (Neutral dark)

    RGB(20, 55, 30), RGB(150, 255, 180),  // Diff New (Dark Emerald / Mint)
    RGB(65, 45, 20), RGB(255, 190, 120),  // Diff Prot Changed (Dark Amber)
    RGB(60, 55, 20), RGB(255, 230, 130),  // Diff Modified (Dark Gold)
    RGB(35, 35, 35), RGB(130, 130, 130),  // Diff Disappeared (Dim Gray)

    RGB(26, 95, 180), RGB(255, 255, 255) // Selection (Deep slate blue)
};

// ============================================================================
// 2. Pattern Matching Functions
// ============================================================================

// Serializes a TriageReport into valid JSON with full MemorySource metadata.
// UI-independent core function.
std::string export_triage_json(const TriageReport &report)
{
    std::string json;
    json.reserve(report.findings.size() * 512 + 512);
    json += "{\n";
    json += "  \"source\": {\n";
    std::string kind_str = "Live";
    if (report.source_kind == MemorySourceKind::MappedPe) kind_str = "MappedPe";
    else if (report.source_kind == MemorySourceKind::RawFile) kind_str = "RawFile";
    json += "    \"kind\": \"" + kind_str + "\",\n";
    json += "    \"name\": \"" + escape_json(report.source_description) + "\",\n";
    json += "    \"base\": \"" + to_hex_string(report.source_base) + "\",\n";
    json += "    \"synthetic_protection\": " + std::string(report.protection_is_synthetic ? "true" : "false") + "\n";
    json += "  },\n";
    json += "  \"pid\": " + std::to_string(report.pid) + ",\n";
    json += "  \"wow64_unsupported\": " + std::string(report.wow64_unsupported ? "true" : "false") + ",\n";
    json += "  \"rules_not_evaluated\": [";
    for (size_t k = 0; k < report.rules_not_evaluated.size(); ++k)
    {
        json += "\"" + report.rules_not_evaluated[k] + "\"" + (k + 1 < report.rules_not_evaluated.size() ? ", " : "");
    }
    json += "],\n";

    // 1. Per-region Entropy Profiles
    json += "  \"entropy\": [\n";
    for (size_t i = 0; i < report.entropy_profiles.size(); ++i)
    {
        const auto &e = report.entropy_profiles[i];
        json += "    {\n";
        json += "      \"base\": \"" + to_hex_string(e.base) + "\",\n";
        json += "      \"avg_entropy\": " + ((e.avg_entropy >= 0.0) ? std::to_string(e.avg_entropy) : "-1.0") + ",\n";
        json += "      \"max_entropy\": " + ((e.max_entropy >= 0.0) ? std::to_string(e.max_entropy) : "-1.0") + ",\n";
        json += "      \"ascii_profile\": \"" + escape_json(e.ascii_profile) + "\"\n";
        json += "    }" + std::string(i + 1 < report.entropy_profiles.size() ? ",\n" : "\n");
    }
    json += "  ],\n";

    // 2. Behavioral Tracking Array (Live Sources Only)
    json += "  \"behavior\": [\n";
    if (report.source_kind == MemorySourceKind::Live)
    {
        for (size_t i = 0; i < g_watched_regions.size(); ++i)
        {
            const auto &w = g_watched_regions[i];
            json += "    {\n";
            json += "      \"base\": \"" + to_hex_string(w.key.base) + "\",\n";
            json += "      \"alloc_base\": \"" + to_hex_string(w.key.alloc_base) + "\",\n";
            json += "      \"generation\": " + std::to_string(w.key.generation) + ",\n";
            json += "      \"size\": " + std::to_string(w.size) + ",\n";
            json += "      \"pinned\": " + std::string(w.is_pinned ? "true" : "false") + ",\n";
            json += "      \"sample_count\": " + std::to_string(w.ring_samples.size()) + ",\n";
            json += "      \"partial_sample_count\": " + std::to_string(g_tracker_partial_samples.load()) + ",\n";
            json += "      \"interval_ms\": " + std::to_string(g_tracker_interval_ms.load()) + ",\n";
            json += "      \"score\": " + std::to_string(w.behavior_score) + ",\n";
            json += "      \"flags\": [";
            for (size_t k = 0; k < w.behavior_flags.size(); ++k)
            {
                json += "\"" + w.behavior_flags[k] + "\"" + (k + 1 < w.behavior_flags.size() ? ", " : "");
            }
            json += "],\n";
            json += "      \"evidence\": {\n";
            json += "        \"summary\": \"" + escape_json(w.evidence_summary) + "\",\n";
            json += "        \"sleep_mask\": {\n";
            json += "          \"cycle_count\": " + std::to_string(w.sleep_evidence.cycles) + ",\n";
            json += "          \"period_ms\": " + std::to_string(w.sleep_evidence.period_ms) + ",\n";
            json += "          \"min_entropy\": " + std::to_string(w.sleep_evidence.min_entropy) + ",\n";
            json += "          \"max_entropy\": " + std::to_string(w.sleep_evidence.max_entropy) + ",\n";
            json += "          \"protection_sequence\": \"" + escape_json(w.sleep_evidence.protect_seq) + "\"\n";
            json += "        },\n";
            json += "        \"key_rotation\": {\n";
            json += "          \"xor_period\": " + std::to_string(w.key_evidence.xor_period) + ",\n";
            std::string dkey_hex;
            for (uint8_t kb : w.key_evidence.candidate_delta_key)
            {
                char h[4]; std::snprintf(h, sizeof(h), "%02X ", kb); dkey_hex += h;
            }
            json += "          \"candidate_delta_key_hex\": \"" + escape_json(dkey_hex) + "\",\n";
            json += "          \"note\": \"" + escape_json(w.key_evidence.note) + "\"\n";
            json += "        },\n";
            json += "        \"decrypt_on_wake\": {\n";
            json += "          \"entropy_before\": " + std::to_string(w.decrypt_evidence.entropy_before) + ",\n";
            json += "          \"entropy_after\": " + std::to_string(w.decrypt_evidence.entropy_after) + ",\n";
            json += "          \"new_strings_count\": " + std::to_string(w.decrypt_evidence.new_strings_count) + ",\n";
            json += "          \"sample_strings\": [";
            for (size_t s = 0; s < w.decrypt_evidence.sample_strings.size(); ++s)
            {
                json += "\"" + escape_json(w.decrypt_evidence.sample_strings[s]) + "\"" + (s + 1 < w.decrypt_evidence.sample_strings.size() ? ", " : "");
            }
            json += "]\n";
            json += "        }\n";
            json += "      }\n";
            json += "    }" + std::string(i + 1 < g_watched_regions.size() ? ",\n" : "\n");
        }
    }
    json += "  ],\n";

    json += "  \"findings_count\": " + std::to_string(report.findings.size()) + ",\n";
    json += "  \"findings\": [\n";

    for (size_t i = 0; i < report.findings.size(); ++i)
    {
        const TriageFinding &f = report.findings[i];
        json += "    {\n";
        json += "      \"base\": \"" + to_hex_string(f.base) + "\",\n";
        json += "      \"size\": " + std::to_string(f.size) + ",\n";
        json += "      \"alloc_base\": \"" + to_hex_string(f.alloc_base) + "\",\n";
        json += "      \"type\": \"" + type_full(f.type) + "\",\n";
        json += "      \"protect\": \"" + prot_full(f.protect) + "\",\n";
        json += "      \"alloc_protect\": \"" + prot_full(f.alloc_protect) + "\",\n";
        json += "      \"severity_score\": " + std::to_string(f.severity_score) + ",\n";
        json += "      \"severity_label\": \"" + f.severity_label + "\",\n";

        json += "      \"flags\": [";
        for (size_t k = 0; k < f.flags.size(); ++k)
        {
            json += "\"" + f.flags[k] + "\"" + (k + 1 < f.flags.size() ? ", " : "");
        }
        json += "],\n";

        json += "      \"reasons\": [\n";
        for (size_t k = 0; k < f.reasons.size(); ++k)
        {
            json += "        \"" + escape_json(f.reasons[k]) + "\"" + (k + 1 < f.reasons.size() ? ",\n" : "\n");
        }
        json += "      ]\n";
        json += "    }" + std::string(i + 1 < report.findings.size() ? ",\n" : "\n");
    }

    json += "  ]\n";
    json += "}\n";
    return json;
}

// ============================================================================
// 3. GUI Subsystem (Visual Triage, Owner-Draw List, Memory Hex Viewer)
// ============================================================================

static HWND g_hwnd_main = nullptr;
static HWND g_edit_pid = nullptr;
static HWND g_btn_attach = nullptr;
static HWND g_btn_load = nullptr;
static HWND g_btn_triage = nullptr;
static HWND g_edit_pattern = nullptr;
static HWND g_btn_search = nullptr;
static HWND g_btn_next_hit = nullptr;
static HWND g_chk_hits_only = nullptr;
static HWND g_chk_heartbeat = nullptr;
static HWND g_btn_diff_proc = nullptr;
static HWND g_btn_yara = nullptr;

static HWND g_combo_view_mode = nullptr;
static HWND g_combo_min_sev = nullptr;
static HWND g_chk_hide_clean = nullptr;
static HWND g_btn_export_json = nullptr;

static HWND g_list_regions = nullptr;
static HWND g_lbl_hex_info = nullptr;
static HWND g_btn_prev_page = nullptr;
static HWND g_btn_next_page = nullptr;
static HWND g_btn_snap = nullptr;
static HWND g_combo_diff = nullptr;
static HWND g_btn_clear_snaps = nullptr;
static HWND g_edit_hex = nullptr;
static HWND g_lbl_triage_reasons = nullptr;
static HWND g_lbl_status = nullptr;

static HFONT g_mono_font = nullptr;
static HFONT g_ui_font = nullptr;
static HFONT g_ui_font_bold = nullptr;
static HBRUSH g_br_window = nullptr;
static HBRUSH g_br_control = nullptr;
static HACCEL g_haccel = nullptr;

static AppTheme g_theme = AppTheme::Light;
static ViewMode g_view_mode = ViewMode::TriageFindings;
static int g_min_sev_filter = 0;
static bool g_hide_clean = false;

static DWORD g_current_pid = 0;
static std::string g_current_pid_label;
static std::shared_ptr<MemorySource> g_current_source = nullptr;
static Pattern g_active_pattern;
static bool g_has_pattern = false;
static std::vector<RegionInfo> g_regions;
static TriageReport g_triage_report;
static std::vector<size_t> g_visible_indices;
static size_t g_selected_region = 0;
static bool g_has_selection = false;
static SIZE_T g_view_offset = 0;
static size_t g_hit_cursor_region = 0;
static size_t g_hit_cursor_index = 0;

// Process-wide Diff and Behavioral Tracking State
static ProcessSnapshotSession g_process_baseline;
static ProcessSnapshotSession g_process_target;
static std::vector<ProcessDiffItem> g_process_diffs;
static bool g_has_baseline = false;
static bool g_has_target = false;
static std::vector<RevealedString> g_revealed_strings;

static HANDLE g_target_proc = nullptr;
static std::string g_last_hex_dump;
static std::string g_last_hex_info;

void close_target_proc()
{
    if (g_target_proc != nullptr)
    {
        CloseHandle(g_target_proc);
        g_target_proc = nullptr;
    }
}

HANDLE get_or_open_target_proc(DWORD pid)
{
    if (g_target_proc != nullptr)
    {
        DWORD exit_code = 0;
        if (g_current_pid == pid && GetExitCodeProcess(g_target_proc, &exit_code) && exit_code == STILL_ACTIVE)
        {
            return g_target_proc;
        }
        close_target_proc();
    }
    g_target_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    return g_target_proc;
}

std::shared_ptr<MemorySource> get_active_source()
{
    if (g_current_source != nullptr)
    {
        return g_current_source;
    }
    if (g_current_pid != 0)
    {
        HANDLE proc = get_or_open_target_proc(g_current_pid);
        g_current_source = std::make_shared<LiveProcessSource>(g_current_pid, proc, false, g_current_pid_label);
        return g_current_source;
    }
    return nullptr;
}

void invalidate_hex_cache()
{
    g_last_hex_dump.clear();
    g_last_hex_info.clear();
}

void set_status(const std::string &text)
{
    SetWindowTextA(g_lbl_status, text.c_str());
}

const ThemeColors &get_current_theme()
{
    return (g_theme == AppTheme::Light) ? g_theme_light : g_theme_dark;
}

void update_theme_brushes()
{
    if (g_br_window)
        DeleteObject(g_br_window);
    if (g_br_control)
        DeleteObject(g_br_control);
    const ThemeColors &tc = get_current_theme();
    g_br_window = CreateSolidBrush(tc.bg_window);
    g_br_control = CreateSolidBrush(tc.bg_control);
}

void apply_theme_switch(HWND hwnd, AppTheme new_theme)
{
    g_theme = new_theme;
    update_theme_brushes();
    InvalidateRect(hwnd, nullptr, TRUE);
    if (g_list_regions) InvalidateRect(g_list_regions, nullptr, TRUE);
    if (g_edit_hex) InvalidateRect(g_edit_hex, nullptr, TRUE);
    if (g_lbl_triage_reasons) InvalidateRect(g_lbl_triage_reasons, nullptr, TRUE);
    if (g_lbl_status) InvalidateRect(g_lbl_status, nullptr, TRUE);
    HWND btns[] = { g_btn_attach, g_btn_load, g_btn_triage, g_btn_search, g_btn_next_hit, g_btn_export_json, g_btn_snap, g_btn_clear_snaps, g_btn_prev_page, g_btn_next_page, g_btn_diff_proc, g_btn_yara };
    for (HWND b : btns) { if (b) InvalidateRect(b, nullptr, TRUE); }
    set_status((g_theme == AppTheme::Dark) ? "Theme switched to Modern Dark." : "Theme switched to Classic Light.");
}

struct DiffPair
{
    bool active;
    std::string title;
    const std::vector<uint8_t> *ref_data;
    const std::vector<uint8_t> *cmp_data;
    SIZE_T ref_view_offset;
    SIZE_T cmp_view_offset;
};

DiffPair get_active_diff_pair()
{
    DiffPair dp = {false, "", nullptr, nullptr, 0, 0};
    if (!g_has_selection || g_selected_region >= g_regions.size())
        return dp;
    const RegionInfo &reg = g_regions[g_selected_region];
    if (reg.snapshots.empty())
        return dp;

    LRESULT sel = SendMessageA(g_combo_diff, CB_GETCURSEL, 0, 0);
    if (sel <= 0 || sel == CB_ERR)
        return dp;

    size_t snap_count = reg.snapshots.size();
    if (static_cast<size_t>(sel) <= snap_count)
    {
        size_t idx = static_cast<size_t>(sel - 1);
        dp.active = true;
        dp.title = "Live vs " + reg.snapshots[idx].label;
        dp.ref_data = &reg.snapshots[idx].data;
        dp.cmp_data = nullptr; // Live
        dp.ref_view_offset = reg.snapshots[idx].view_offset;
        dp.cmp_view_offset = g_view_offset;
        return dp;
    }

    size_t pair_idx = static_cast<size_t>(sel - 1 - snap_count);
    if (pair_idx + 1 < snap_count)
    {
        dp.active = true;
        dp.title = reg.snapshots[pair_idx].label + " vs " + reg.snapshots[pair_idx + 1].label;
        dp.ref_data = &reg.snapshots[pair_idx].data;
        dp.cmp_data = &reg.snapshots[pair_idx + 1].data;
        dp.ref_view_offset = reg.snapshots[pair_idx].view_offset;
        dp.cmp_view_offset = reg.snapshots[pair_idx + 1].view_offset;
        return dp;
    }
    return dp;
}

std::string build_hex_dump(const uint8_t *buf, size_t buf_len, uintptr_t view_addr,
                           const std::vector<SIZE_T> &region_hits, SIZE_T view_offset,
                           size_t pat_len, SIZE_T focus_offset, int &out_focus_line,
                           const uint8_t *ref_buf, size_t ref_len, bool diff_active,
                           size_t &out_chg_bytes, size_t &out_new_bytes, size_t &out_zeroed_bytes)
{
    out_focus_line = -1;
    out_chg_bytes = 0;
    out_new_bytes = 0;
    out_zeroed_bytes = 0;

    if (buf_len == 0)
    {
        return "(No readable bytes in this page)\r\n";
    }

    std::vector<uint8_t> hit_byte(buf_len, 0);
    if (g_has_pattern && pat_len > 0)
    {
        for (size_t i = 0; i < region_hits.size(); ++i)
        {
            SIZE_T h = region_hits[i];
            if (h + pat_len <= view_offset || h >= view_offset + buf_len)
            {
                continue;
            }
            for (size_t j = 0; j < pat_len; ++j)
            {
                if (h + j >= view_offset && h + j < view_offset + buf_len)
                {
                    hit_byte[(h + j) - view_offset] = 1;
                }
            }
        }
    }

    std::string out;
    out.reserve(buf_len * 6 + 256);
    out += "    Address           00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  0123456789ABCDEF\r\n";
    out += "    ----------------  -----------------------  -----------------------  ----------------\r\n";

    size_t num_rows = (buf_len + 15) / 16;
    int line_counter = 2;

    for (size_t row = 0; row < num_rows; ++row)
    {
        size_t rs = row * 16;
        size_t re = rs + 16;
        if (re > buf_len)
            re = buf_len;

        bool row_has_hit = false;
        bool row_has_diff = false;

        for (size_t i = rs; i < re; ++i)
        {
            if (hit_byte[i] != 0)
            {
                row_has_hit = true;
            }
            if (diff_active && ref_buf != nullptr)
            {
                if (i < ref_len)
                {
                    if (buf[i] != ref_buf[i])
                    {
                        row_has_diff = true;
                        out_chg_bytes++;
                        if (ref_buf[i] == 0 && buf[i] != 0)
                            out_new_bytes++;
                        else if (ref_buf[i] != 0 && buf[i] == 0)
                            out_zeroed_bytes++;
                    }
                }
                else
                {
                    row_has_diff = true;
                    out_chg_bytes++;
                    if (buf[i] != 0)
                        out_new_bytes++;
                }
            }
        }

        if (focus_offset != static_cast<SIZE_T>(-1) &&
            focus_offset >= view_offset + rs && focus_offset < view_offset + re)
        {
            out_focus_line = line_counter;
        }

        if (row_has_hit && row_has_diff)
        {
            out += "!>> ";
        }
        else if (row_has_diff)
        {
            out += "CHG ";
        }
        else if (row_has_hit)
        {
            out += ">>> ";
        }
        else
        {
            out += "    ";
        }

        out += fmt_addr(view_addr + rs);
        out += "  ";

        char hx[8];
        for (size_t i = rs; i < rs + 16; ++i)
        {
            if (i == rs + 8)
                out += " ";
            if (i < re)
            {
                std::snprintf(hx, sizeof(hx), "%02X ", buf[i]);
                out += hx;
            }
            else
            {
                out += "   ";
            }
        }
        out += " ";

        for (size_t i = rs; i < rs + 16; ++i)
        {
            if (i < re)
            {
                uint8_t b = buf[i];
                out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            }
            else
            {
                out += ' ';
            }
        }
        out += "\r\n";
        line_counter++;

        // Sub-row for changed bytes in diff timeline
        if (row_has_diff && ref_buf != nullptr)
        {
            out += "        old:          ";
            for (size_t i = rs; i < rs + 16; ++i)
            {
                if (i == rs + 8)
                    out += " ";
                if (i < re && i < ref_len && buf[i] != ref_buf[i])
                {
                    std::snprintf(hx, sizeof(hx), "%02X ", ref_buf[i]);
                    out += hx;
                }
                else
                {
                    out += "   ";
                }
            }
            out += " ";
            for (size_t i = rs; i < rs + 16; ++i)
            {
                if (i < re && i < ref_len && buf[i] != ref_buf[i])
                {
                    uint8_t b = ref_buf[i];
                    out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
                }
                else
                {
                    out += ' ';
                }
            }
            out += "\r\n";
            line_counter++;
        }
    }
    return out;
}

void display_selected_region(SIZE_T focus_offset);
void populate_region_list();
void update_triage_details_label(size_t reg_idx);

void update_diff_combo()
{
    SendMessageA(g_combo_diff, CB_RESETCONTENT, 0, 0);
    SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Diff: Off (Normal)"));

    if (!g_has_selection || g_selected_region >= g_regions.size())
    {
        SendMessageA(g_combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(g_btn_snap, FALSE);
        EnableWindow(g_combo_diff, FALSE);
        EnableWindow(g_btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(g_btn_snap, TRUE);
    const RegionInfo &reg = g_regions[g_selected_region];

    if (reg.snapshots.empty())
    {
        SendMessageA(g_combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(g_combo_diff, FALSE);
        EnableWindow(g_btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(g_combo_diff, TRUE);
    EnableWindow(g_btn_clear_snaps, TRUE);

    for (size_t i = 0; i < reg.snapshots.size(); ++i)
    {
        std::string item = "Live vs " + reg.snapshots[i].label;
        SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
    }

    if (reg.snapshots.size() >= 2)
    {
        for (size_t i = 0; i + 1 < reg.snapshots.size(); ++i)
        {
            std::string item = reg.snapshots[i].label + " vs " + reg.snapshots[i + 1].label;
            SendMessageA(g_combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
        }
    }

    LRESULT count = SendMessageA(g_combo_diff, CB_GETCOUNT, 0, 0);
    WPARAM sel = (reg.snapshots.size() > 0) ? static_cast<WPARAM>(reg.snapshots.size()) : 0;
    if (sel >= static_cast<WPARAM>(count))
        sel = 0;
    SendMessageA(g_combo_diff, CB_SETCURSEL, sel, 0);
}

void on_take_snapshot()
{
    if (!g_has_selection || g_selected_region >= g_regions.size())
        return;
    RegionInfo &reg = g_regions[g_selected_region];

    if (g_view_offset >= reg.size)
        g_view_offset = 0;
    SIZE_T remaining = reg.size - g_view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    auto src = get_active_source();
    if (src == nullptr)
    {
        set_status("[ERROR] No memory source available");
        return;
    }

    Snapshot snap;
    snap.data.resize(to_read);
    SIZE_T bytes_read = src->read(reg.base + g_view_offset, to_read, snap.data.data());

    if (bytes_read == 0)
    {
        set_status("[ERROR] Could not capture snapshot: memory unreadable at 0x" + fmt_addr(reg.base + g_view_offset));
        return;
    }
    snap.data.resize(bytes_read);
    snap.view_offset = g_view_offset;
    snap.timestamp_ms = GetTickCount();

    size_t snap_num = reg.snapshots.size() + 1;
    char label_buf[64];
    if (reg.snapshots.empty())
    {
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (0.0s)", snap_num);
    }
    else
    {
        DWORD elapsed_ms = snap.timestamp_ms - reg.snapshots[0].timestamp_ms;
        double sec = static_cast<double>(elapsed_ms) / 1000.0;
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (+%.1fs)", snap_num, sec);
    }
    snap.label = label_buf;

    reg.snapshots.push_back(snap);
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis)
    {
        if (g_visible_indices[vis] == g_selected_region)
        {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }

    char status[192];
    std::snprintf(status, sizeof(status),
                  "Captured %s for region 0x%016llX (%zu bytes) | %zu snapshot(s) in timeline",
                  snap.label.c_str(),
                  static_cast<unsigned long long>(reg.base + g_view_offset),
                  bytes_read, reg.snapshots.size());
    set_status(status);
    display_selected_region(static_cast<SIZE_T>(-1));
}

void on_clear_snapshots()
{
    if (!g_has_selection || g_selected_region >= g_regions.size())
        return;
    RegionInfo &reg = g_regions[g_selected_region];
    size_t count = reg.snapshots.size();
    reg.snapshots.clear();
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis)
    {
        if (g_visible_indices[vis] == g_selected_region)
        {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    display_selected_region(static_cast<SIZE_T>(-1));

    char status[128];
    std::snprintf(status, sizeof(status), "Cleared %zu snapshot(s) for current region.", count);
    set_status(status);
}

void display_selected_region(SIZE_T focus_offset)
{
    if (!g_has_selection || g_selected_region >= g_regions.size())
    {
        SetWindowTextA(g_lbl_hex_info, "Hex View: (no region selected)");
        SetWindowTextA(g_edit_hex, "");
        g_last_hex_info.clear();
        g_last_hex_dump.clear();
        EnableWindow(g_btn_prev_page, FALSE);
        EnableWindow(g_btn_next_page, FALSE);
        return;
    }

    const RegionInfo &reg = g_regions[g_selected_region];
    if (g_view_offset >= reg.size)
    {
        g_view_offset = 0;
    }

    SIZE_T remaining = reg.size - g_view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    EnableWindow(g_btn_prev_page, g_view_offset > 0 ? TRUE : FALSE);
    EnableWindow(g_btn_next_page, (g_view_offset + to_read < reg.size) ? TRUE : FALSE);

    DiffPair dp = get_active_diff_pair();
    std::vector<uint8_t> buf;
    SIZE_T bytes_read = 0;
    BOOL ok = TRUE;
    DWORD read_err = 0;

    if (dp.active && dp.cmp_data != nullptr)
    {
        buf = *dp.cmp_data;
        bytes_read = buf.size();
    }
    else
    {
        auto src = get_active_source();
        if (src == nullptr)
        {
            std::string msg = "[ERROR] No memory source available\r\n";
            SetWindowTextA(g_edit_hex, msg.c_str());
            g_last_hex_dump = msg;
            return;
        }

        buf.resize(to_read);
        bytes_read = src->read(reg.base + g_view_offset, to_read, buf.data());

        if (bytes_read == 0)
        {
            std::string msg = "[WARN] Memory unreadable at 0x" + fmt_addr(reg.base + g_view_offset) + "\r\n";
            SetWindowTextA(g_edit_hex, msg.c_str());
            g_last_hex_dump = msg;
            return;
        }
        buf.resize(bytes_read);
    }

    const uint8_t *ref_ptr = nullptr;
    size_t ref_len = 0;
    bool offset_mismatch = false;
    uintptr_t display_addr = reg.base + g_view_offset;
    SIZE_T display_view_offset = g_view_offset;

    if (dp.active)
    {
        if (dp.cmp_data != nullptr)
        {
            display_view_offset = dp.cmp_view_offset;
            display_addr = reg.base + display_view_offset;
            if (dp.ref_view_offset != dp.cmp_view_offset)
            {
                offset_mismatch = true;
            }
            else
            {
                ref_ptr = dp.ref_data->data();
                ref_len = dp.ref_data->size();
            }
        }
        else
        {
            if (dp.ref_view_offset == g_view_offset)
            {
                ref_ptr = dp.ref_data->data();
                ref_len = dp.ref_data->size();
            }
            else
            {
                offset_mismatch = true;
            }
        }
    }

    int focus_line = -1;
    size_t chg_bytes = 0, new_bytes = 0, zeroed_bytes = 0;
    std::string dump = build_hex_dump(buf.data(), bytes_read, display_addr,
                                      reg.hits, display_view_offset, g_active_pattern.bytes.size(),
                                      focus_offset, focus_line,
                                      ref_ptr, ref_len, dp.active && !offset_mismatch,
                                      chg_bytes, new_bytes, zeroed_bytes);

    if (offset_mismatch)
    {
        char warn_note[256];
        if (dp.cmp_data != nullptr)
        {
            std::snprintf(warn_note, sizeof(warn_note),
                          "[Note: Snapshots belong to different page offsets (0x%llX vs 0x%llX). Cannot diff across different offsets.]\r\n\r\n",
                          static_cast<unsigned long long>(dp.ref_view_offset),
                          static_cast<unsigned long long>(dp.cmp_view_offset));
        }
        else
        {
            std::snprintf(warn_note, sizeof(warn_note),
                          "[Note: Selected snapshot belongs to offset 0x%llX; current page is 0x%llX. Navigate back or take a new snapshot.]\r\n\r\n",
                          static_cast<unsigned long long>(dp.ref_view_offset),
                          static_cast<unsigned long long>(g_view_offset));
        }
        dump = warn_note + dump;
        if (focus_line >= 0)
            focus_line += 2;
    }

    if (!ok)
    {
        dump = "[WARN] Partial read (" + std::to_string(bytes_read) + "/" + std::to_string(to_read) +
               " bytes): " + format_win32_error(read_err) + "\r\n\r\n" + dump;
        if (focus_line >= 0)
            focus_line += 2;
    }

    char info[360];
    std::string det_tag;
    if (reg.is_pe_in_private)
        det_tag = " [! INJECTED PE]";
    else if (reg.private_rwx)
        det_tag = " [! RWX]";
    else if (reg.is_unbacked_exec)
        det_tag = " [! UNBACKED EXEC]";

    if (dp.active && !offset_mismatch)
    {
        std::snprintf(info, sizeof(info),
                      "Reg %zu/%zu | Base 0x%016llX | AllocBase 0x%016llX | %s | %s%s | Diff [%s]: %zu chg (%zu new, %zu wiped)",
                      g_selected_region + 1, g_regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      static_cast<unsigned long long>(reg.alloc_base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      det_tag.c_str(),
                      dp.title.c_str(), chg_bytes, new_bytes, zeroed_bytes);
    }
    else
    {
        std::snprintf(info, sizeof(info),
                      "Reg %zu/%zu | Base 0x%016llX | AllocBase 0x%016llX | %s | %s%s | Showing 0x%llX..0x%llX of 0x%llX",
                      g_selected_region + 1, g_regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      static_cast<unsigned long long>(reg.alloc_base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      det_tag.c_str(),
                      static_cast<unsigned long long>(display_view_offset),
                      static_cast<unsigned long long>(display_view_offset + to_read),
                      static_cast<unsigned long long>(reg.size));
    }

    if (g_last_hex_info != info)
    {
        SetWindowTextA(g_lbl_hex_info, info);
        g_last_hex_info = info;
    }

    if (g_last_hex_dump != dump)
    {
        int first_line = static_cast<int>(SendMessageA(g_edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(g_edit_hex, WM_SETREDRAW, FALSE, 0);
        SetWindowTextA(g_edit_hex, dump.c_str());
        if (focus_line > 3)
        {
            SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(focus_line - 3));
        }
        else if (first_line > 0)
        {
            SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(first_line));
        }
        else
        {
            SendMessageA(g_edit_hex, EM_SETSEL, 0, 0);
            SendMessageA(g_edit_hex, EM_SCROLLCARET, 0, 0);
        }
        SendMessageA(g_edit_hex, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_edit_hex, nullptr, TRUE);
        g_last_hex_dump = dump;
    }
    else if (focus_line > 3)
    {
        int cur = static_cast<int>(SendMessageA(g_edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(g_edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>((focus_line - 3) - cur));
    }
}

void update_triage_details_label(size_t reg_idx)
{
    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (reg_idx < g_process_diffs.size())
        {
            const auto &d = g_process_diffs[reg_idx];
            std::string kind_str = (d.kind == ProcessDiffKind::Appeared) ? "NEW" :
                                   (d.kind == ProcessDiffKind::Disappeared) ? "REMOVED" :
                                   (d.kind == ProcessDiffKind::ProtectionChg) ? "PROT_CHG" : "MODIFIED";
            std::string text = "Diff Details [" + kind_str + "]: 0x" + to_hex_string(d.base) + " (" + fmt_size_short(d.size) + ") | " + d.summary;
            SetWindowTextA(g_lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(g_lbl_triage_reasons, "Diff Details: Ready.");
        }
        return;
    }

    if (g_view_mode == ViewMode::BehaviorTracker)
    {
        if (reg_idx < g_watched_regions.size())
        {
            const auto &w = g_watched_regions[reg_idx];
            std::string text = "Behavior [Score " + std::to_string(w.behavior_score) + "]: " +
                               (w.evidence_summary.empty() ? "Monitoring region. Samples collected: " + std::to_string(w.ring_samples.size()) : w.evidence_summary);
            SetWindowTextA(g_lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(g_lbl_triage_reasons, "Behavior Details: Ready. Press Ctrl+P to pin selected region.");
        }
        return;
    }

    if (g_view_mode == ViewMode::StringsView)
    {
        if (reg_idx < g_extracted_strings.size())
        {
            const auto &st = g_extracted_strings[reg_idx];
            std::string text = "String at 0x" + to_hex_string(st.addr) + " [" + st.encoding + ", len " +
                               std::to_string(st.length) + "] " +
                               (st.is_new ? "[NEW SINCE BASELINE] " : "") + st.tag_hint + ": " + st.text;
            SetWindowTextA(g_lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(g_lbl_triage_reasons, "Strings Details: Ready. F7 to extract, Ctrl+B to set baseline.");
        }
        return;
    }

    if (reg_idx >= g_regions.size())
    {
        SetWindowTextA(g_lbl_triage_reasons, "Details: Ready.");
        return;
    }
    const RegionInfo &reg = g_regions[reg_idx];

    const TriageFinding *match = nullptr;
    for (const auto &f : g_triage_report.findings)
    {
        if (f.region_index == reg_idx)
        {
            match = &f;
            break;
        }
    }

    bool synthetic = (g_current_source != nullptr && g_current_source->capabilities().protection_is_synthetic);

    std::string text;
    if (match != nullptr && !match->reasons.empty())
    {
        text = "Details [" + match->severity_label + " " + std::to_string(match->severity_score) + "]: ";
        for (size_t i = 0; i < match->reasons.size(); ++i)
        {
            text += match->reasons[i];
            if (i + 1 < match->reasons.size())
                text += " | ";
        }
        if (synthetic)
        {
            text = "[Synthetic Protection] " + text;
        }
    }
    else
    {
        text = "Details [CLEAN 0]: Normal " + type_full(reg.type) + " memory (" +
               prot_full(reg.protect) + "), AllocBase " + to_hex_string(reg.alloc_base);
        if (synthetic)
        {
            text = "[Synthetic Protection] " + text;
        }
    }

    // Append per-region average, max, and compact ASCII profile of page entropies
    if (reg.avg_entropy >= 0.0)
    {
        char ent_buf[160];
        std::snprintf(ent_buf, sizeof(ent_buf), " | Entropy: avg %.2f, max %.2f [%s]%s",
                      reg.avg_entropy, reg.max_entropy, reg.entropy_ascii_profile.c_str(),
                      reg.entropy_sampled ? " (sampled)" : "");
        text += ent_buf;
    }

    SetWindowTextA(g_lbl_triage_reasons, text.c_str());
}

void populate_region_list()
{
    SendMessageA(g_list_regions, WM_SETREDRAW, FALSE, 0);
    SendMessageA(g_list_regions, LB_RESETCONTENT, 0, 0);
    g_visible_indices.clear();

    bool hits_only = (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);

    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (g_process_diffs.empty())
        {
            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No process diffs. Capture baseline (Ctrl+B), then diff (Ctrl+D)."));
        }
        else
        {
            for (size_t i = 0; i < g_process_diffs.size(); ++i)
            {
                const auto &d = g_process_diffs[i];
                std::string badge;
                switch (d.kind)
                {
                    case ProcessDiffKind::Appeared: badge = "[+NEW   ]"; break;
                    case ProcessDiffKind::Disappeared: badge = "[-FREED ]"; break;
                    case ProcessDiffKind::ProtectionChg: badge = "[!PROT  ]"; break;
                    case ProcessDiffKind::ContentChg: badge = "[~MODIF ]"; break;
                    default: badge = "[ UNCHG ]"; break;
                }

                char row[256];
                std::snprintf(row, sizeof(row), "%-9s %016llX %s %-4s %-8s %s",
                              badge.c_str(),
                              static_cast<unsigned long long>(d.base),
                              fmt_size_short(d.size).c_str(),
                              type_short(d.type).c_str(),
                              prot_short(d.new_protect ? d.new_protect : d.old_protect).c_str(),
                              d.summary.c_str());

                SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                g_visible_indices.push_back(i);
            }
        }
        SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_list_regions, nullptr, TRUE);
        return;
    }

    if (g_view_mode == ViewMode::BehaviorTracker)
    {
        if (g_watched_regions.empty())
        {
            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No watched regions. Attach live process & triage, or press Ctrl+P to pin selected region."));
        }
        else
        {
            for (size_t i = 0; i < g_watched_regions.size(); ++i)
            {
                const auto &w = g_watched_regions[i];
                char sev_badge[32];
                std::snprintf(sev_badge, sizeof(sev_badge), "[SCR %3d]", w.behavior_score);

                std::string flg_str;
                for (const auto &flg : w.behavior_flags)
                {
                    if (flg == "SLEEP_MASK_SUSPECT") flg_str += "!SMSP ";
                    else if (flg == "KEY_ROTATION_SUSPECT") flg_str += "!KROT ";
                    else if (flg == "DECRYPT_ON_WAKE") flg_str += "!DWAK ";
                }
                if (flg_str.empty()) flg_str = "      ";
                while (flg_str.size() < 14) flg_str.push_back(' ');

                char hbuf[32];
                if (w.ring_samples.empty())
                {
                    std::strcpy(hbuf, "H:--/--");
                }
                else
                {
                    double min_e = 10.0, max_e = -1.0;
                    for (const auto &s : w.ring_samples)
                    {
                        if (!s.is_unreadable)
                        {
                            if (s.avg_entropy < min_e) min_e = s.avg_entropy;
                            if (s.avg_entropy > max_e) max_e = s.avg_entropy;
                        }
                    }
                    if (max_e >= 0.0)
                        std::snprintf(hbuf, sizeof(hbuf), "H:%.1f-%.1f", min_e, max_e);
                    else
                        std::strcpy(hbuf, "H:unreadable");
                }

                double last_chg = 0.0;
                if (!w.ring_samples.empty()) last_chg = w.ring_samples.back().changed_fraction * 100.0;
                DWORD last_prot = w.ring_samples.empty() ? w.alloc_protect : w.ring_samples.back().protect;

                char row[256];
                std::snprintf(row, sizeof(row), "%-11s %-14s %016llX %4zus %-11s %2dc %3.0f%% %-4s %s",
                              sev_badge, flg_str.c_str(),
                              static_cast<unsigned long long>(w.key.base),
                              w.ring_samples.size(),
                              hbuf,
                              w.sleep_evidence.cycles,
                              last_chg,
                              prot_short(last_prot).c_str(),
                              w.is_pinned ? "[PIN]" : "");

                SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                g_visible_indices.push_back(i);
            }
        }
        SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_list_regions, nullptr, TRUE);
        return;
    }

    if (g_view_mode == ViewMode::StringsView)
    {
        if (g_extracted_strings.empty())
        {
            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No strings extracted. Press F7 to extract selected region, or use Strings -> Extract All."));
        }
        else
        {
            char pat_buf[256] = {};
            GetWindowTextA(g_edit_pattern, pat_buf, sizeof(pat_buf));
            std::string q_str(pat_buf);
            for (char &c : q_str) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            for (size_t i = 0; i < g_extracted_strings.size(); ++i)
            {
                const auto &st = g_extracted_strings[i];
                if (g_strings_filter_new_only && !st.is_new)
                    continue;

                if (!q_str.empty())
                {
                    std::string text_lower = st.text;
                    for (char &c : text_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (text_lower.find(q_str) == std::string::npos)
                        continue;
                }

                char row[512];
                std::snprintf(row, sizeof(row), "%016llX %-8s %-4zu %-14s %-6s %s",
                              static_cast<unsigned long long>(st.addr),
                              st.encoding.c_str(),
                              st.length,
                              st.tag_hint.c_str(),
                              st.is_new ? "[NEW]" : "     ",
                              st.text.c_str());

                SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                g_visible_indices.push_back(i);
            }
        }
        SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_list_regions, nullptr, TRUE);
        return;
    }

    if (g_view_mode == ViewMode::TriageFindings)
    {
        for (size_t i = 0; i < g_triage_report.findings.size(); ++i)
        {
            const TriageFinding &f = g_triage_report.findings[i];
            if (f.region_index >= g_regions.size())
                continue;
            const RegionInfo &r = g_regions[f.region_index];

            if (f.severity_score < g_min_sev_filter)
                continue;
            if (g_hide_clean && f.severity_score == 0)
                continue;
            if (hits_only && r.hits.empty())
                continue;

            char sev_badge[32];
            std::snprintf(sev_badge, sizeof(sev_badge), "[%-4s %3d]", f.severity_label.c_str(), f.severity_score);

            std::string flg_str;
            for (const auto &flg : f.flags)
            {
                if (flg == "INJECTED_PE")
                    flg_str += "!PE ";
                else if (flg == "UNLINKED_MODULE")
                    flg_str += "!UNL ";
                else if (flg == "PRIVATE_RWX")
                    flg_str += "!RWX ";
                else if (flg == "WRITE_THEN_FLIP")
                    flg_str += "!FLIP ";
                else if (flg == "UNBACKED_EXEC")
                    flg_str += "!X ";
                else if (flg == "BEHAVIOR_UNPACK")
                    flg_str += "!UNPK ";
                else if (flg == "SLEEP_OBFUSCATION")
                    flg_str += "!SLP ";
                else if (flg == "STATIC_WX_SECTION")
                    flg_str += "!W+X ";
                else if (flg == "STATIC_EP_OUTSIDE_EXEC")
                    flg_str += "!EP ";
                else if (flg == "STATIC_EXEC_HIGH_ENTROPY")
                    flg_str += "!ENT ";
                else if (flg == "STATIC_NONTRIVIAL_OVERLAY")
                    flg_str += "!OVL ";
                else if (flg == "HIGH_ENTROPY_EXEC")
                    flg_str += "!HENT ";
                else if (flg == "HIGH_ENTROPY_PRIVATE")
                    flg_str += "!HPVT ";
                else if (flg == "SLEEP_MASK_SUSPECT")
                    flg_str += "!SMSP ";
                else if (flg == "KEY_ROTATION_SUSPECT")
                    flg_str += "!KROT ";
                else if (flg == "DECRYPT_ON_WAKE")
                    flg_str += "!DWAK ";
            }
            if (flg_str.empty())
                flg_str = "      ";
            while (flg_str.size() < 14)
                flg_str.push_back(' ');

            std::string tag;
            if (!r.hits.empty())
            {
                tag += " [" + std::to_string(r.hits.size()) + "h]";
            }
            if (!r.snapshots.empty())
            {
                tag += " (" + std::to_string(r.snapshots.size()) + "s)";
            }

            char row[256];
            std::snprintf(row, sizeof(row), "%-11s %-14s %016llX %s %-4s %-4s%s",
                          sev_badge, flg_str.c_str(),
                          static_cast<unsigned long long>(f.base),
                          fmt_size_short(f.size).c_str(),
                          type_short(f.type).c_str(),
                          prot_short(f.protect).c_str(),
                          tag.c_str());

            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
            g_visible_indices.push_back(f.region_index);
        }
    }
    else
    {
        // ViewMode::MemoryMap
        for (size_t i = 0; i < g_regions.size(); ++i)
        {
            const RegionInfo &r = g_regions[i];
            if (hits_only && r.hits.empty())
                continue;

            // Find severity for filtering in map mode
            int sev = 0;
            for (const auto &f : g_triage_report.findings)
            {
                if (f.region_index == i)
                {
                    sev = f.severity_score;
                    break;
                }
            }

            if (sev < g_min_sev_filter)
                continue;
            if (g_hide_clean && sev == 0)
                continue;

            char row[256];
            std::string tag;
            if (!r.hits.empty())
            {
                char hbuf[48];
                if (r.hits_truncated)
                {
                    std::snprintf(hbuf, sizeof(hbuf), " [%zu+ hits (capped)]", r.hits.size());
                }
                else
                {
                    std::snprintf(hbuf, sizeof(hbuf), " [%zu hit%s]", r.hits.size(), r.hits.size() == 1 ? "" : "s");
                }
                tag += hbuf;
            }
            if (!r.snapshots.empty())
            {
                char sbuf[32];
                std::snprintf(sbuf, sizeof(sbuf), " (%zu snap%s)", r.snapshots.size(), r.snapshots.size() == 1 ? "" : "s");
                tag += sbuf;
            }

            std::string flag = "    ";
            if (r.is_pe_in_private)
                flag = "!PE ";
            else if (r.private_rwx)
                flag = "!RWX";
            else if (r.write_then_flip)
                flag = "!FLP";
            else if (r.is_unlinked_image)
                flag = "!UNL";
            else if (r.is_unbacked_exec)
                flag = "!X  ";

            if (!r.section_name.empty())
            {
                tag = " [" + r.section_name + "]" + tag;
            }

            if (r.avg_entropy >= 0.0)
            {
                char hbuf[32];
                std::snprintf(hbuf, sizeof(hbuf), " H:%.1f/%.1f", r.avg_entropy, r.max_entropy);
                tag += hbuf;
            }

            std::snprintf(row, sizeof(row), "%016llX %s %s %s %s%s",
                          static_cast<unsigned long long>(r.base),
                          fmt_size_short(r.size).c_str(),
                          type_short(r.type).c_str(),
                          prot_short(r.protect).c_str(),
                          flag.c_str(),
                          tag.c_str());

            SendMessageA(g_list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
            g_visible_indices.push_back(i);
        }
    }

    SendMessageA(g_list_regions, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list_regions, nullptr, TRUE);
}

void select_region_in_ui(size_t region_idx, SIZE_T view_offset, SIZE_T focus_offset)
{
    if (region_idx >= g_regions.size())
        return;
    g_selected_region = region_idx;
    g_has_selection = true;
    g_view_offset = view_offset;

    for (size_t vis = 0; vis < g_visible_indices.size(); ++vis)
    {
        if (g_visible_indices[vis] == region_idx)
        {
            SendMessageA(g_list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    update_diff_combo();
    invalidate_hex_cache();
    display_selected_region(focus_offset);
    update_triage_details_label(region_idx);
}

// Visual Triage List Item Drawing Handler
void draw_region_list_item(DRAWITEMSTRUCT *dis)
{
    if (dis->itemID == static_cast<UINT>(-1))
        return;

    const ThemeColors &tc = get_current_theme();
    size_t vis_idx = static_cast<size_t>(dis->itemID);

    if (g_visible_indices.empty() || vis_idx >= g_visible_indices.size())
    {
        HDC hdc = dis->hDC;
        HBRUSH hbr = CreateSolidBrush(tc.bg_control);
        FillRect(hdc, &dis->rcItem, hbr);
        DeleteObject(hbr);

        char buf[256] = {};
        SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(buf));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, tc.text_muted);
        HGDIOBJ old_font = SelectObject(hdc, g_mono_font);
        RECT text_rc = dis->rcItem;
        text_rc.left += 6;
        DrawTextA(hdc, buf, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, old_font);
        return;
    }

    size_t reg_idx = g_visible_indices[vis_idx];

    bool is_selected = (dis->itemState & ODS_SELECTED) != 0;

    COLORREF bg_color = tc.row_image_bg;
    COLORREF text_color = tc.row_image_text;

    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (reg_idx < g_process_diffs.size())
        {
            const auto &d = g_process_diffs[reg_idx];
            switch (d.kind)
            {
                case ProcessDiffKind::Appeared:
                    bg_color = tc.row_diff_new_bg;
                    text_color = tc.row_diff_new_text;
                    break;
                case ProcessDiffKind::ProtectionChg:
                    bg_color = tc.row_diff_chg_bg;
                    text_color = tc.row_diff_chg_text;
                    break;
                case ProcessDiffKind::ContentChg:
                    bg_color = tc.row_diff_mod_bg;
                    text_color = tc.row_diff_mod_text;
                    break;
                case ProcessDiffKind::Disappeared:
                    bg_color = tc.row_diff_del_bg;
                    text_color = tc.row_diff_del_text;
                    break;
                default:
                    break;
            }
        }
    }
    else if (g_view_mode == ViewMode::BehaviorTracker)
    {
        if (reg_idx < g_watched_regions.size())
        {
            const auto &w = g_watched_regions[reg_idx];
            if (w.behavior_score >= SEV_MIN_CRITICAL)
            {
                bg_color = tc.row_pe_bg;
                text_color = tc.row_pe_text;
            }
            else if (w.behavior_score >= SEV_MIN_HIGH)
            {
                bg_color = tc.row_rwx_bg;
                text_color = tc.row_rwx_text;
            }
            else if (w.behavior_score >= SEV_MIN_MEDIUM)
            {
                bg_color = tc.row_flip_bg;
                text_color = tc.row_flip_text;
            }
            else
            {
                bg_color = tc.row_priv_bg;
                text_color = tc.row_priv_text;
            }
        }
    }
    else if (g_view_mode == ViewMode::StringsView)
    {
        if (reg_idx < g_extracted_strings.size())
        {
            const auto &st = g_extracted_strings[reg_idx];
            if (st.is_new)
            {
                bg_color = tc.row_diff_new_bg;
                text_color = tc.row_diff_new_text;
            }
            else
            {
                bg_color = tc.row_priv_bg;
                text_color = tc.row_priv_text;
            }
        }
    }
    else
    {
        if (reg_idx >= g_regions.size())
            return;
        const RegionInfo &reg = g_regions[reg_idx];

        // Apply highlight colors based on region threat indicators
        if (reg.is_pe_in_private)
        {
            bg_color = tc.row_pe_bg;
            text_color = tc.row_pe_text;
        }
        else if (reg.private_rwx)
        {
            bg_color = tc.row_rwx_bg;
            text_color = tc.row_rwx_text;
        }
        else if (reg.write_then_flip)
        {
            bg_color = tc.row_flip_bg;
            text_color = tc.row_flip_text;
        }
        else if (reg.is_unlinked_image)
        {
            bg_color = tc.row_unlinked_bg;
            text_color = tc.row_unlinked_text;
        }
        else if (reg.is_unbacked_exec)
        {
            bg_color = tc.row_unbacked_bg;
            text_color = tc.row_unbacked_text;
        }
        else if (reg.type == MEM_PRIVATE)
        {
            bg_color = tc.row_priv_bg;
            text_color = tc.row_priv_text;
        }
        else if (reg.type == MEM_MAPPED)
        {
            bg_color = tc.row_mapped_bg;
            text_color = tc.row_mapped_text;
        }
    }

    if (is_selected)
    {
        bg_color = tc.row_sel_bg;
        text_color = tc.row_sel_text;
    }

    HDC hdc = dis->hDC;
    HBRUSH hbr = CreateSolidBrush(bg_color);
    FillRect(hdc, &dis->rcItem, hbr);
    DeleteObject(hbr);

    char buf[512] = {};
    SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(buf));

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text_color);
    HGDIOBJ old_font = SelectObject(hdc, g_mono_font);

    RECT text_rc = dis->rcItem;
    text_rc.left += 6; // Left margin padding
    DrawTextA(hdc, buf, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, old_font);
}

enum class WorkerTaskType
{
    MemoryMapScan = 0,
    Triage = 1,
    BehaviorTick = 2
};

struct WorkerTask
{
    HWND hwnd;
    DWORD pid;
    std::string pid_label;
    Pattern pat;
    bool use_pattern;
    WorkerTaskType task_type;
    std::shared_ptr<MemorySource> source;
};

struct WorkerResult
{
    WorkerTaskType task_type;
    DWORD pid;
    std::string pid_label;
    Pattern pat;
    bool use_pattern;
    std::shared_ptr<MemorySource> source;
    bool success;
    DWORD error_code;
    std::string error_msg;
    std::vector<RegionInfo> regions;
    TriageReport report;
    SIZE_T total_bytes;
    SIZE_T total_hits;
    size_t regions_with_hits;
};

static HANDLE g_h_worker_thread = nullptr;
static std::atomic<bool> g_scan_abort{false};

DWORD WINAPI WorkerThreadProc(LPVOID param)
{
    WorkerTask *task = reinterpret_cast<WorkerTask *>(param);
    WorkerResult *res = new WorkerResult();
    res->task_type = task->task_type;
    res->pid = task->pid;
    res->pid_label = task->pid_label;
    res->pat = task->pat;
    res->use_pattern = task->use_pattern;
    res->source = task->source;
    res->success = false;
    res->error_code = 0;
    res->total_bytes = 0;
    res->total_hits = 0;
    res->regions_with_hits = 0;

    HWND hwnd = task->hwnd;
    std::shared_ptr<MemorySource> source = task->source;
    delete task;

    if (!source && res->pid != 0)
    {
        source = std::make_shared<LiveProcessSource>(res->pid, res->pid_label);
        res->source = source;
    }

    if (!source)
    {
        res->error_msg = "No memory source available.";
        if (!PostMessageA(hwnd, (res->task_type == WorkerTaskType::Triage) ? WM_TRIAGE_COMPLETE : WM_SCAN_COMPLETE,
                          FALSE, reinterpret_cast<LPARAM>(res)))
        {
            delete res;
        }
        return 0;
    }

    if (source->capabilities().is_live)
    {
        auto live_src = std::dynamic_pointer_cast<LiveProcessSource>(source);
        if (live_src && live_src->get_raw_handle() == nullptr)
        {
            res->error_code = GetLastError();
            res->error_msg = format_win32_error(res->error_code);
            if (!PostMessageA(hwnd, (res->task_type == WorkerTaskType::Triage) ? WM_TRIAGE_COMPLETE : WM_SCAN_COMPLETE,
                              FALSE, reinterpret_cast<LPARAM>(res)))
            {
                delete res;
            }
            return 0;
        }
    }

    if (res->task_type == WorkerTaskType::BehaviorTick)
    {
        BehaviorTrackerContext ctx;
        ctx.proc = get_or_open_target_proc(source->get_pid());
        ctx.watched_regions = &g_watched_regions;
        ctx.region_generations = &g_region_generations;
        ctx.regions = &g_regions;
        ctx.triage_report = &g_triage_report;
        ctx.string_baselines = &g_string_baselines;
        ctx.watch_all_priv_exec = g_tracker_watch_all_priv_exec.load();
        ctx.rotating_idx = &g_tracker_rotating_idx;
        ctx.total_samples = &g_tracker_total_samples;
        ctx.partial_samples = &g_tracker_partial_samples;
        ctx.target_process_exited = &g_target_process_exited;

        run_behavior_tracker_tick(source, ctx);
        g_tracker_busy.store(false);
        PostMessageA(hwnd, WM_BEHAVIOR_TICK_DONE, 0, 0);
        delete res;
        return 0;
    }

    if (res->task_type == WorkerTaskType::Triage)
    {
        std::string err;
        if (!source->query_regions(res->regions, err))
        {
            res->error_code = GetLastError();
            res->error_msg = err.empty() ? format_win32_error(res->error_code) : err;
            if (!PostMessageA(hwnd, WM_TRIAGE_COMPLETE, FALSE, reinterpret_cast<LPARAM>(res)))
            {
                delete res;
            }
            return 0;
        }

        auto triage_cb = [](SIZE_T cur, SIZE_T tot, void *u)
        {
            HWND h = reinterpret_cast<HWND>(u);
            PostMessageA(h, WM_SCAN_PROGRESS, cur, tot);
        };

        res->report = run_source_triage(source, res->regions, &g_scan_abort, triage_cb, hwnd);

        if (g_scan_abort.load(std::memory_order_relaxed))
        {
            delete res;
            return 0;
        }

        res->success = true;
        if (!PostMessageA(hwnd, WM_TRIAGE_COMPLETE, TRUE, reinterpret_cast<LPARAM>(res)))
        {
            delete res;
        }
        return 0;
    }

    // MemoryMapScan (Load / Search)
    std::string q_err;
    std::vector<RegionInfo> query_regs;
    if (!source->query_regions(query_regs, q_err))
    {
        res->error_code = GetLastError();
        res->error_msg = q_err.empty() ? format_win32_error(res->error_code) : q_err;
        if (!PostMessageA(hwnd, WM_SCAN_COMPLETE, FALSE, reinterpret_cast<LPARAM>(res)))
        {
            delete res;
        }
        return 0;
    }

    std::vector<uint8_t> chunk_buf(CLI_CHUNK_SIZE);
    std::vector<SIZE_T> chunk_hits;
    SIZE_T last_progress_bytes = 0;

    for (size_t r_i = 0; r_i < query_regs.size() && !g_scan_abort.load(std::memory_order_relaxed); ++r_i)
    {
        RegionInfo reg = query_regs[r_i];
        uintptr_t region_base = reg.base;
        SIZE_T region_size = reg.size;

        SIZE_T offset = 0;
        SIZE_T overlap = (res->use_pattern && !res->pat.bytes.empty()) ? (res->pat.bytes.size() - 1) : 0;
        SIZE_T prev_overlap = 0;
        bool pe_found = false;

        while (offset < region_size && !g_scan_abort.load(std::memory_order_relaxed))
        {
            SIZE_T rem = region_size - offset;
            SIZE_T to_read = (rem < CLI_CHUNK_SIZE) ? rem : CLI_CHUNK_SIZE;
            chunk_hits.clear();

            bool truncated = false;
            SIZE_T bytes_read = scan_chunk_robust(source.get(), region_base + offset, to_read,
                                                  res->use_pattern ? &res->pat : nullptr,
                                                  chunk_buf, offset, chunk_hits,
                                                  MAX_HITS_PER_REGION - reg.hits.size(),
                                                  truncated, pe_found);

            if (truncated)
            {
                reg.hits_truncated = true;
            }

            if (reg.type == MEM_PRIVATE && pe_found)
            {
                reg.is_pe_in_private = true;
            }

            if (bytes_read > prev_overlap)
            {
                res->total_bytes += (bytes_read - prev_overlap);
            }

            for (SIZE_T h : chunk_hits)
            {
                if (reg.hits.size() < MAX_HITS_PER_REGION)
                {
                    reg.hits.push_back(h);
                }
                else
                {
                    reg.hits_truncated = true;
                    break;
                }
            }

            if (offset + to_read >= region_size)
                break;
            if (bytes_read <= overlap)
            {
                offset += to_read;
                prev_overlap = 0;
            }
            else
            {
                offset += (bytes_read - overlap);
                prev_overlap = overlap;
            }
        }

        if (!reg.hits.empty())
        {
            res->total_hits += reg.hits.size();
            res->regions_with_hits += 1;
        }

        res->regions.push_back(std::move(reg));

        if (res->total_bytes - last_progress_bytes >= 8 * 1024 * 1024)
        {
            last_progress_bytes = res->total_bytes;
            PostMessageA(hwnd, WM_SCAN_PROGRESS,
                         static_cast<WPARAM>(res->total_bytes / (1024 * 1024)),
                         static_cast<LPARAM>(res->total_hits));
        }
    }

    if (!g_scan_abort.load(std::memory_order_relaxed))
    {
        res->report = run_source_triage(source, res->regions, &g_scan_abort, nullptr, nullptr);
    }

    if (g_scan_abort.load(std::memory_order_relaxed))
    {
        delete res;
        return 0;
    }

    res->success = true;
    if (!PostMessageA(hwnd, WM_SCAN_COMPLETE, TRUE, reinterpret_cast<LPARAM>(res)))
    {
        delete res;
    }
    return 0;
}

void enable_ui_controls(BOOL enable)
{
    EnableWindow(g_btn_attach, enable);
    EnableWindow(g_btn_load, enable);
    EnableWindow(g_btn_triage, enable);
    EnableWindow(g_btn_search, enable);
    EnableWindow(g_edit_pid, enable);
    EnableWindow(g_edit_pattern, enable);
}

void on_worker_completed(WorkerResult *res)
{
    if (g_h_worker_thread != nullptr)
    {
        WaitForSingleObject(g_h_worker_thread, 100);
        CloseHandle(g_h_worker_thread);
        g_h_worker_thread = nullptr;
    }

    enable_ui_controls(TRUE);

    if (!res->success)
    {
        std::string msg = "Cannot open PID " + std::to_string(res->pid) + ": " + res->error_msg;
        if (res->error_code == ERROR_ACCESS_DENIED)
        {
            msg += "\n\nRun elevated or inspect a non-protected process.";
        }
        set_status("[ERROR] " + msg);
        MessageBoxA(g_hwnd_main, msg.c_str(), "Deadeye Scanner", MB_ICONERROR);
        return;
    }

    close_target_proc();
    invalidate_hex_cache();

    g_regions = std::move(res->regions);
    g_triage_report = std::move(res->report);
    g_current_pid = res->pid;
    g_current_pid_label = res->pid_label;
    if (res->source)
    {
        g_current_source = res->source;
    }
    g_active_pattern = res->pat;
    g_has_pattern = res->use_pattern;
    g_has_selection = false;
    g_view_offset = 0;

    EnableWindow(g_btn_next_hit, (g_has_pattern && res->total_hits > 0) ? TRUE : FALSE);

    if (res->task_type == WorkerTaskType::Triage)
    {
        g_view_mode = ViewMode::TriageFindings;
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);
    }

    if (g_current_source != nullptr && g_current_source->capabilities().is_live)
    {
        g_tracker_active.store(true);
        g_target_process_exited.store(false);

        // Build default watch set: regions with triage score >= 25 or high entropy, plus pinned or watch all priv
        for (const auto &reg : g_regions)
        {
            int sev = 0;
            for (const auto &f : g_triage_report.findings)
            {
                if (f.base == reg.base)
                {
                    sev = f.severity_score;
                    break;
                }
            }

            bool is_exec = (reg.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool high_ent = (reg.avg_entropy >= 7.0 || reg.max_entropy >= 7.2);
            bool watch_all_priv = g_tracker_watch_all_priv_exec.load() && (reg.type == MEM_PRIVATE && is_exec);

            if (sev >= 25 || high_ent || watch_all_priv)
            {
                bool exists = false;
                for (const auto &w : g_watched_regions)
                {
                    if (w.key.base == reg.base && w.key.alloc_base == reg.alloc_base)
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    WatchedRegionState nw;
                    nw.key.base = reg.base;
                    nw.key.alloc_base = reg.alloc_base;
                    nw.key.generation = g_region_generations[reg.base];
                    nw.size = reg.size;
                    nw.type = reg.type;
                    nw.alloc_protect = reg.alloc_protect;
                    nw.is_pinned = false;
                    g_watched_regions.push_back(std::move(nw));
                }
            }
        }
    }

    populate_region_list();

    // Select the first finding or region
    if (!g_visible_indices.empty())
    {
        select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
    }
    else
    {
        update_diff_combo();
        display_selected_region(static_cast<SIZE_T>(-1));
        SetWindowTextA(g_lbl_triage_reasons, "Details: Ready.");
    }

    // Calculate threat breakdown
    size_t crit = 0, high = 0, med = 0, low = 0;
    for (const auto &f : g_triage_report.findings)
    {
        if (f.severity_label == "CRIT")
            crit++;
        else if (f.severity_label == "HIGH")
            high++;
        else if (f.severity_label == "MED")
            med++;
        else if (f.severity_label == "LOW")
            low++;
    }

    double mb = static_cast<double>(res->total_bytes) / (1024.0 * 1024.0);
    char status[320];
    if (g_current_source != nullptr && !g_current_source->capabilities().is_live)
    {
        std::snprintf(status, sizeof(status),
                      "%s: %zu sections/regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW [Static PE Rules]",
                      g_current_source->describe().c_str(),
                      g_regions.size(), crit, high, med, low);
    }
    else if (res->task_type == WorkerTaskType::Triage)
    {
        std::snprintf(status, sizeof(status),
                      "Triage complete for PID %lu (%s): %zu regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW%s",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      g_regions.size(), crit, high, med, low,
                      res->report.wow64_unsupported ? " (WOW64: PEB unlinked check unsupported)" : "");
    }
    else if (g_has_pattern)
    {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): %zu regions, %.2f MB scanned | %zu hit(s) in %zu region(s) | Triage: %zu Suspicious",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      g_regions.size(), mb, res->total_hits, res->regions_with_hits,
                      crit + high + med);
    }
    else
    {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): Loaded %zu committed regions (%.2f MB) | Triage: %zu Suspicious (%zu CRIT, %zu HIGH)",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      g_regions.size(), mb, crit + high + med, crit, high);
    }
    set_status(status);
}

void start_worker_task(WorkerTaskType task_type, bool require_pattern)
{
    if (g_h_worker_thread != nullptr)
    {
        DWORD exit_code = 0;
        if (GetExitCodeThread(g_h_worker_thread, &exit_code) && exit_code == STILL_ACTIVE)
        {
            set_status("Operation already in progress. Please wait...");
            return;
        }
        CloseHandle(g_h_worker_thread);
        g_h_worker_thread = nullptr;
    }

    char pid_buf[64] = {};
    char pat_buf[512] = {};
    GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
    GetWindowTextA(g_edit_pattern, pat_buf, sizeof(pat_buf));

    std::string pid_str(pid_buf);
    std::string pat_str(pat_buf);

    DWORD pid = 0;
    std::shared_ptr<MemorySource> active_source = nullptr;
    if (parse_pid_string(pid_str, pid))
    {
        active_source = std::make_shared<LiveProcessSource>(pid);
        g_current_source = active_source;
        g_current_pid = pid;
        SetWindowTextA(g_hwnd_main, "Deadeye - Memory Triage Scanner & Hex Viewer");
        if (g_chk_heartbeat) EnableWindow(g_chk_heartbeat, TRUE);
    }
    else if (g_current_source != nullptr && !g_current_source->capabilities().is_live)
    {
        active_source = g_current_source;
    }
    else
    {
        MessageBoxA(g_hwnd_main, "Enter a valid numeric PID, or select File > Open Memory Source... to inspect a PE/binary file.", "Invalid Target", MB_ICONWARNING);
        return;
    }

    bool trim_empty = true;
    for (size_t i = 0; i < pat_str.size(); ++i)
    {
        if (!std::isspace(static_cast<unsigned char>(pat_str[i])))
        {
            trim_empty = false;
            break;
        }
    }

    if (require_pattern && trim_empty)
    {
        MessageBoxA(g_hwnd_main, "Enter a hex pattern to search (e.g. '4D 5A ?? 00'), or click 'Load' / 'Triage'.",
                    "Pattern Required", MB_ICONINFORMATION);
        return;
    }

    Pattern pat;
    bool use_pattern = !trim_empty && (task_type == WorkerTaskType::MemoryMapScan);
    if (use_pattern)
    {
        std::string err;
        if (!parse_pattern(pat_str, pat, err))
        {
            MessageBoxA(g_hwnd_main, err.c_str(), "Invalid Hex Pattern", MB_ICONWARNING);
            return;
        }
    }

    close_target_proc();
    invalidate_hex_cache();
    enable_ui_controls(FALSE);
    EnableWindow(g_btn_next_hit, FALSE);

    if (task_type == WorkerTaskType::Triage)
    {
        set_status("Triaging memory in background...");
    }
    else
    {
        set_status(use_pattern ? "Scanning memory in background..." : "Loading memory map in background...");
    }

    WorkerTask *task = new WorkerTask();
    task->hwnd = g_hwnd_main;
    task->pid = pid;
    task->pid_label = active_source ? active_source->describe() : ("PID " + std::to_string(pid));
    task->pat = pat;
    task->use_pattern = use_pattern;
    task->task_type = task_type;
    task->source = active_source;

    g_scan_abort.store(false, std::memory_order_relaxed);
    g_h_worker_thread = CreateThread(nullptr, 0, WorkerThreadProc, task, 0, nullptr);
    if (g_h_worker_thread == nullptr)
    {
        DWORD err = GetLastError();
        delete task;
        enable_ui_controls(TRUE);
        set_status("[ERROR] CreateThread failed: " + format_win32_error(err));
        MessageBoxA(g_hwnd_main, "Failed to launch background worker thread.", "Thread Error", MB_ICONERROR);
    }
}

void on_next_hit()
{
    if (!g_has_pattern || g_regions.empty())
        return;

    size_t total_hits = 0;
    for (size_t i = 0; i < g_regions.size(); ++i)
    {
        total_hits += g_regions[i].hits.size();
    }
    if (total_hits == 0)
        return;

    g_hit_cursor_index += 1;
    if (g_hit_cursor_region >= g_regions.size() ||
        g_hit_cursor_index >= g_regions[g_hit_cursor_region].hits.size())
    {
        g_hit_cursor_index = 0;
        size_t r = (g_hit_cursor_region + 1) % g_regions.size();
        while (g_regions[r].hits.empty())
        {
            r = (r + 1) % g_regions.size();
        }
        g_hit_cursor_region = r;
    }

    SIZE_T hit_off = g_regions[g_hit_cursor_region].hits[g_hit_cursor_index];
    SIZE_T page_off = (hit_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
    select_region_in_ui(g_hit_cursor_region, page_off, hit_off);

    char status[160];
    std::snprintf(status, sizeof(status),
                  "Hit at 0x%016llX (region %zu, hit %zu/%zu in region)",
                  static_cast<unsigned long long>(g_regions[g_hit_cursor_region].base + hit_off),
                  g_hit_cursor_region + 1,
                  g_hit_cursor_index + 1,
                  g_regions[g_hit_cursor_region].hits.size());
    set_status(status);
}

void on_export_json()
{
    if (g_triage_report.findings.empty() && g_regions.empty())
    {
        MessageBoxA(g_hwnd_main, "Please Load or Triage a target process before exporting findings.",
                    "No Data", MB_ICONINFORMATION);
        return;
    }

    if (g_triage_report.findings.empty())
    {
        auto src = get_active_source();
        if (src != nullptr)
        {
            g_triage_report = run_source_triage(src, g_regions);
        }
    }

    char filename_buf[MAX_PATH] = {};
    if (g_current_source != nullptr && !g_current_source->capabilities().is_live)
    {
        std::string fn = g_current_source->get_file_path();
        size_t last_slash = fn.find_last_of("\\/");
        std::string base_fn = (last_slash != std::string::npos) ? fn.substr(last_slash + 1) : fn;
        std::snprintf(filename_buf, sizeof(filename_buf), "deadeye_triage_%s.json", base_fn.c_str());
    }
    else
    {
        std::snprintf(filename_buf, sizeof(filename_buf), "deadeye_triage_pid_%lu.json",
                      static_cast<unsigned long>(g_current_pid));
    }

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename_buf;
    ofn.nMaxFile = sizeof(filename_buf);
    ofn.lpstrTitle = "Export Triage Report (JSON)";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "json";

    if (GetSaveFileNameA(&ofn))
    {
        std::string json_data = export_triage_json(g_triage_report);
        FILE *fp = std::fopen(filename_buf, "wb");
        if (fp != nullptr)
        {
            std::fwrite(json_data.data(), 1, json_data.size(), fp);
            std::fclose(fp);
            char status[320];
            std::snprintf(status, sizeof(status), "Exported %zu triage findings to %s",
                          g_triage_report.findings.size(), filename_buf);
            set_status(status);
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Failed to write JSON file to chosen location.",
                        "Export Error", MB_ICONERROR);
        }
    }
}

// ============================================================================
// Modern Flat / Fluent Button Rendering Engine
// ============================================================================

enum class ModernButtonStyle {
    Standard,
    Primary, // "Triage"
    Accent   // "Export JSON"
};

struct ModernButtonData {
    WNDPROC old_proc = nullptr;
    ModernButtonStyle style = ModernButtonStyle::Standard;
    bool is_hovered = false;
};

static const char* const DEADEYE_BTN_PROP = "DEADEYE_MODERN_BTN_DATA";

LRESULT CALLBACK ModernButtonSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    ModernButtonData* data = reinterpret_cast<ModernButtonData*>(GetPropA(hwnd, DEADEYE_BTN_PROP));
    if (data == nullptr) {
        return DefWindowProcA(hwnd, msg, wp, lp);
    }

    switch (msg) {
    case WM_MOUSEMOVE: {
        if (!data->is_hovered) {
            data->is_hovered = true;
            TRACKMOUSEEVENT tme = {};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hwnd;
            TrackMouseEvent(&tme);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        break;
    }

    case WM_MOUSELEAVE: {
        data->is_hovered = false;
        InvalidateRect(hwnd, nullptr, FALSE);
        break;
    }

    case WM_SETCURSOR: {
        if (IsWindowEnabled(hwnd)) {
            SetCursor(LoadCursorA(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    }

    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_CAPTURECHANGED:
    case WM_ENABLE:
    case WM_SETFOCUS:
    case WM_KILLFOCUS: {
        InvalidateRect(hwnd, nullptr, FALSE);
        break;
    }

    case WM_NCDESTROY: {
        WNDPROC old_proc = data->old_proc;
        RemovePropA(hwnd, DEADEYE_BTN_PROP);
        delete data;
        return CallWindowProcA(old_proc, hwnd, msg, wp, lp);
    }

    case WM_ERASEBKGND:
        return 1; // Handled in double-buffered WM_PAINT

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w <= 0 || h <= 0) {
            EndPaint(hwnd, &ps);
            return 0;
        }

        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, w, h);
        HGDIOBJ oldBmp = SelectObject(memDC, memBmp);

        // Pre-fill corners with parent window background color
        const ThemeColors& tc = get_current_theme();
        HBRUSH brParent = CreateSolidBrush(tc.bg_window);
        FillRect(memDC, &rc, brParent);
        DeleteObject(brParent);

        bool is_enabled = (IsWindowEnabled(hwnd) != FALSE);
        bool is_pressed = ((SendMessageA(hwnd, BM_GETSTATE, 0, 0) & BST_PUSHED) != 0);
        bool is_hovered = (data->is_hovered && is_enabled);
        bool is_focused = (GetFocus() == hwnd && is_enabled);
        bool is_dark    = (g_theme == AppTheme::Dark);

        COLORREF bg_color, border_color, text_color;

        if (data->style == ModernButtonStyle::Primary) {
            // Modern Primary Accent ("Triage") - High-visibility cobalt / azure
            if (!is_enabled) {
                bg_color     = is_dark ? RGB(45, 55, 70)    : RGB(195, 218, 242);
                border_color = is_dark ? RGB(50, 60, 75)    : RGB(180, 205, 230);
                text_color   = is_dark ? RGB(110, 120, 135) : RGB(255, 255, 255);
            } else if (is_pressed) {
                bg_color     = is_dark ? RGB(0, 90, 175)    : RGB(0, 84, 153);
                border_color = is_dark ? RGB(0, 80, 160)    : RGB(0, 70, 130);
                text_color   = RGB(255, 255, 255);
            } else if (is_hovered) {
                bg_color     = is_dark ? RGB(24, 138, 248)  : RGB(16, 110, 190);
                border_color = is_dark ? RGB(50, 155, 255)  : RGB(10, 95, 165);
                text_color   = RGB(255, 255, 255);
            } else {
                bg_color     = is_dark ? RGB(0, 120, 215)   : RGB(0, 102, 204);
                border_color = is_focused ? (is_dark ? RGB(100, 180, 255) : RGB(0, 60, 140))
                                          : (is_dark ? RGB(20, 130, 225)  : RGB(0, 90, 185));
                text_color   = RGB(255, 255, 255);
            }
        } else if (data->style == ModernButtonStyle::Accent) {
            // Modern Emerald Accent ("Export JSON")
            if (!is_enabled) {
                bg_color     = is_dark ? RGB(35, 50, 40)    : RGB(195, 225, 205);
                border_color = is_dark ? RGB(40, 55, 45)    : RGB(180, 210, 190);
                text_color   = is_dark ? RGB(100, 120, 105) : RGB(255, 255, 255);
            } else if (is_pressed) {
                bg_color     = is_dark ? RGB(10, 90, 48)    : RGB(11, 85, 45);
                border_color = is_dark ? RGB(8, 75, 40)     : RGB(9, 70, 36);
                text_color   = RGB(255, 255, 255);
            } else if (is_hovered) {
                bg_color     = is_dark ? RGB(20, 145, 82)   : RGB(18, 138, 72);
                border_color = is_dark ? RGB(25, 160, 92)   : RGB(14, 120, 62);
                text_color   = RGB(255, 255, 255);
            } else {
                bg_color     = is_dark ? RGB(16, 124, 65)   : RGB(14, 115, 60);
                border_color = is_focused ? (is_dark ? RGB(80, 220, 140) : RGB(8, 80, 40))
                                          : (is_dark ? RGB(20, 135, 75)  : RGB(12, 100, 52));
                text_color   = RGB(255, 255, 255);
            }
        } else {
            // Modern Flat Card Pushbuttons (Load, Search, Next Hit, + Snap, Clear, Navigation)
            if (!is_enabled) {
                bg_color     = is_dark ? RGB(38, 38, 42)    : RGB(244, 245, 247);
                border_color = is_dark ? RGB(50, 50, 55)    : RGB(225, 228, 233);
                text_color   = is_dark ? RGB(100, 100, 105) : RGB(165, 170, 180);
            } else if (is_pressed) {
                bg_color     = is_dark ? RGB(32, 32, 35)    : RGB(220, 224, 230);
                border_color = is_dark ? RGB(75, 75, 82)    : RGB(170, 175, 185);
                text_color   = is_dark ? RGB(255, 255, 255) : RGB(15, 23, 42);
            } else if (is_hovered) {
                bg_color     = is_dark ? RGB(54, 54, 60)    : RGB(238, 242, 246);
                border_color = is_dark ? RGB(95, 95, 105)   : RGB(160, 168, 180);
                text_color   = is_dark ? RGB(255, 255, 255) : RGB(15, 23, 42);
            } else {
                bg_color     = is_dark ? RGB(45, 45, 50)    : RGB(255, 255, 255);
                border_color = is_focused ? (is_dark ? RGB(100, 160, 240) : RGB(0, 120, 215))
                                          : (is_dark ? RGB(70, 70, 78)    : RGB(205, 210, 218));
                text_color   = is_dark ? RGB(225, 225, 230) : RGB(30, 41, 59);
            }
        }

        // Draw modern rounded rectangle
        HBRUSH brBtn = CreateSolidBrush(bg_color);
        HPEN penBorder = CreatePen(PS_SOLID, 1, border_color);
        HGDIOBJ oldBrush = SelectObject(memDC, brBtn);
        HGDIOBJ oldPen = SelectObject(memDC, penBorder);

        RoundRect(memDC, rc.left, rc.top, rc.right, rc.bottom, 6, 6);

        SelectObject(memDC, oldPen);
        SelectObject(memDC, oldBrush);
        DeleteObject(penBorder);
        DeleteObject(brBtn);

        // Fetch button text
        char text_buf[128] = {};
        GetWindowTextA(hwnd, text_buf, sizeof(text_buf));

        SetBkMode(memDC, TRANSPARENT);
        SetTextColor(memDC, text_color);
        HFONT btn_font = (data->style == ModernButtonStyle::Primary) ? g_ui_font_bold : g_ui_font;
        HGDIOBJ oldFont = SelectObject(memDC, btn_font);

        RECT text_rc = rc;
        if (is_pressed) {
            text_rc.top  += 1;
            text_rc.left += 1;
        }
        DrawTextA(memDC, text_buf, -1, &text_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        BitBlt(hdc, 0, 0, w, h, memDC, 0, 0, SRCCOPY);

        SelectObject(memDC, oldFont);
        SelectObject(memDC, oldBmp);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    }

    return CallWindowProcA(data->old_proc, hwnd, msg, wp, lp);
}

void make_button_modern(HWND btn, ModernButtonStyle style) {
    if (btn == nullptr) return;
    ModernButtonData* existing = reinterpret_cast<ModernButtonData*>(GetPropA(btn, DEADEYE_BTN_PROP));
    if (existing != nullptr) {
        existing->style = style;
        return;
    }
    ModernButtonData* data = new ModernButtonData();
    data->style = style;
    data->is_hovered = false;
    data->old_proc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrA(btn, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ModernButtonSubclassProc))
    );
    SetPropA(btn, DEADEYE_BTN_PROP, reinterpret_cast<HANDLE>(data));
}

void copy_text_to_clipboard(HWND hwnd, const std::string &text)
{
    if (!OpenClipboard(hwnd))
        return;
    EmptyClipboard();
    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hGlob)
    {
        char *p = static_cast<char *>(GlobalLock(hGlob));
        if (p)
        {
            std::memcpy(p, text.c_str(), text.size() + 1);
            GlobalUnlock(hGlob);
            if (!SetClipboardData(CF_TEXT, hGlob))
            {
                GlobalFree(hGlob);
            }
        }
        else
        {
            GlobalFree(hGlob);
        }
    }
    CloseClipboard();
}

void on_capture_baseline()
{
    if (g_current_pid == 0)
    {
        char pid_buf[64] = {};
        GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
        DWORD parsed_pid = 0;
        if (parse_pid_string(pid_buf, parsed_pid) && parsed_pid != 0)
        {
            g_current_pid = parsed_pid;
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Please enter a valid numeric target PID first before capturing a baseline.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    std::string err;
    set_status("Capturing full process baseline snapshot (PID " + std::to_string(g_current_pid) + ")...");
    UpdateWindow(g_lbl_status);

    if (capture_process_snapshot_session(g_current_pid, g_process_baseline, err))
    {
        g_has_baseline = true;
        char msg[160];
        std::snprintf(msg, sizeof(msg), "Baseline captured: %zu committed regions (%s) for PID %u (%s)",
                      g_process_baseline.regions.size(),
                      fmt_size_short(g_process_baseline.total_committed_bytes).c_str(),
                      static_cast<unsigned int>(g_process_baseline.pid),
                      g_process_baseline.process_name.c_str());
        set_status(msg);
        MessageBoxA(g_hwnd_main, msg, "Deadeye Process Diff", MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        set_status("[ERROR] " + err);
        MessageBoxA(g_hwnd_main, err.c_str(), "Deadeye Process Diff Error", MB_OK | MB_ICONERROR);
    }
}

void on_capture_diff()
{
    if (g_current_pid == 0)
    {
        char pid_buf[64] = {};
        GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
        DWORD parsed_pid = 0;
        if (parse_pid_string(pid_buf, parsed_pid) && parsed_pid != 0)
        {
            g_current_pid = parsed_pid;
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Please enter a valid numeric target PID first.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    if (!g_has_baseline)
    {
        on_capture_baseline();
        if (g_has_baseline)
        {
            MessageBoxA(g_hwnd_main,
                        "Baseline snapshot captured successfully!\n\n"
                        "Now run your target malware sample or trigger suspicious activity,\n"
                        "then click 'Diff Proc' again (or press Ctrl+D) to compute the diff.",
                        "Deadeye Baseline Captured", MB_OK | MB_ICONINFORMATION);
        }
        return;
    }

    std::string err;
    set_status("Capturing current process snapshot and computing diff...");
    UpdateWindow(g_lbl_status);

    if (capture_process_snapshot_session(g_current_pid, g_process_target, err))
    {
        g_has_target = true;
        compute_process_diff(g_process_baseline, g_process_target, g_process_diffs);

        // Switch to Process Diff view
        g_view_mode = ViewMode::ProcessDiff;
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 2, 0);
        populate_region_list();

        size_t new_cnt = 0, prot_cnt = 0, mod_cnt = 0, del_cnt = 0;
        for (const auto &d : g_process_diffs)
        {
            if (d.kind == ProcessDiffKind::Appeared) new_cnt++;
            else if (d.kind == ProcessDiffKind::ProtectionChg) prot_cnt++;
            else if (d.kind == ProcessDiffKind::ContentChg) mod_cnt++;
            else if (d.kind == ProcessDiffKind::Disappeared) del_cnt++;
        }

        char msg[220];
        std::snprintf(msg, sizeof(msg),
                      "Diff complete: %zu changes detected | %zu new regions, %zu protection flips, %zu modified, %zu freed",
                      g_process_diffs.size(), new_cnt, prot_cnt, mod_cnt, del_cnt);
        set_status(msg);
    }
    else
    {
        set_status("[ERROR] " + err);
        MessageBoxA(g_hwnd_main, err.c_str(), "Deadeye Process Diff Error", MB_OK | MB_ICONERROR);
    }
}

void on_save_diff_session()
{
    if (!g_has_baseline && !g_has_target)
    {
        MessageBoxA(g_hwnd_main, "No process session snapshots to save.", "Deadeye Session Export", MB_OK | MB_ICONWARNING);
        return;
    }

    const ProcessSnapshotSession &session_to_save = g_has_target ? g_process_target : g_process_baseline;

    char file_buf[MAX_PATH] = {};
    std::string def_name = "deadeye_session_" + std::to_string(session_to_save.pid) + ".json";
    std::strncpy(file_buf, def_name.c_str(), sizeof(file_buf) - 1);

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "JSON Session Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "json";

    if (GetSaveFileNameA(&ofn))
    {
        if (save_process_session_to_file(session_to_save, ofn.lpstrFile))
        {
            set_status("Session saved successfully to " + std::string(ofn.lpstrFile));
            MessageBoxA(g_hwnd_main, "Process snapshot session exported successfully.", "Deadeye Session Export", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Failed to write session file.", "Deadeye Session Export Error", MB_OK | MB_ICONERROR);
        }
    }
}

void on_load_diff_session()
{
    char file_buf[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "JSON Session Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.Flags = OFN_FILEMUSTEXIST;
    ofn.lpstrDefExt = "json";

    if (GetOpenFileNameA(&ofn))
    {
        ProcessSnapshotSession loaded_session;
        if (load_process_session_from_file(ofn.lpstrFile, loaded_session))
        {
            if (!g_has_baseline)
            {
                g_process_baseline = loaded_session;
                g_has_baseline = true;
                set_status("Loaded baseline session: " + loaded_session.process_name + " (" + std::to_string(loaded_session.regions.size()) + " regions)");
                MessageBoxA(g_hwnd_main, ("Loaded baseline snapshot session from:\n" + std::string(ofn.lpstrFile) + "\n\nYou can now capture a live snapshot or load a second session to compare.").c_str(), "Deadeye Session Load", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                g_process_target = loaded_session;
                g_has_target = true;
                compute_process_diff(g_process_baseline, g_process_target, g_process_diffs);
                g_view_mode = ViewMode::ProcessDiff;
                SendMessageA(g_combo_view_mode, CB_SETCURSEL, 2, 0);
                populate_region_list();
                set_status("Loaded target session & computed diff: " + std::to_string(g_process_diffs.size()) + " changes identified.");
                MessageBoxA(g_hwnd_main, ("Compared loaded session with baseline.\nIdentified " + std::to_string(g_process_diffs.size()) + " differences.").c_str(), "Deadeye Session Diff", MB_OK | MB_ICONINFORMATION);
            }
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Failed to parse session JSON file.", "Deadeye Session Load Error", MB_OK | MB_ICONERROR);
        }
    }
}

void evaluate_memory_behavior_heartbeat()
{
    if (g_current_pid == 0) return;
    HANDLE proc = get_or_open_target_proc(g_current_pid);
    if (!proc) return;

    DWORD now = GetTickCount();
    std::vector<uint8_t> read_buf(64 * 1024);
    bool new_detection = false;

    for (auto &reg : g_regions)
    {
        if (reg.type == MEM_IMAGE)
            continue;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(reg.base), &mbi, sizeof(mbi)) != sizeof(mbi))
            continue;

        DWORD cur_protect = mbi.Protect;
        if (reg.last_protect == 0)
        {
            reg.last_protect = reg.protect;
            reg.last_entropy = 0.0;
            reg.last_hash = 0;
        }

        if (cur_protect != reg.last_protect)
        {
            bool was_non_exec = (reg.last_protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY)) != 0;
            bool is_exec = (cur_protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

            reg.flip_count++;
            reg.protect_history.push_back(cur_protect);

            SIZE_T to_read = std::min<SIZE_T>(reg.size, read_buf.size());
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(reg.base), read_buf.data(), to_read, &bytes_read) && bytes_read > 0)
            {
                uint64_t cur_hash = fnv1a64(read_buf.data(), bytes_read);
                double cur_entropy = calculate_shannon_entropy(read_buf.data(), bytes_read);

                MemoryTransition tr;
                tr.timestamp_ms = now;
                tr.old_protect = reg.last_protect;
                tr.new_protect = cur_protect;
                tr.old_entropy = reg.last_entropy;
                tr.new_entropy = cur_entropy;
                tr.old_hash = reg.last_hash;
                tr.new_hash = cur_hash;

                // Unpack detection: non-exec -> exec, bytes mutated or entropy dropped
                if (was_non_exec && is_exec && (cur_hash != reg.last_hash || cur_entropy < reg.last_entropy - 0.4 || reg.last_hash == 0))
                {
                    tr.is_unpack = true;
                    if (!reg.behavior_unpack_detected)
                    {
                        reg.behavior_unpack_detected = true;
                        new_detection = true;
                    }

                    // Extract new strings
                    auto revealed = extract_strings_from_buffer(read_buf.data(), bytes_read, reg.base, 4);
                    for (const auto &rs : revealed)
                    {
                        bool exists = false;
                        for (const auto &prev : g_revealed_strings)
                        {
                            if (prev.addr == rs.addr && prev.text == rs.text)
                            {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            g_revealed_strings.push_back(rs);
                        }
                    }
                }

                // Sleep obfuscation detection: oscillating across ticks
                if (reg.flip_count >= 2)
                {
                    tr.is_sleep_cycle = true;
                    if (!reg.sleep_obfuscation_detected)
                    {
                        reg.sleep_obfuscation_detected = true;
                        new_detection = true;
                    }
                }

                reg.transitions.push_back(tr);
                reg.last_hash = cur_hash;
                reg.last_entropy = cur_entropy;
            }
            reg.last_protect = cur_protect;
        }
    }

    if (new_detection)
    {
        g_triage_report = run_process_triage(proc, g_current_pid, g_regions, nullptr, nullptr, nullptr);
        populate_region_list();
        set_status("[BEHAVIOR DETECTED] Unpack or sleep obfuscation transition identified during heartbeat!");
    }
}

struct YaraDialogData
{
    std::string rule_text;
    uintptr_t base_addr = 0;
    DWORD pid = 0;
    HWND hEditRule = nullptr;
    HWND hEditReport = nullptr;
    HWND hBtnTestFP = nullptr;
    HWND hBtnCopy = nullptr;
    HWND hBtnSave = nullptr;
    HWND hBtnClose = nullptr;
};

LRESULT CALLBACK YaraDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<YaraDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<YaraDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));

        HINSTANCE hInst = cs->hInstance;

        HWND lbl1 = CreateWindowA("STATIC", "Generated YARA Rule (Auto-Wildcarded for Displacements, Relocations & Immediates):",
                                  WS_CHILD | WS_VISIBLE, 12, 12, 730, 18, hwnd, nullptr, hInst, nullptr);

        data->hEditRule = CreateWindowA("EDIT", data->rule_text.c_str(),
                                        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
                                        12, 34, 740, 240, hwnd, reinterpret_cast<HMENU>(3001), hInst, nullptr);

        data->hBtnTestFP = CreateWindowA("BUTTON", "Run False-Positive Test",
                                         WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         12, 284, 200, 28, hwnd, reinterpret_cast<HMENU>(3002), hInst, nullptr);

        data->hBtnCopy = CreateWindowA("BUTTON", "Copy Rule",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       222, 284, 100, 28, hwnd, reinterpret_cast<HMENU>(3003), hInst, nullptr);

        data->hBtnSave = CreateWindowA("BUTTON", "Save .yar File...",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       332, 284, 130, 28, hwnd, reinterpret_cast<HMENU>(3004), hInst, nullptr);

        data->hBtnClose = CreateWindowA("BUTTON", "Close",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        652, 284, 100, 28, hwnd, reinterpret_cast<HMENU>(3005), hInst, nullptr);

        HWND lbl2 = CreateWindowA("STATIC", "False-Positive Test Status & Clean Software Verification:",
                                  WS_CHILD | WS_VISIBLE, 12, 322, 730, 18, hwnd, nullptr, hInst, nullptr);

        data->hEditReport = CreateWindowA("EDIT", "Ready. Click 'Run False-Positive Test' to scan all active running processes on the system.",
                                          WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL |
                                              ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                          12, 344, 740, 220, hwnd, reinterpret_cast<HMENU>(3006), hInst, nullptr);

        HWND ui_ctrls[] = { lbl1, data->hBtnTestFP, data->hBtnCopy, data->hBtnSave, data->hBtnClose, lbl2 };
        for (HWND c : ui_ctrls)
            SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        SendMessageA(data->hEditRule, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);
        SendMessageA(data->hEditReport, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

        make_button_modern(data->hBtnTestFP, ModernButtonStyle::Primary);
        make_button_modern(data->hBtnCopy, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnSave, ModernButtonStyle::Accent);
        make_button_modern(data->hBtnClose, ModernButtonStyle::Standard);

        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        if (id == 3002) // Run FP Test
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hEditRule);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hEditRule, buf.data(), len + 1);
            std::string rule_str = buf.data();

            std::string hex_str;
            size_t str_pos = rule_str.find("strings:");
            if (str_pos != std::string::npos)
            {
                size_t sig_brace_start = rule_str.find('{', str_pos);
                if (sig_brace_start != std::string::npos)
                {
                    size_t sig_brace_end = rule_str.find('}', sig_brace_start);
                    if (sig_brace_end != std::string::npos && sig_brace_end > sig_brace_start)
                    {
                        hex_str = rule_str.substr(sig_brace_start + 1, sig_brace_end - sig_brace_start - 1);
                    }
                }
            }
            if (hex_str.empty())
            {
                size_t first_brace = rule_str.find('{');
                if (first_brace != std::string::npos)
                {
                    size_t second_brace = rule_str.find('{', first_brace + 1);
                    if (second_brace != std::string::npos)
                    {
                        size_t second_brace_end = rule_str.find('}', second_brace);
                        if (second_brace_end != std::string::npos && second_brace_end > second_brace)
                        {
                            hex_str = rule_str.substr(second_brace + 1, second_brace_end - second_brace - 1);
                        }
                    }
                }
            }
            if (hex_str.empty())
            {
                hex_str = rule_str;
            }

            Pattern pat;
            std::string perr;
            if (!parse_pattern(hex_str, pat, perr))
            {
                SetWindowTextA(data->hEditReport, ("[ERROR] Invalid signature pattern: " + perr).c_str());
                return 0;
            }

            SetWindowTextA(data->hEditReport, "Scanning all running processes on the system... Please wait...");
            UpdateWindow(data->hEditReport);

            FalsePositiveReport rep = test_rule_false_positives(pat, data->pid);

            std::ostringstream ss;
            ss << "======================================================================\r\n";
            ss << "                     FALSE-POSITIVE TEST REPORT                       \r\n";
            ss << "======================================================================\r\n\r\n";
            ss << "Target PID (Excluded):      " << data->pid << "\r\n";
            ss << "Running Processes Scanned:  " << rep.total_processes_scanned << " (out of " << rep.total_processes_checked << " total)\r\n";
            ss << "Executable Memory Searched: " << fmt_size_short(rep.total_bytes_scanned) << "\r\n";
            ss << "Scan Time:                  " << rep.elapsed_ms << " ms\r\n\r\n";

            if (rep.matches.empty())
            {
                ss << ">>> RESULT: [PASSED - 0 FALSE POSITIVES] <<<\r\n";
                ss << "The generated signature did not match any clean running software on this system.\r\n";
                ss << "This rule is highly specific and safe for deployment in detection pipelines.\r\n";
            }
            else
            {
                ss << ">>> RESULT: [WARNING - " << rep.matches.size() << " FALSE POSITIVES DETECTED] <<<\r\n";
                ss << "Matches were detected in clean system software:\r\n";
                for (const auto &m : rep.matches)
                {
                    char abuf[32];
                    std::snprintf(abuf, sizeof(abuf), "0x%016llX", static_cast<unsigned long long>(m.match_addr));
                    ss << "  * " << m.process_name << " (PID " << m.pid << ") at " << abuf << "\r\n";
                }
                ss << "\r\nRecommendation: Restrict wildcards or include anchor instruction prefixes.\r\n";
            }

            SetWindowTextA(data->hEditReport, ss.str().c_str());
        }
        else if (id == 3003) // Copy Rule
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hEditRule);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hEditRule, buf.data(), len + 1);
            copy_text_to_clipboard(hwnd, buf.data());
            MessageBoxA(hwnd, "YARA rule copied to clipboard.", "Deadeye YARA", MB_OK | MB_ICONINFORMATION);
        }
        else if (id == 3004) // Save .yar
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hEditRule);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hEditRule, buf.data(), len + 1);

            char file_buf[MAX_PATH] = "deadeye_rule.yar";
            OPENFILENAMEA ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = "YARA Rules (*.yar;*.yara)\0*.yar;*.yara\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = file_buf;
            ofn.nMaxFile = sizeof(file_buf);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = "yar";

            if (GetSaveFileNameA(&ofn))
            {
                std::ofstream f(ofn.lpstrFile, std::ios::binary);
                if (f.is_open())
                {
                    f.write(buf.data(), len);
                    MessageBoxA(hwnd, "Rule saved successfully.", "Deadeye YARA", MB_OK | MB_ICONINFORMATION);
                }
            }
        }
        else if (id == 3005) // Close
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
    {
        HWND hOwner = GetWindow(hwnd, GW_OWNER);
        if (hOwner)
        {
            EnableWindow(hOwner, TRUE);
            SetActiveWindow(hOwner);
        }
        if (data) delete data;
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

void open_yara_dialog(HWND hParent)
{
    uintptr_t target_base = 0;
    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (g_selected_region < g_process_diffs.size())
        {
            target_base = g_process_diffs[g_selected_region].base + g_view_offset;
        }
    }
    else
    {
        if (g_selected_region < g_regions.size())
        {
            target_base = g_regions[g_selected_region].base + g_view_offset;
        }
    }

    if (target_base == 0)
    {
        MessageBoxA(hParent, "Please select a memory region or bytes in hex view first.", "Deadeye YARA Generator", MB_OK | MB_ICONWARNING);
        return;
    }

    std::vector<uint8_t> target_bytes;

    // Check if user selected text in hex dump
    DWORD sel_start = 0, sel_end = 0;
    SendMessageA(g_edit_hex, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start), reinterpret_cast<LPARAM>(&sel_end));
    if (sel_start != sel_end)
    {
        int len = GetWindowTextLengthA(g_edit_hex);
        if (len > 0)
        {
            std::vector<char> full_text(len + 1);
            GetWindowTextA(g_edit_hex, full_text.data(), len + 1);
            std::string sel_text(full_text.data() + sel_start, full_text.data() + sel_end);

            std::istringstream iss(sel_text);
            std::string tok;
            while (iss >> tok)
            {
                if (tok.size() == 2 && isxdigit(static_cast<unsigned char>(tok[0])) && isxdigit(static_cast<unsigned char>(tok[1])))
                {
                    uint8_t b = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
                    target_bytes.push_back(b);
                }
            }
        }
    }

    if (target_bytes.empty())
    {
        // Read 64 bytes at current view offset
        HANDLE proc = get_or_open_target_proc(g_current_pid);
        if (proc)
        {
            target_bytes.resize(64);
            SIZE_T bytes_read = 0;
            ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(target_base), target_bytes.data(), 64, &bytes_read);
            target_bytes.resize(bytes_read);
        }
    }

    if (target_bytes.empty())
    {
        MessageBoxA(hParent, "Could not read memory bytes at current location to generate rule.", "Deadeye YARA Generator", MB_OK | MB_ICONWARNING);
        return;
    }

    std::string rule_name = "sig_mem_pid" + std::to_string(g_current_pid) + "_" + to_hex_string(target_base).substr(8);
    YaraWildcardResult wres = auto_wildcard_bytes(target_bytes.data(), target_bytes.size(), target_base, g_current_pid, rule_name);
    std::string rule_text = generate_yara_rule_text(wres, target_base, g_current_pid, rule_name);

    YaraDialogData *data = new YaraDialogData();
    data->rule_text = rule_text;
    data->base_addr = target_base;
    data->pid = g_current_pid;

    EnableWindow(hParent, FALSE);

    RECT parent_rc;
    GetWindowRect(hParent, &parent_rc);
    int dlg_w = 780, dlg_h = 620;
    int dlg_x = parent_rc.left + (parent_rc.right - parent_rc.left - dlg_w) / 2;
    int dlg_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - dlg_h) / 2;
    if (dlg_x < 10) dlg_x = 10;
    if (dlg_y < 10) dlg_y = 10;

    CreateWindowExA(WS_EX_DLGMODALFRAME, "DeadeyeYaraDlg",
                    "YARA Rule Generator & False-Positive Validator",
                    WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                    dlg_x, dlg_y, dlg_w, dlg_h, hParent, nullptr, GetModuleHandleA(nullptr), data);
}

struct StringsDialogData
{
    HWND hFilterEdit = nullptr;
    HWND hListStrings = nullptr;
    HWND hBtnCopy = nullptr;
    HWND hBtnExport = nullptr;
    HWND hBtnClose = nullptr;
};

void populate_strings_view(HWND hEdit, const std::string &filter)
{
    std::string text;
    for (const auto &s : g_revealed_strings)
    {
        if (!filter.empty() && s.text.find(filter) == std::string::npos && s.category.find(filter) == std::string::npos)
            continue;

        char abuf[32];
        std::snprintf(abuf, sizeof(abuf), "0x%016llX", static_cast<unsigned long long>(s.addr));
        text += s.category + "  " + abuf + "  " + s.text + "\r\n";
    }
    if (text.empty())
    {
        if (g_revealed_strings.empty())
            text = "(No strings revealed yet. Enable Heartbeat to monitor payload unpacking/transitions.)\r\n";
        else
            text = "(No strings match current filter.)\r\n";
    }
    SetWindowTextA(hEdit, text.c_str());
}

LRESULT CALLBACK StringsDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<StringsDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<StringsDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));
        HINSTANCE hInst = cs->hInstance;

        HWND lbl1 = CreateWindowA("STATIC", "Newly Revealed Strings (Extracted after Unpack / Protection Transitions):",
                                  WS_CHILD | WS_VISIBLE, 12, 10, 720, 18, hwnd, nullptr, hInst, nullptr);

        HWND lbl_note = CreateWindowA("STATIC", "[Note: Monitored via 1-second heartbeat polling. Sub-second transitions may be missed.]",
                                      WS_CHILD | WS_VISIBLE, 12, 30, 720, 18, hwnd, nullptr, hInst, nullptr);

        HWND lbl_flt = CreateWindowA("STATIC", "Filter:", WS_CHILD | WS_VISIBLE, 12, 54, 42, 20, hwnd, nullptr, hInst, nullptr);

        data->hFilterEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                          58, 52, 240, 24, hwnd, reinterpret_cast<HMENU>(4001), hInst, nullptr);

        data->hBtnCopy = CreateWindowA("BUTTON", "Copy All", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       310, 52, 90, 24, hwnd, reinterpret_cast<HMENU>(4002), hInst, nullptr);

        data->hBtnExport = CreateWindowA("BUTTON", "Export TXT...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         408, 52, 110, 24, hwnd, reinterpret_cast<HMENU>(4003), hInst, nullptr);

        data->hBtnClose = CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        642, 52, 90, 24, hwnd, reinterpret_cast<HMENU>(4004), hInst, nullptr);

        data->hListStrings = CreateWindowA("EDIT", "",
                                           WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                               ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                           12, 84, 720, 430, hwnd, reinterpret_cast<HMENU>(4005), hInst, nullptr);

        HWND ui_ctrls[] = { lbl1, lbl_note, lbl_flt, data->hFilterEdit, data->hBtnCopy, data->hBtnExport, data->hBtnClose };
        for (HWND c : ui_ctrls)
            SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        SendMessageA(data->hListStrings, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

        make_button_modern(data->hBtnCopy, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnExport, ModernButtonStyle::Accent);
        make_button_modern(data->hBtnClose, ModernButtonStyle::Standard);

        populate_strings_view(data->hListStrings, "");
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
        if (id == 4001 && code == EN_CHANGE)
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hFilterEdit);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hFilterEdit, buf.data(), len + 1);
            populate_strings_view(data->hListStrings, buf.data());
        }
        else if (id == 4002) // Copy
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hListStrings);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(data->hListStrings, buf.data(), len + 1);
                copy_text_to_clipboard(hwnd, buf.data());
                MessageBoxA(hwnd, "Revealed strings copied to clipboard.", "Deadeye Strings", MB_OK | MB_ICONINFORMATION);
            }
        }
        else if (id == 4003) // Export
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hListStrings);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(data->hListStrings, buf.data(), len + 1);

                char file_buf[MAX_PATH] = "revealed_strings.txt";
                OPENFILENAMEA ofn = {};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
                ofn.lpstrFile = file_buf;
                ofn.nMaxFile = sizeof(file_buf);
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
                ofn.lpstrDefExt = "txt";

                if (GetSaveFileNameA(&ofn))
                {
                    std::ofstream f(ofn.lpstrFile, std::ios::binary);
                    if (f.is_open())
                    {
                        f.write(buf.data(), len);
                        MessageBoxA(hwnd, "Strings exported successfully.", "Deadeye Strings", MB_OK | MB_ICONINFORMATION);
                    }
                }
            }
        }
        else if (id == 4004) // Close
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
    {
        HWND hOwner = GetWindow(hwnd, GW_OWNER);
        if (hOwner)
        {
            EnableWindow(hOwner, TRUE);
            SetActiveWindow(hOwner);
        }
        if (data) delete data;
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

void open_revealed_strings_dialog(HWND hParent)
{
    StringsDialogData *data = new StringsDialogData();
    EnableWindow(hParent, FALSE);

    RECT parent_rc;
    GetWindowRect(hParent, &parent_rc);
    int dlg_w = 760, dlg_h = 560;
    int dlg_x = parent_rc.left + (parent_rc.right - parent_rc.left - dlg_w) / 2;
    int dlg_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - dlg_h) / 2;
    if (dlg_x < 10) dlg_x = 10;
    if (dlg_y < 10) dlg_y = 10;

    CreateWindowExA(WS_EX_DLGMODALFRAME, "DeadeyeStringsDlg",
                    "Revealed Strings - Memory Behavior Timeline",
                    WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                    dlg_x, dlg_y, dlg_w, dlg_h, hParent, nullptr, GetModuleHandleA(nullptr), data);
}

// ============================================================================
// Process Attachment Dialog (Debugger-Style Process / Window Picker)
// ============================================================================

#define ID_ATTACH_SEARCH 5001
#define ID_ATTACH_LIST 5002
#define ID_ATTACH_WINDOWS_ONLY 5003
#define ID_ATTACH_BTN_REFRESH 5004
#define ID_ATTACH_BTN_ATTACH 5005
#define ID_ATTACH_BTN_CANCEL 5006
#define ID_ATTACH_STATUS 5007

struct ProcessListEntry
{
    DWORD pid = 0;
    std::string name;
    std::string window_title;
    std::string arch;        // "x64", "x86", or "?"
    std::string path;
    bool has_window = false;
};

struct AttachDialogData
{
    HWND hEditSearch = nullptr;
    HWND hChkWindowsOnly = nullptr;
    HWND hBtnRefresh = nullptr;
    HWND hList = nullptr;
    HWND hLblStatus = nullptr;
    HWND hBtnAttach = nullptr;
    HWND hBtnCancel = nullptr;

    std::vector<ProcessListEntry> all_entries;
    std::vector<ProcessListEntry> filtered_entries;

    int sort_column = -1; // -1 means default: visible windows first, then name alphabetical
    bool sort_asc = true;

    bool confirmed = false;
    DWORD selected_pid = 0;
    std::string selected_name;
};

struct EnumWindowsAttachContext
{
    std::unordered_map<DWORD, std::string> pid_to_title;
};

static BOOL CALLBACK EnumWindowsAttachProc(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;

    if (GetWindow(hwnd, GW_OWNER) != nullptr)
        return TRUE;

    LONG_PTR ex_style = GetWindowLongPtrA(hwnd, GWL_EXSTYLE);
    if (ex_style & WS_EX_TOOLWINDOW)
        return TRUE;

    int len = GetWindowTextLengthA(hwnd);
    if (len <= 0)
        return TRUE;

    std::vector<char> title_buf(static_cast<size_t>(len) + 1);
    GetWindowTextA(hwnd, title_buf.data(), len + 1);
    std::string title = title_buf.data();

    bool non_ws = false;
    for (char c : title)
    {
        if (!std::isspace(static_cast<unsigned char>(c)))
        {
            non_ws = true;
            break;
        }
    }
    if (!non_ws)
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != 0)
    {
        auto *ctx = reinterpret_cast<EnumWindowsAttachContext*>(lParam);
        auto it = ctx->pid_to_title.find(pid);
        if (it == ctx->pid_to_title.end())
        {
            ctx->pid_to_title[pid] = title;
        }
        else if (title.length() > it->second.length())
        {
            ctx->pid_to_title[pid] = title;
        }
    }
    return TRUE;
}

static bool is_host_64bit()
{
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
}

static void sort_process_entries(AttachDialogData *data)
{
    int col = data->sort_column;
    bool asc = data->sort_asc;

    std::sort(data->all_entries.begin(), data->all_entries.end(), [col, asc](const ProcessListEntry &a, const ProcessListEntry &b) {
        if (col == 0) // Process Name
        {
            std::string na = a.name, nb = b.name;
            for (char &c : na) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char &c : nb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (na != nb) return asc ? (na < nb) : (na > nb);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }
        else if (col == 1) // PID
        {
            if (a.pid != b.pid) return asc ? (a.pid < b.pid) : (a.pid > b.pid);
            return false;
        }
        else if (col == 2) // Window Title
        {
            std::string ta = a.window_title, tb = b.window_title;
            for (char &c : ta) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char &c : tb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (ta != tb) return asc ? (ta < tb) : (ta > tb);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }
        else if (col == 3) // Arch
        {
            if (a.arch != b.arch) return asc ? (a.arch < b.arch) : (a.arch > b.arch);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }
        else if (col == 4) // Path
        {
            std::string pa = a.path, pb = b.path;
            for (char &c : pa) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char &c : pb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (pa != pb) return asc ? (pa < pb) : (pa > pb);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }

        // Default sort: entries with visible windows first, then name alphabetical
        if (a.has_window != b.has_window)
            return a.has_window > b.has_window;
        std::string na = a.name, nb = b.name;
        for (char &c : na) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (char &c : nb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (na != nb) return na < nb;
        return a.pid < b.pid;
    });
}

static void refresh_process_list(AttachDialogData *data)
{
    data->all_entries.clear();

    EnumWindowsAttachContext wctx;
    EnumWindows(EnumWindowsAttachProc, reinterpret_cast<LPARAM>(&wctx));

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe))
        {
            bool sys_64 = is_host_64bit();
            do
            {
                DWORD pid = pe.th32ProcessID;
                if (pid == 0) // Skip System Idle Process
                    continue;

                ProcessListEntry entry;
                entry.pid = pid;

                char name_buf[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, sizeof(name_buf), nullptr, nullptr);
                entry.name = name_buf;

                auto wit = wctx.pid_to_title.find(pid);
                if (wit != wctx.pid_to_title.end() && !wit->second.empty())
                {
                    entry.window_title = wit->second;
                    entry.has_window = true;
                }

                entry.arch = "?";
                entry.path = "";

                // Query architecture and image path strictly read-only
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!hProc)
                {
                    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                }

                if (hProc)
                {
                    BOOL is_wow64 = FALSE;
                    if (IsWow64Process(hProc, &is_wow64))
                    {
                        if (sys_64)
                            entry.arch = is_wow64 ? "x86" : "x64";
                        else
                            entry.arch = "x86";
                    }

                    char path_buf[MAX_PATH * 2] = {};
                    DWORD path_len = static_cast<DWORD>(sizeof(path_buf));
                    if (QueryFullProcessImageNameA(hProc, 0, path_buf, &path_len) && path_len > 0)
                    {
                        entry.path = path_buf;
                    }
                    CloseHandle(hProc);
                }

                data->all_entries.push_back(std::move(entry));
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    sort_process_entries(data);
}

static void apply_process_filter(AttachDialogData *data)
{
    char filter_buf[256] = {};
    if (data->hEditSearch)
        GetWindowTextA(data->hEditSearch, filter_buf, sizeof(filter_buf));
    std::string query = filter_buf;
    for (char &c : query) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    while (!query.empty() && std::isspace(static_cast<unsigned char>(query.front()))) query.erase(query.begin());
    while (!query.empty() && std::isspace(static_cast<unsigned char>(query.back()))) query.pop_back();

    bool windows_only = false;
    if (data->hChkWindowsOnly)
        windows_only = (SendMessageA(data->hChkWindowsOnly, BM_GETCHECK, 0, 0) == BST_CHECKED);

    data->filtered_entries.clear();
    for (const auto &e : data->all_entries)
    {
        if (windows_only && !e.has_window)
            continue;

        if (query.empty())
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match name
        std::string name_lower = e.name;
        for (char &c : name_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (name_lower.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match window title
        std::string title_lower = e.window_title;
        for (char &c : title_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (title_lower.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match decimal PID
        std::string pid_str = std::to_string(e.pid);
        if (pid_str.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match hex PID
        char hex_buf[32];
        snprintf(hex_buf, sizeof(hex_buf), "%lx", static_cast<unsigned long>(e.pid));
        std::string hex_str = hex_buf;
        if (hex_str.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }
        std::string hex_0x = "0x" + hex_str;
        if (hex_0x.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }
    }
}

static void populate_attach_listview(AttachDialogData *data)
{
    apply_process_filter(data);

    HWND hList = data->hList;
    SendMessageA(hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hList);

    for (int i = 0; i < static_cast<int>(data->filtered_entries.size()); ++i)
    {
        const auto &e = data->filtered_entries[static_cast<size_t>(i)];
        LVITEMA item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = i;
        item.iSubItem = 0;
        item.pszText = const_cast<char*>(e.name.c_str());
        item.lParam = static_cast<LPARAM>(e.pid);
        ListView_InsertItem(hList, &item);

        char pid_str[64];
        snprintf(pid_str, sizeof(pid_str), "%lu (0x%04lX)", static_cast<unsigned long>(e.pid), static_cast<unsigned long>(e.pid));
        ListView_SetItemText(hList, i, 1, pid_str);

        ListView_SetItemText(hList, i, 2, const_cast<char*>(e.window_title.c_str()));
        ListView_SetItemText(hList, i, 3, const_cast<char*>(e.arch.c_str()));
        ListView_SetItemText(hList, i, 4, const_cast<char*>(e.path.c_str()));
    }

    SendMessageA(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, nullptr, TRUE);

    if (!data->filtered_entries.empty())
    {
        ListView_SetItemState(hList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    size_t win_count = 0;
    for (const auto &e : data->all_entries)
    {
        if (e.has_window) win_count++;
    }
    std::string status_str = "Showing " + std::to_string(data->filtered_entries.size()) +
                             " of " + std::to_string(data->all_entries.size()) +
                             " processes (" + std::to_string(win_count) + " with windows)";
    if (data->hLblStatus)
    {
        SetWindowTextA(data->hLblStatus, status_str.c_str());
    }
}

static void on_attach_confirm(HWND hwnd, AttachDialogData *data)
{
    int sel = ListView_GetNextItem(data->hList, -1, LVNI_SELECTED);
    if (sel < 0 && !data->filtered_entries.empty())
    {
        sel = 0;
    }
    if (sel < 0 || sel >= static_cast<int>(data->filtered_entries.size()))
    {
        MessageBoxA(hwnd, "Please select a target process from the list.", "Deadeye Attach", MB_OK | MB_ICONINFORMATION);
        return;
    }

    data->selected_pid = data->filtered_entries[static_cast<size_t>(sel)].pid;
    data->selected_name = data->filtered_entries[static_cast<size_t>(sel)].name;
    data->confirmed = true;

    DestroyWindow(hwnd);
}

LRESULT CALLBACK AttachDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<AttachDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<AttachDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));

        HINSTANCE hInst = cs->hInstance;

        HWND lbl_search = CreateWindowA("STATIC", "Search:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                        12, 14, 50, 20, hwnd, nullptr, hInst, nullptr);

        data->hEditSearch = CreateWindowA("EDIT", "",
                                          WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                          68, 12, 240, 24, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_SEARCH), hInst, nullptr);

        data->hChkWindowsOnly = CreateWindowA("BUTTON", "Processes with visible windows only",
                                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                              320, 12, 250, 24, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_WINDOWS_ONLY), hInst, nullptr);

        data->hBtnRefresh = CreateWindowA("BUTTON", "Refresh",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          760, 12, 80, 24, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_BTN_REFRESH), hInst, nullptr);

        data->hList = CreateWindowExA(
            0, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            12, 44, 830, 460, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_LIST), hInst, nullptr);

        SendMessageA(data->hList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNA col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        col.pszText = const_cast<char*>("Process Name");
        col.cx = 170;
        col.iSubItem = 0;
        ListView_InsertColumn(data->hList, 0, &col);

        col.pszText = const_cast<char*>("PID");
        col.cx = 105;
        col.iSubItem = 1;
        ListView_InsertColumn(data->hList, 1, &col);

        col.pszText = const_cast<char*>("Window Title");
        col.cx = 240;
        col.iSubItem = 2;
        ListView_InsertColumn(data->hList, 2, &col);

        col.pszText = const_cast<char*>("Arch");
        col.cx = 60;
        col.iSubItem = 3;
        ListView_InsertColumn(data->hList, 3, &col);

        col.pszText = const_cast<char*>("Executable Path");
        col.cx = 240;
        col.iSubItem = 4;
        ListView_InsertColumn(data->hList, 4, &col);

        data->hLblStatus = CreateWindowA("STATIC", "Loading processes...",
                                         WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                         12, 516, 620, 22, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_STATUS), hInst, nullptr);

        data->hBtnAttach = CreateWindowA("BUTTON", "Attach",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                         660, 514, 85, 26, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_BTN_ATTACH), hInst, nullptr);

        data->hBtnCancel = CreateWindowA("BUTTON", "Cancel",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                         755, 514, 85, 26, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_BTN_CANCEL), hInst, nullptr);

        HWND ui_ctrls[] = { lbl_search, data->hEditSearch, data->hChkWindowsOnly, data->hBtnRefresh,
                            data->hLblStatus, data->hBtnAttach, data->hBtnCancel };
        for (HWND c : ui_ctrls)
        {
            if (c) SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }
        if (data->hList)
        {
            SendMessageA(data->hList, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }

        make_button_modern(data->hBtnAttach, ModernButtonStyle::Primary);
        make_button_modern(data->hBtnCancel, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnRefresh, ModernButtonStyle::Standard);

        const ThemeColors &tc = get_current_theme();
        if (g_theme == AppTheme::Dark)
        {
            ListView_SetBkColor(data->hList, tc.bg_control);
            ListView_SetTextBkColor(data->hList, tc.bg_control);
            ListView_SetTextColor(data->hList, tc.text_normal);
        }
        else
        {
            ListView_SetBkColor(data->hList, RGB(255, 255, 255));
            ListView_SetTextBkColor(data->hList, RGB(255, 255, 255));
            ListView_SetTextColor(data->hList, RGB(20, 20, 20));
        }

        refresh_process_list(data);
        populate_attach_listview(data);

        SetFocus(data->hEditSearch);
        return 0;
    }

    case WM_SIZE:
    {
        if (data && data->hList)
        {
            int cw = LOWORD(lp);
            int ch = HIWORD(lp);
            if (cw >= 400 && ch >= 250)
            {
                int search_w = cw - 12 - 58 - 250 - 90 - 24;
                if (search_w < 160) search_w = 160;
                MoveWindow(data->hEditSearch, 68, 12, search_w, 24, TRUE);
                MoveWindow(data->hChkWindowsOnly, 68 + search_w + 12, 12, 240, 24, TRUE);
                MoveWindow(data->hBtnRefresh, cw - 12 - 80, 12, 80, 24, TRUE);

                int list_y = 44;
                int list_h = ch - list_y - 44;
                if (list_h < 100) list_h = 100;
                MoveWindow(data->hList, 12, list_y, cw - 24, list_h, TRUE);

                int btm_y = ch - 34;
                MoveWindow(data->hLblStatus, 12, btm_y + 3, cw - 24 - 190, 22, TRUE);
                MoveWindow(data->hBtnAttach, cw - 12 - 180, btm_y, 85, 26, TRUE);
                MoveWindow(data->hBtnCancel, cw - 12 - 85, btm_y, 85, 26, TRUE);
            }
        }
        return 0;
    }

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO *mmi = reinterpret_cast<MINMAXINFO*>(lp);
        mmi->ptMinTrackSize.x = 680;
        mmi->ptMinTrackSize.y = 400;
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
        if (id == ID_ATTACH_SEARCH && code == EN_CHANGE)
        {
            if (data) populate_attach_listview(data);
        }
        else if (id == ID_ATTACH_WINDOWS_ONLY)
        {
            if (data) populate_attach_listview(data);
        }
        else if (id == ID_ATTACH_BTN_REFRESH)
        {
            if (data)
            {
                refresh_process_list(data);
                populate_attach_listview(data);
            }
        }
        else if (id == ID_ATTACH_BTN_ATTACH || id == IDOK)
        {
            if (data) on_attach_confirm(hwnd, data);
        }
        else if (id == ID_ATTACH_BTN_CANCEL || id == IDCANCEL)
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR *nm = reinterpret_cast<NMHDR*>(lp);
        if (nm && nm->idFrom == ID_ATTACH_LIST && data)
        {
            if (nm->code == NM_DBLCLK)
            {
                on_attach_confirm(hwnd, data);
                return 0;
            }
            else if (nm->code == LVN_COLUMNCLICK)
            {
                NMLISTVIEW *nmlv = reinterpret_cast<NMLISTVIEW*>(lp);
                int col = nmlv->iSubItem;
                if (data->sort_column == col)
                {
                    data->sort_asc = !data->sort_asc;
                }
                else
                {
                    data->sort_column = col;
                    data->sort_asc = true;
                }
                sort_process_entries(data);
                populate_attach_listview(data);
                return 0;
            }
        }
        break;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

void open_attach_process_dialog(HWND hParent)
{
    AttachDialogData state;

    RECT parent_rc = {};
    GetWindowRect(hParent, &parent_rc);
    int dlg_w = 860, dlg_h = 560;
    int dlg_x = parent_rc.left + (parent_rc.right - parent_rc.left - dlg_w) / 2;
    int dlg_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - dlg_h) / 2;
    if (dlg_x < 10) dlg_x = 10;
    if (dlg_y < 10) dlg_y = 10;

    HWND hwnd_dlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME,
        "DeadeyeAttachDlg",
        "Attach to Process - Deadeye",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_VISIBLE,
        dlg_x, dlg_y, dlg_w, dlg_h,
        hParent, nullptr, GetModuleHandleA(nullptr), &state);

    if (hwnd_dlg == nullptr)
        return;

    EnableWindow(hParent, FALSE);

    MSG msg;
    while (IsWindow(hwnd_dlg) && GetMessageA(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_KEYDOWN)
        {
            if (msg.wParam == VK_ESCAPE)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, IDCANCEL, 0);
                continue;
            }
            if (msg.wParam == VK_RETURN)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, IDOK, 0);
                continue;
            }
            if (msg.wParam == VK_F5)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, ID_ATTACH_BTN_REFRESH, 0);
                continue;
            }
            if (msg.wParam == VK_DOWN && GetFocus() == state.hEditSearch)
            {
                SetFocus(state.hList);
                continue;
            }
        }
        if (!IsDialogMessageA(hwnd_dlg, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);

    if (state.confirmed && state.selected_pid != 0)
    {
        std::string pid_str = std::to_string(state.selected_pid);
        if (g_edit_pid != nullptr)
        {
            SetWindowTextA(g_edit_pid, pid_str.c_str());
        }

        std::string msg_text = "Attaching to " + state.selected_name + " (PID " + pid_str + ")...";
        set_status(msg_text);

        PostMessageA(hParent, WM_COMMAND, ID_BTN_TRIAGE, 0);
    }
}


struct PeMapDlgState
{
    bool confirmed = false;
    uintptr_t base_address = 0;
    bool apply_relocs = true;
    HWND h_edit_base = nullptr;
    HWND h_chk_relocs = nullptr;
};

static LRESULT CALLBACK PeMapDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    PeMapDlgState *state = reinterpret_cast<PeMapDlgState *>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA *>(lp);
        state = reinterpret_cast<PeMapDlgState *>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

        HWND lbl1 = CreateWindowExA(0, "STATIC", "Target Virtual Base Address (hex):",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 16, 380, 20, hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
        SendMessageA(lbl1, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        char base_str[32];
        std::snprintf(base_str, sizeof(base_str), "0x%016llX", static_cast<unsigned long long>(state->base_address));

        state->h_edit_base = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", base_str,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            20, 40, 380, 26, hwnd, reinterpret_cast<HMENU>(101), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(state->h_edit_base, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        state->h_chk_relocs = CreateWindowExA(0, "BUTTON", "Apply base relocations (if mapped base != ImageBase)",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            20, 78, 380, 24, hwnd, reinterpret_cast<HMENU>(102), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(state->h_chk_relocs, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageA(state->h_chk_relocs, BM_SETCHECK, state->apply_relocs ? BST_CHECKED : BST_UNCHECKED, 0);

        HWND btn_ok = CreateWindowExA(0, "BUTTON", "OK",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            195, 120, 95, 30, hwnd, reinterpret_cast<HMENU>(IDOK), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(btn_ok, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font_bold ? g_ui_font_bold : g_ui_font), TRUE);

        HWND btn_cancel = CreateWindowExA(0, "BUTTON", "Cancel",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            305, 120, 95, 30, hwnd, reinterpret_cast<HMENU>(IDCANCEL), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(btn_cancel, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        SetFocus(state->h_edit_base);
        SendMessageA(state->h_edit_base, EM_SETSEL, 0, -1);
        return 0;
    }
    case WM_COMMAND:
    {
        WORD id = LOWORD(wp);
        if (id == IDOK)
        {
            if (state != nullptr)
            {
                char buf[64] = {};
                GetWindowTextA(state->h_edit_base, buf, sizeof(buf));
                std::string s(buf);
                uintptr_t val = 0;
                try
                {
                    val = std::stoull(s, nullptr, 16);
                }
                catch (...)
                {
                    MessageBoxA(hwnd, "Invalid hexadecimal base address. Please enter a valid hex address (e.g. 0x140000000).", "Invalid Address", MB_OK | MB_ICONWARNING);
                    return 0;
                }
                state->base_address = val;
                state->apply_relocs = (SendMessageA(state->h_chk_relocs, BM_GETCHECK, 0, 0) == BST_CHECKED);
                state->confirmed = true;
            }
            DestroyWindow(hwnd);
            return 0;
        }
        else if (id == IDCANCEL)
        {
            if (state != nullptr) state->confirmed = false;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        if (state != nullptr) state->confirmed = false;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

bool show_pe_map_options_dialog(HWND parent, uintptr_t default_base, uintptr_t &out_base, bool &out_apply_relocs)
{
    static bool registered = false;
    static const char *CLASS_NAME = "DeadeyePeMapDlg";
    if (!registered)
    {
        WNDCLASSA wc = {};
        wc.lpfnWndProc = PeMapDlgProc;
        wc.hInstance = GetModuleHandleA(nullptr);
        wc.lpszClassName = CLASS_NAME;
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
        RegisterClassA(&wc);
        registered = true;
    }

    PeMapDlgState state;
    state.base_address = default_base;
    state.apply_relocs = true;

    RECT rc_parent = {};
    GetWindowRect(parent, &rc_parent);
    int dlg_w = 440;
    int dlg_h = 210;
    int dlg_x = rc_parent.left + (rc_parent.right - rc_parent.left - dlg_w) / 2;
    int dlg_y = rc_parent.top + (rc_parent.bottom - rc_parent.top - dlg_h) / 2;

    HWND hwnd_dlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        CLASS_NAME,
        "Deadeye - Map PE In-Memory Layout",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        dlg_x, dlg_y, dlg_w, dlg_h,
        parent, nullptr, GetModuleHandleA(nullptr), &state);

    if (hwnd_dlg == nullptr)
        return false;

    EnableWindow(parent, FALSE);

    MSG msg;
    while (IsWindow(hwnd_dlg) && GetMessageA(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_KEYDOWN)
        {
            if (msg.wParam == VK_ESCAPE)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, IDCANCEL, 0);
                continue;
            }
            if (msg.wParam == VK_RETURN)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, IDOK, 0);
                continue;
            }
        }
        if (!IsDialogMessageA(hwnd_dlg, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);

    if (state.confirmed)
    {
        out_base = state.base_address;
        out_apply_relocs = state.apply_relocs;
        return true;
    }
    return false;
}

void on_open_memory_source()
{
    char file_buf[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "Executable & Binary Files (*.exe;*.dll;*.sys;*.bin;*.*)\0*.exe;*.dll;*.sys;*.bin;*.*\0PE Files (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.lpstrTitle = "Open Executable or Binary File";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameA(&ofn))
    {
        return;
    }

    std::string filepath(file_buf);
    uintptr_t pe_base = 0;
    bool is_pe = false;
    get_pe_default_base(filepath, pe_base, is_pe);

    std::shared_ptr<MemorySource> new_source = nullptr;
    std::string load_err;

    if (is_pe)
    {
        int choice = MessageBoxA(
            g_hwnd_main,
            "This file has a valid Portable Executable (PE) signature.\n\n"
            "Would you like to map it as an in-memory image layout according to its PE headers?\n\n"
            "• Click YES to map sections at virtual addresses (loader layout)\n"
            "• Click NO to open as flat raw bytes (one contiguous region)\n"
            "• Click CANCEL to abort",
            "Deadeye - Open Memory Source",
            MB_YESNOCANCEL | MB_ICONQUESTION);

        if (choice == IDCANCEL)
        {
            return;
        }

        if (choice == IDYES)
        {
            uintptr_t chosen_base = pe_base;
            bool apply_relocs = true;
            if (!show_pe_map_options_dialog(g_hwnd_main, pe_base, chosen_base, apply_relocs))
            {
                return;
            }

            new_source = MappedPeSource::open(filepath, chosen_base, apply_relocs, load_err);
            if (!new_source)
            {
                MessageBoxA(g_hwnd_main, ("Failed to map PE: " + load_err).c_str(), "Deadeye - PE Loader Error", MB_OK | MB_ICONERROR);
                return;
            }
        }
        else
        {
            new_source = RawFileSource::open(filepath, 0x100000000ULL, load_err);
            if (!new_source)
            {
                MessageBoxA(g_hwnd_main, ("Failed to open file: " + load_err).c_str(), "Deadeye - Raw File Error", MB_OK | MB_ICONERROR);
                return;
            }
        }
    }
    else
    {
        new_source = RawFileSource::open(filepath, 0x100000000ULL, load_err);
        if (!new_source)
        {
            MessageBoxA(g_hwnd_main, ("Failed to open raw file: " + load_err).c_str(), "Deadeye - Raw File Error", MB_OK | MB_ICONERROR);
            return;
        }
    }

    g_current_source = new_source;
    g_current_pid = 0;
    close_target_proc();

    if (g_chk_heartbeat)
    {
        SendMessageA(g_chk_heartbeat, BM_SETCHECK, BST_UNCHECKED, 0);
        EnableWindow(g_chk_heartbeat, FALSE);
    }
    KillTimer(g_hwnd_main, IDT_HEARTBEAT);

    std::string desc = g_current_source->describe();
    SetWindowTextA(g_hwnd_main, ("Deadeye - [" + desc + "]").c_str());
    SetWindowTextA(g_edit_pid, desc.c_str());

    g_regions.clear();
    std::string q_err;
    if (!g_current_source->query_regions(g_regions, q_err))
    {
        MessageBoxA(g_hwnd_main, ("Error querying regions: " + q_err).c_str(), "Deadeye - Error", MB_OK | MB_ICONERROR);
        return;
    }

    invalidate_hex_cache();

    g_triage_report = run_source_triage(g_current_source, g_regions);

    PeSummaryInfo pe_summary;
    if (g_current_source->get_pe_summary(pe_summary))
    {
        SetWindowTextA(g_lbl_triage_reasons, format_pe_summary(pe_summary).c_str());
    }

    g_view_mode = ViewMode::TriageFindings;
    if (g_combo_view_mode)
    {
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);
    }
    populate_region_list();

    if (!g_visible_indices.empty())
    {
        select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
    }
    else
    {
        g_has_selection = false;
        SetWindowTextA(g_edit_hex, "");
        update_diff_combo();
    }

    size_t crit = 0, high = 0, med = 0, low = 0;
    for (const auto &f : g_triage_report.findings)
    {
        if (f.severity_label == "CRIT") crit++;
        else if (f.severity_label == "HIGH") high++;
        else if (f.severity_label == "MED") med++;
        else if (f.severity_label == "LOW") low++;
    }

    char status[320];
    std::snprintf(status, sizeof(status),
                  "%s: %zu sections/regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW [Static PE Rules]",
                  desc.c_str(), g_regions.size(), crit, high, med, low);
    set_status(status);
}

HMENU create_application_menu()
{
    HMENU hMenuBar = CreateMenu();

    // 1. File Menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_ATTACH, "&Attach to Process...\tCtrl+A");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_OPEN_SOURCE, "&Open Memory Source...\tCtrl+O");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_TRIAGE, "Run Defensive &Triage\tCtrl+T");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXPORT_JSON, "&Export Triage JSON...\tCtrl+S");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);

    HMENU hThemeMenu = CreatePopupMenu();
    AppendMenuA(hThemeMenu, MF_STRING, IDM_FILE_THEME_LIGHT, "&Light Mode");
    AppendMenuA(hThemeMenu, MF_STRING, IDM_FILE_THEME_DARK, "&Dark Mode");
    AppendMenuA(hFileMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hThemeMenu), "&Theme");

    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "E&xit\tAlt+F4");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), "&File");

    // 2. Edit Menu
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_ADDR, "&Copy Region Address\tCtrl+C");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_HEX, "Copy &Hex Dump\tCtrl+Shift+C");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_PATTERN, "&Find Hex Pattern...\tCtrl+F");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_NEXT, "Find &Next Hit\tF3");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_GENERATE_YARA, "Generate &YARA Rule from Selection...\tCtrl+Y");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hEditMenu), "&Edit");

    // 3. View Menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_TRIAGE_FINDINGS, "&Triage Findings View\tCtrl+1");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MEMORY_MAP, "&Memory Map View\tCtrl+2");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_BEHAVIOR, "&Behavior Tracker View\tCtrl+3");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_STRINGS, "&Strings View\tCtrl+4");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_PROCESS_DIFF, "&Process Diff View\tCtrl+5");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_HIDE_CLEAN, "&Hide Clean Regions");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_HITS_ONLY, "&Hits Only Filter");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_REFRESH, "&Refresh Memory Walk\tF5");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hViewMenu), "&View");

    // 4. Behavior Menu
    HMENU hBehaviorMenu = CreatePopupMenu();
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_BEHAVIOR_PIN, "&Pin / Unpin Selected Region\tCtrl+P");
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_BEHAVIOR_WATCH_ALL_PRIV, "Watch &All Private Executable Regions");
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_BEHAVIOR_CLEAR, "&Clear Sample History");
    AppendMenuA(hBehaviorMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_HELP_BEHAVIOR_LIMITS, "Polling &Limitations & Detection Guide...");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hBehaviorMenu), "&Behavior");

    // 5. Strings Menu
    HMENU hStringsMenu = CreatePopupMenu();
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_BASELINE, "Set String &Baseline\tCtrl+B");
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_TOGGLE_NEW, "Toggle &New Since Baseline Filter\tF6");
    AppendMenuA(hStringsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_EXTRACT_SEL, "Extract Strings from &Selected Region\tF7");
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_EXTRACT_ALL, "Extract Strings across &All Regions");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hStringsMenu), "&Strings");

    // 6. Diff Menu
    HMENU hDiffMenu = CreatePopupMenu();
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_CAPTURE_BASELINE, "Capture &Baseline Snapshot\tCtrl+B");
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_CAPTURE_CURRENT, "Compare with &Current (Diff)\tCtrl+D");
    AppendMenuA(hDiffMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_SAVE_SESSION, "&Save Diff Session to JSON...");
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_LOAD_SESSION, "&Load Diff Session from JSON...");
    AppendMenuA(hDiffMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_VIEW_STRINGS, "View Newly &Revealed Strings...\tCtrl+U");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDiffMenu), "&Diff");

    // 7. Timeline Menu
    HMENU hTimelineMenu = CreatePopupMenu();
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_SNAP, "&Take Snapshot\tCtrl+N");
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_CLEAR, "&Clear All Snapshots");
    AppendMenuA(hTimelineMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_HEARTBEAT, "&Live Memory Heartbeat (1s)");
    AppendMenuA(hTimelineMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_PREV_PAGE, "&Previous 64K Page\tPgUp");
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_NEXT_PAGE, "&Next 64K Page\tPgDn");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hTimelineMenu), "&Timeline");

    // 8. Help Menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_HEURISTICS, "&Defensive Heuristics Guide...");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_BEHAVIOR_LIMITS, "&Behavior Polling Limitations...");
    AppendMenuA(hHelpMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "&About Deadeye...");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelpMenu), "&Help");

    return hMenuBar;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_hwnd_main = hwnd;
        HINSTANCE hInst = GetModuleHandleA(nullptr);

        g_ui_font = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_ui_font_bold = CreateFontA(15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_mono_font = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        update_theme_brushes();

        const int M = 8, RH = 24;
        int x = M;

        // Row 1: Top Bar
        HWND lbl_pid = CreateWindowA("STATIC", "PID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 28, RH, hwnd, nullptr, hInst, nullptr);
        x += 30;

        g_edit_pid = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                   x, M, 56, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PID), hInst, nullptr);
        x += 60;

        g_btn_attach = CreateWindowA("BUTTON", "Attach...",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     x, M, 66, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_ATTACH), hInst, nullptr);
        x += 70;

        g_btn_load = CreateWindowA("BUTTON", "Load",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 48, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_LOAD), hInst, nullptr);
        x += 52;

        g_btn_triage = CreateWindowA("BUTTON", "Triage",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     x, M, 58, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_TRIAGE), hInst, nullptr);
        x += 64;

        HWND lbl_pat = CreateWindowA("STATIC", "Search Hex:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 76, RH, hwnd, nullptr, hInst, nullptr);
        x += 78;

        g_edit_pattern = CreateWindowA("EDIT", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                       x, M, 200, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PATTERN), hInst, nullptr);
        x += 204;

        g_btn_search = CreateWindowA("BUTTON", "Search",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     x, M, 58, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SEARCH), hInst, nullptr);
        x += 62;

        g_btn_next_hit = CreateWindowA("BUTTON", "Next Hit",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                                       x, M, 66, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_HIT), hInst, nullptr);
        x += 70;

        g_chk_hits_only = CreateWindowA("BUTTON", "Hits only",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 78, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HITS_ONLY), hInst, nullptr);
        x += 82;

        g_chk_heartbeat = CreateWindowA("BUTTON", "Heartbeat (1s)",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 110, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HEARTBEAT), hInst, nullptr);
        x += 114;

        g_btn_diff_proc = CreateWindowA("BUTTON", "Diff Proc",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                        x, M, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_DIFF_PROC), hInst, nullptr);
        x += 78;

        g_btn_yara = CreateWindowA("BUTTON", "YARA Rule",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 78, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_YARA), hInst, nullptr);

        // Row 2: Filter Bar (Left side) & Hex Timeline Bar (Right side)
        int r2_y = M + RH + 6;

        g_combo_view_mode = CreateWindowA("COMBOBOX", "",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                          M, r2_y, 168, 160, hwnd, reinterpret_cast<HMENU>(ID_COMBO_VIEW_MODE), hInst, nullptr);
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Triage Findings"));
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Memory Map"));
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Behavior Tracker"));
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Strings"));
        SendMessageA(g_combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Process Diff"));
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);

        g_combo_min_sev = CreateWindowA("COMBOBOX", "",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                        M + 172, r2_y, 102, 140, hwnd, reinterpret_cast<HMENU>(ID_COMBO_MIN_SEV), hInst, nullptr);
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: All (0+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Low (10+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Med (25+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: High (50+)"));
        SendMessageA(g_combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Crit (80+)"));
        SendMessageA(g_combo_min_sev, CB_SETCURSEL, 0, 0);

        g_chk_hide_clean = CreateWindowA("BUTTON", "Hide clean",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                         M + 278, r2_y, 84, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HIDE_CLEAN), hInst, nullptr);

        g_btn_export_json = CreateWindowA("BUTTON", "Export JSON",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          M + 366, r2_y, 88, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_EXPORT_JSON), hInst, nullptr);

        // Right side timeline header controls
        g_lbl_hex_info = CreateWindowA("STATIC", "Hex View",
                                       WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                       442, r2_y, 300, RH, hwnd, nullptr, hInst, nullptr);

        g_btn_snap = CreateWindowA("BUTTON", "+ Snap",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                   0, 0, 68, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SNAP), hInst, nullptr);
        g_combo_diff = CreateWindowA("COMBOBOX", "",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL | WS_DISABLED,
                                     0, 0, 142, 160, hwnd, reinterpret_cast<HMENU>(ID_COMBO_DIFF), hInst, nullptr);
        g_btn_clear_snaps = CreateWindowA("BUTTON", "Clear",
                                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                          0, 0, 50, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_CLEAR_SNAPS), hInst, nullptr);
        g_btn_prev_page = CreateWindowA("BUTTON", "< Prev 64K",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_PREV_PAGE), hInst, nullptr);
        g_btn_next_page = CreateWindowA("BUTTON", "Next 64K >",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_PAGE), hInst, nullptr);

        // Main Panes: Left Owner-Drawn ListBox & Right Hex Edit View
        g_list_regions = CreateWindowA("LISTBOX", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                           WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                                       M, 66, 434, 400, hwnd, reinterpret_cast<HMENU>(ID_LIST_REGIONS), hInst, nullptr);

        g_edit_hex = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                       WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                   442, 66, 500, 400, hwnd, reinterpret_cast<HMENU>(ID_EDIT_HEX), hInst, nullptr);
        SendMessageA(g_edit_hex, EM_SETLIMITTEXT, 0, 0);

        // Details label and Status bar
        g_lbl_triage_reasons = CreateWindowA("STATIC", "Details: Ready.",
                                             WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                             M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        g_lbl_status = CreateWindowA("STATIC", "Ready.",
                                     WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                     M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        HWND ui_items[] = {
            lbl_pid, g_edit_pid, g_btn_attach, g_btn_load, g_btn_triage, lbl_pat, g_edit_pattern, g_btn_search,
            g_btn_next_hit, g_chk_hits_only, g_chk_heartbeat, g_btn_diff_proc, g_btn_yara,
            g_combo_view_mode, g_combo_min_sev, g_chk_hide_clean, g_btn_export_json,
            g_lbl_hex_info, g_btn_snap, g_combo_diff, g_btn_clear_snaps,
            g_btn_prev_page, g_btn_next_page, g_lbl_triage_reasons, g_lbl_status};
        for (size_t i = 0; i < sizeof(ui_items) / sizeof(ui_items[0]); ++i)
        {
            SendMessageA(ui_items[i], WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }
        SendMessageA(g_edit_hex, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

        // Modernize all push buttons with sleek flat rounded styling and interactive hover effects
        make_button_modern(g_btn_triage, ModernButtonStyle::Primary);
        make_button_modern(g_btn_export_json, ModernButtonStyle::Accent);
        make_button_modern(g_btn_attach, ModernButtonStyle::Accent);
        make_button_modern(g_btn_load, ModernButtonStyle::Standard);
        make_button_modern(g_btn_search, ModernButtonStyle::Standard);
        make_button_modern(g_btn_next_hit, ModernButtonStyle::Standard);
        make_button_modern(g_btn_snap, ModernButtonStyle::Standard);
        make_button_modern(g_btn_clear_snaps, ModernButtonStyle::Standard);
        make_button_modern(g_btn_prev_page, ModernButtonStyle::Standard);
        make_button_modern(g_btn_next_page, ModernButtonStyle::Standard);
        make_button_modern(g_btn_diff_proc, ModernButtonStyle::Accent);
        make_button_modern(g_btn_yara, ModernButtonStyle::Primary);

        // Attach application menu bar
        HMENU hMenu = create_application_menu();
        SetMenu(hwnd, hMenu);

        // Build global keyboard accelerators
        ACCEL accels[] = {
            { FCONTROL | FVIRTKEY, 'A', IDM_FILE_ATTACH },
            { FCONTROL | FVIRTKEY, 'O', IDM_FILE_OPEN_SOURCE },
            { FCONTROL | FVIRTKEY, 'T', ID_BTN_TRIAGE },
            { FCONTROL | FVIRTKEY, 'S', ID_BTN_EXPORT_JSON },
            { FCONTROL | FVIRTKEY, 'F', IDM_EDIT_FIND_PATTERN },
            { FVIRTKEY, VK_F3, ID_BTN_NEXT_HIT },
            { FVIRTKEY, VK_F5, ID_BTN_LOAD },
            { FCONTROL | FVIRTKEY, 'C', IDM_EDIT_COPY_ADDR },
            { FCONTROL | FSHIFT | FVIRTKEY, 'C', IDM_EDIT_COPY_HEX },
            { FCONTROL | FVIRTKEY, 'N', ID_BTN_SNAP },
            { FCONTROL | FVIRTKEY, '1', IDM_VIEW_TRIAGE_FINDINGS },
            { FCONTROL | FVIRTKEY, '2', IDM_VIEW_MEMORY_MAP },
            { FCONTROL | FVIRTKEY, '3', IDM_VIEW_BEHAVIOR },
            { FCONTROL | FVIRTKEY, '4', IDM_VIEW_STRINGS },
            { FCONTROL | FVIRTKEY, '5', IDM_VIEW_PROCESS_DIFF },
            { FCONTROL | FVIRTKEY, 'P', IDM_BEHAVIOR_PIN },
            { FCONTROL | FVIRTKEY, 'B', IDM_STRINGS_BASELINE },
            { FVIRTKEY, VK_F6, IDM_STRINGS_TOGGLE_NEW },
            { FVIRTKEY, VK_F7, IDM_STRINGS_EXTRACT_SEL },
            { FCONTROL | FVIRTKEY, 'D', IDM_DIFF_CAPTURE_CURRENT },
            { FCONTROL | FVIRTKEY, 'Y', ID_BTN_YARA },
            { FCONTROL | FVIRTKEY, 'U', IDM_DIFF_VIEW_STRINGS }
        };
        g_haccel = CreateAcceleratorTableA(accels, sizeof(accels) / sizeof(accels[0]));

        if (GetWindowTextLengthA(g_edit_pid) > 0)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_TRIAGE, 0);
        }
        else
        {
            set_status("Ready. Enter target PID and click 'Triage Findings'.");
        }
        return 0;
    }

    case WM_INITMENUPOPUP:
    {
        HMENU hMenu = reinterpret_cast<HMENU>(wp);
        CheckMenuItem(hMenu, IDM_FILE_THEME_LIGHT, (g_theme == AppTheme::Light) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_FILE_THEME_DARK, (g_theme == AppTheme::Dark) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_TRIAGE_FINDINGS, (g_view_mode == ViewMode::TriageFindings) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_MEMORY_MAP, (g_view_mode == ViewMode::MemoryMap) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_BEHAVIOR, (g_view_mode == ViewMode::BehaviorTracker) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_STRINGS, (g_view_mode == ViewMode::StringsView) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_PROCESS_DIFF, (g_view_mode == ViewMode::ProcessDiff) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_BEHAVIOR_WATCH_ALL_PRIV, g_tracker_watch_all_priv_exec.load() ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_STRINGS_TOGGLE_NEW, g_strings_filter_new_only ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_HIDE_CLEAN, g_hide_clean ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_HITS_ONLY, (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_TIMELINE_HEARTBEAT, (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED) ? MF_CHECKED : MF_UNCHECKED);
        return 0;
    }

    case WM_MEASUREITEM:
    {
        MEASUREITEMSTRUCT *mis = reinterpret_cast<MEASUREITEMSTRUCT *>(lp);
        if (mis->CtlID == ID_LIST_REGIONS)
        {
            mis->itemHeight = 20; // Row height
            return TRUE;
        }
        break;
    }

    case WM_DRAWITEM:
    {
        DRAWITEMSTRUCT *dis = reinterpret_cast<DRAWITEMSTRUCT *>(lp);
        if (dis->CtlID == ID_LIST_REGIONS)
        {
            draw_region_list_item(dis);
            return TRUE;
        }
        break;
    }

    case WM_CTLCOLOREDIT:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        HWND hctl = reinterpret_cast<HWND>(lp);
        const ThemeColors &tc = get_current_theme();
        if (hctl == g_edit_hex)
        {
            SetTextColor(hdc, tc.text_normal);
            SetBkColor(hdc, tc.bg_control);
            return reinterpret_cast<INT_PTR>(g_br_control);
        }
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_window);
        return reinterpret_cast<INT_PTR>(g_br_window);
    }

    case WM_CTLCOLORLISTBOX:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
        return 1;
    }

    case WM_SIZE:
    {
        int w = LOWORD(lp);
        int h = HIWORD(lp);
        const int M = 8, RH = 24;

        int list_w = 434;
        if (w < 880)
            list_w = w / 2 - M;

        int right_x = M + list_w + M;
        int right_w = w - right_x - M;
        if (right_w < 120)
            right_w = 120;

        int r2_y = M + RH + 6;
        int pane_top = r2_y + RH + 6;
        int pane_h = h - pane_top - 46;
        if (pane_h < 60)
            pane_h = 60;

        int cur_r = w - M;
        int btn_next_x = cur_r - 74;
        cur_r -= 78;
        int btn_prev_x = cur_r - 74;
        cur_r -= 78;
        int btn_clr_x = cur_r - 50;
        cur_r -= 54;
        int combo_x = cur_r - 142;
        cur_r -= 146;
        int btn_snap_x = cur_r - 68;
        cur_r -= 72;
        int info_w = btn_snap_x - right_x - 6;
        if (info_w < 50)
            info_w = 50;

        MoveWindow(g_lbl_hex_info, right_x, r2_y, info_w, RH, TRUE);
        MoveWindow(g_btn_snap, btn_snap_x, r2_y, 68, RH, TRUE);
        MoveWindow(g_combo_diff, combo_x, r2_y, 142, 160, TRUE);
        MoveWindow(g_btn_clear_snaps, btn_clr_x, r2_y, 50, RH, TRUE);
        MoveWindow(g_btn_prev_page, btn_prev_x, r2_y, 74, RH, TRUE);
        MoveWindow(g_btn_next_page, btn_next_x, r2_y, 74, RH, TRUE);

        MoveWindow(g_list_regions, M, pane_top, list_w, pane_h, TRUE);
        MoveWindow(g_edit_hex, right_x, pane_top, right_w, pane_h, TRUE);

        MoveWindow(g_lbl_triage_reasons, M, h - 42, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
        MoveWindow(g_lbl_status, M, h - 22, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);

        if (id == ID_BTN_ATTACH)
        {
            open_attach_process_dialog(hwnd);
        }
        else if (id == IDM_FILE_ATTACH)
        {
            HWND focus = GetFocus();
            if (focus == g_edit_pattern || focus == g_edit_hex || focus == g_edit_pid)
            {
                SendMessageA(focus, EM_SETSEL, 0, -1);
            }
            else
            {
                open_attach_process_dialog(hwnd);
            }
        }
        else if (id == ID_BTN_LOAD)
        {
            start_worker_task(WorkerTaskType::MemoryMapScan, false);
        }
        else if (id == ID_BTN_TRIAGE)
        {
            start_worker_task(WorkerTaskType::Triage, false);
        }
        else if (id == ID_BTN_SEARCH || id == IDOK)
        {
            if (GetFocus() == g_edit_pid)
            {
                start_worker_task(WorkerTaskType::Triage, false);
            }
            else
            {
                start_worker_task(WorkerTaskType::MemoryMapScan, true);
            }
        }
        else if (id == ID_BTN_NEXT_HIT)
        {
            on_next_hit();
        }
        else if (id == ID_BTN_EXPORT_JSON)
        {
            on_export_json();
        }
        else if (id == ID_COMBO_VIEW_MODE && code == CBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(g_combo_view_mode, CB_GETCURSEL, 0, 0);
            if (sel == 4)
                g_view_mode = ViewMode::ProcessDiff;
            else if (sel == 3)
                g_view_mode = ViewMode::StringsView;
            else if (sel == 2)
                g_view_mode = ViewMode::BehaviorTracker;
            else if (sel == 1)
                g_view_mode = ViewMode::MemoryMap;
            else
                g_view_mode = ViewMode::TriageFindings;

            populate_region_list();
            if (g_view_mode == ViewMode::ProcessDiff)
            {
                if (!g_visible_indices.empty())
                {
                    SendMessageA(g_list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(0);
                }
                else
                {
                    SetWindowTextA(g_lbl_triage_reasons, "Diff Details: No diffs. Click Diff Proc to compare.");
                }
            }
            else if (g_view_mode == ViewMode::BehaviorTracker)
            {
                if (!g_visible_indices.empty())
                {
                    SendMessageA(g_list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(0);
                    uintptr_t target_base = g_watched_regions[g_visible_indices[0]].key.base;
                    for (size_t r = 0; r < g_regions.size(); ++r)
                    {
                        if (g_regions[r].base == target_base)
                        {
                            g_selected_region = r;
                            g_has_selection = true;
                            g_view_offset = 0;
                            display_selected_region(static_cast<SIZE_T>(-1));
                            break;
                        }
                    }
                }
                else
                {
                    SetWindowTextA(g_lbl_triage_reasons, "Behavior Details: No regions watched. Attach live process and run triage, or press Ctrl+P to pin.");
                }
            }
            else if (g_view_mode == ViewMode::StringsView)
            {
                if (!g_visible_indices.empty())
                {
                    SendMessageA(g_list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(g_visible_indices[0]);
                    const auto &st = g_extracted_strings[g_visible_indices[0]];
                    for (size_t r = 0; r < g_regions.size(); ++r)
                    {
                        if (st.addr >= g_regions[r].base && st.addr < g_regions[r].base + g_regions[r].size)
                        {
                            g_selected_region = r;
                            g_has_selection = true;
                            SIZE_T rel_off = st.addr - g_regions[r].base;
                            g_view_offset = (rel_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                            display_selected_region(rel_off);
                            break;
                        }
                    }
                }
                else
                {
                    SetWindowTextA(g_lbl_triage_reasons, "Strings Details: No strings extracted. Press F7 to extract from selected region.");
                }
            }
            else
            {
                if (!g_visible_indices.empty())
                {
                    select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
                }
                else
                {
                    g_has_selection = false;
                    update_diff_combo();
                    display_selected_region(static_cast<SIZE_T>(-1));
                    SetWindowTextA(g_lbl_triage_reasons, "Details: Ready.");
                }
            }
        }
        else if (id == ID_COMBO_MIN_SEV && code == CBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(g_combo_min_sev, CB_GETCURSEL, 0, 0);
            if (sel == 1)
                g_min_sev_filter = SEV_MIN_LOW;
            else if (sel == 2)
                g_min_sev_filter = SEV_MIN_MEDIUM;
            else if (sel == 3)
                g_min_sev_filter = SEV_MIN_HIGH;
            else if (sel == 4)
                g_min_sev_filter = SEV_MIN_CRITICAL;
            else
                g_min_sev_filter = 0;
            populate_region_list();
        }
        else if (id == ID_CHK_HIDE_CLEAN)
        {
            g_hide_clean = (SendMessageA(g_chk_hide_clean, BM_GETCHECK, 0, 0) == BST_CHECKED);
            populate_region_list();
        }
        else if (id == ID_CHK_HITS_ONLY)
        {
            populate_region_list();
            if (!g_visible_indices.empty())
            {
                select_region_in_ui(g_visible_indices[0], 0, static_cast<SIZE_T>(-1));
            }
            else
            {
                g_has_selection = false;
                update_diff_combo();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_LIST_REGIONS && code == LBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(g_list_regions, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && static_cast<size_t>(sel) < g_visible_indices.size())
            {
                size_t reg_idx = g_visible_indices[static_cast<size_t>(sel)];
                if (g_view_mode == ViewMode::ProcessDiff)
                {
                    if (reg_idx < g_process_diffs.size())
                    {
                        update_triage_details_label(reg_idx);
                        uintptr_t target_base = g_process_diffs[reg_idx].base;
                        for (size_t r = 0; r < g_regions.size(); ++r)
                        {
                            if (g_regions[r].base == target_base)
                            {
                                g_selected_region = r;
                                g_has_selection = true;
                                g_view_offset = 0;
                                display_selected_region(static_cast<SIZE_T>(-1));
                                break;
                            }
                        }
                    }
                }
                else if (g_view_mode == ViewMode::BehaviorTracker)
                {
                    if (reg_idx < g_watched_regions.size())
                    {
                        update_triage_details_label(reg_idx);
                        uintptr_t target_base = g_watched_regions[reg_idx].key.base;
                        for (size_t r = 0; r < g_regions.size(); ++r)
                        {
                            if (g_regions[r].base == target_base)
                            {
                                g_selected_region = r;
                                g_has_selection = true;
                                g_view_offset = 0;
                                display_selected_region(static_cast<SIZE_T>(-1));
                                break;
                            }
                        }
                    }
                }
                else if (g_view_mode == ViewMode::StringsView)
                {
                    if (reg_idx < g_extracted_strings.size())
                    {
                        update_triage_details_label(reg_idx);
                        const auto &st = g_extracted_strings[reg_idx];
                        for (size_t r = 0; r < g_regions.size(); ++r)
                        {
                            if (st.addr >= g_regions[r].base && st.addr < g_regions[r].base + g_regions[r].size)
                            {
                                g_selected_region = r;
                                g_has_selection = true;
                                SIZE_T rel_off = st.addr - g_regions[r].base;
                                g_view_offset = (rel_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                                display_selected_region(rel_off);
                                break;
                            }
                        }
                    }
                }
                else
                {
                    if (reg_idx < g_regions.size())
                    {
                        SIZE_T first_hit = g_regions[reg_idx].hits.empty()
                                               ? static_cast<SIZE_T>(-1)
                                               : g_regions[reg_idx].hits[0];
                        SIZE_T page_off = (first_hit == static_cast<SIZE_T>(-1))
                                              ? 0
                                              : (first_hit / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                        g_selected_region = reg_idx;
                        g_has_selection = true;
                        g_view_offset = page_off;
                        display_selected_region(first_hit);
                        update_triage_details_label(reg_idx);
                    }
                }
            }
        }
        else if (id == ID_BTN_PREV_PAGE)
        {
            if (g_has_selection && g_view_offset >= VIEW_PAGE_SIZE)
            {
                g_view_offset -= VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_BTN_NEXT_PAGE)
        {
            if (g_has_selection && g_selected_region < g_regions.size() &&
                g_view_offset + VIEW_PAGE_SIZE < g_regions[g_selected_region].size)
            {
                g_view_offset += VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_BTN_SNAP)
        {
            on_take_snapshot();
        }
        else if (id == ID_BTN_CLEAR_SNAPS)
        {
            on_clear_snapshots();
        }
        else if (id == ID_COMBO_DIFF && code == CBN_SELCHANGE)
        {
            invalidate_hex_cache();
            display_selected_region(static_cast<SIZE_T>(-1));
        }
        else if (id == ID_CHK_HEARTBEAT)
        {
            bool checked = (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (checked)
            {
                if (g_has_selection && g_selected_region < g_regions.size())
                {
                    RegionInfo &reg = g_regions[g_selected_region];
                    if (reg.snapshots.empty())
                    {
                        on_take_snapshot();
                    }
                }
                SetTimer(hwnd, IDT_HEARTBEAT, 1000, nullptr);
                set_status("Heartbeat active (1s interval): Monitoring memory diff in real time...");
            }
            else
            {
                KillTimer(hwnd, IDT_HEARTBEAT);
                set_status("Heartbeat stopped.");
            }
        }
        else if (id == IDM_FILE_OPEN_SOURCE)
        {
            on_open_memory_source();
        }
        else if (id == IDM_FILE_TRIAGE)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_TRIAGE, 0);
        }
        else if (id == IDM_FILE_EXPORT_JSON)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_EXPORT_JSON, 0);
        }
        else if (id == IDM_FILE_EXIT)
        {
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
        }
        else if (id == IDM_EDIT_COPY_ADDR)
        {
            HWND focused = GetFocus();
            if (focused == g_edit_hex)
            {
                DWORD sel_start = 0, sel_end = 0;
                SendMessageA(g_edit_hex, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start), reinterpret_cast<LPARAM>(&sel_end));
                if (sel_start != sel_end)
                {
                    SendMessageA(g_edit_hex, WM_COPY, 0, 0);
                    return 0;
                }
            }
            if (g_has_selection && g_selected_region < g_regions.size())
            {
                std::string addr_hex = to_hex_string(g_regions[g_selected_region].base);
                copy_text_to_clipboard(hwnd, addr_hex);
                set_status("Copied region address " + addr_hex + " to clipboard.");
            }
        }
        else if (id == IDM_EDIT_COPY_HEX)
        {
            int len = GetWindowTextLengthA(g_edit_hex);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(g_edit_hex, buf.data(), len + 1);
                copy_text_to_clipboard(hwnd, buf.data());
                set_status("Hex dump copied to clipboard (" + std::to_string(len) + " bytes).");
            }
        }
        else if (id == IDM_EDIT_FIND_PATTERN)
        {
            SetFocus(g_edit_pattern);
            SendMessageA(g_edit_pattern, EM_SETSEL, 0, -1);
        }
        else if (id == IDM_EDIT_FIND_NEXT)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_NEXT_HIT, 0);
        }
        else if (id == IDM_VIEW_TRIAGE_FINDINGS)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 0, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_VIEW_MEMORY_MAP)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 1, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_FILE_THEME_LIGHT)
        {
            apply_theme_switch(hwnd, AppTheme::Light);
        }
        else if (id == IDM_FILE_THEME_DARK)
        {
            apply_theme_switch(hwnd, AppTheme::Dark);
        }
        else if (id == IDM_VIEW_HIDE_CLEAN)
        {
            bool cur = (SendMessageA(g_chk_hide_clean, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(g_chk_hide_clean, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HIDE_CLEAN, 0);
        }
        else if (id == IDM_VIEW_HITS_ONLY)
        {
            bool cur = (SendMessageA(g_chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(g_chk_hits_only, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HITS_ONLY, 0);
        }
        else if (id == IDM_VIEW_REFRESH)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_LOAD, 0);
        }
        else if (id == IDM_TIMELINE_SNAP)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_SNAP, 0);
        }
        else if (id == IDM_TIMELINE_CLEAR)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_CLEAR_SNAPS, 0);
        }
        else if (id == IDM_TIMELINE_HEARTBEAT)
        {
            bool cur = (SendMessageA(g_chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(g_chk_heartbeat, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HEARTBEAT, 0);
        }
        else if (id == IDM_TIMELINE_PREV_PAGE)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_PREV_PAGE, 0);
        }
        else if (id == IDM_TIMELINE_NEXT_PAGE)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_NEXT_PAGE, 0);
        }
        else if (id == ID_BTN_DIFF_PROC)
        {
            on_capture_diff();
        }
        else if (id == ID_BTN_YARA || id == IDM_EDIT_GENERATE_YARA)
        {
            open_yara_dialog(hwnd);
        }
        else if (id == IDM_DIFF_CAPTURE_BASELINE)
        {
            on_capture_baseline();
        }
        else if (id == IDM_DIFF_CAPTURE_CURRENT)
        {
            on_capture_diff();
        }
        else if (id == IDM_DIFF_SAVE_SESSION)
        {
            on_save_diff_session();
        }
        else if (id == IDM_DIFF_LOAD_SESSION)
        {
            on_load_diff_session();
        }
        else if (id == IDM_DIFF_VIEW_STRINGS)
        {
            open_revealed_strings_dialog(hwnd);
        }
        else if (id == IDM_VIEW_BEHAVIOR)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 2, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_VIEW_STRINGS)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 3, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_VIEW_PROCESS_DIFF)
        {
            SendMessageA(g_combo_view_mode, CB_SETCURSEL, 4, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(g_combo_view_mode));
        }
        else if (id == IDM_BEHAVIOR_PIN)
        {
            if (g_has_selection && g_selected_region < g_regions.size())
            {
                const auto &reg = g_regions[g_selected_region];
                auto it = std::find_if(g_watched_regions.begin(), g_watched_regions.end(),
                    [&](const WatchedRegionState &w) { return w.key.base == reg.base && w.key.alloc_base == reg.alloc_base; });
                if (it != g_watched_regions.end())
                {
                    it->is_pinned = !it->is_pinned;
                    set_status(std::string(it->is_pinned ? "Pinned region 0x" : "Unpinned region 0x") + to_hex_string(reg.base));
                }
                else
                {
                    WatchedRegionState nw;
                    nw.key.base = reg.base;
                    nw.key.alloc_base = reg.alloc_base;
                    nw.key.generation = g_region_generations[reg.base];
                    nw.size = reg.size;
                    nw.type = reg.type;
                    nw.alloc_protect = reg.alloc_protect;
                    nw.is_pinned = true;
                    g_watched_regions.push_back(std::move(nw));
                    set_status("Pinned and watching region 0x" + to_hex_string(reg.base));
                }
                if (g_view_mode == ViewMode::BehaviorTracker)
                {
                    populate_region_list();
                }
            }
            else
            {
                set_status("Select a region first to pin/unpin for behavior tracking.");
            }
        }
        else if (id == IDM_BEHAVIOR_WATCH_ALL_PRIV)
        {
            bool cur = g_tracker_watch_all_priv_exec.load();
            g_tracker_watch_all_priv_exec.store(!cur);
            if (!cur)
            {
                for (const auto &reg : g_regions)
                {
                    bool is_exec = (reg.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    if (reg.type == MEM_PRIVATE && is_exec)
                    {
                        auto it = std::find_if(g_watched_regions.begin(), g_watched_regions.end(),
                            [&](const WatchedRegionState &w) { return w.key.base == reg.base; });
                        if (it == g_watched_regions.end())
                        {
                            WatchedRegionState nw;
                            nw.key.base = reg.base;
                            nw.key.alloc_base = reg.alloc_base;
                            nw.key.generation = g_region_generations[reg.base];
                            nw.size = reg.size;
                            nw.type = reg.type;
                            nw.alloc_protect = reg.alloc_protect;
                            nw.is_pinned = false;
                            g_watched_regions.push_back(std::move(nw));
                        }
                    }
                }
                set_status("Behavior Tracker: Watching all private executable regions (ON).");
            }
            else
            {
                set_status("Behavior Tracker: Watch all private executable regions (OFF).");
            }
            if (g_view_mode == ViewMode::BehaviorTracker)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_BEHAVIOR_CLEAR)
        {
            for (auto &w : g_watched_regions)
            {
                w.ring_samples.clear();
                w.total_samples = 0;
                w.behavior_score = 0;
                w.behavior_flags.clear();
                w.evidence_summary.clear();
                w.sleep_evidence = {};
                w.key_evidence = {};
                w.decrypt_evidence = {};
            }
            g_tracker_total_samples.store(0);
            g_tracker_partial_samples.store(0);
            set_status("Behavior tracker sample history cleared.");
            if (g_view_mode == ViewMode::BehaviorTracker)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_STRINGS_BASELINE)
        {
            g_string_baselines.clear();
            for (const auto &st : g_extracted_strings)
            {
                g_string_baselines[st.region_base].insert(st.content_hash);
            }
            for (auto &st : g_extracted_strings)
            {
                st.is_new = false;
            }
            set_status("String baseline set (" + std::to_string(g_extracted_strings.size()) + " strings across " +
                       std::to_string(g_string_baselines.size()) + " regions).");
            if (g_view_mode == ViewMode::StringsView)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_STRINGS_TOGGLE_NEW)
        {
            g_strings_filter_new_only = !g_strings_filter_new_only;
            set_status(g_strings_filter_new_only ? "Strings View: Showing only NEW strings since baseline." : "Strings View: Showing all extracted strings.");
            if (g_view_mode == ViewMode::StringsView)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_STRINGS_EXTRACT_SEL)
        {
            if (g_current_source != nullptr && g_has_selection && g_selected_region < g_regions.size())
            {
                set_status("Extracting ASCII & UTF-16 strings from selected region...");
                extract_all_strings_from_source(g_current_source, g_regions, static_cast<int>(g_selected_region), g_strings_min_len, g_extracted_strings, &g_string_baselines);
                g_view_mode = ViewMode::StringsView;
                SendMessageA(g_combo_view_mode, CB_SETCURSEL, 3, 0);
                populate_region_list();
                set_status("Extracted " + std::to_string(g_extracted_strings.size()) + " strings from region 0x" + to_hex_string(g_regions[g_selected_region].base));
            }
            else
            {
                set_status("Select a region first to extract strings.");
            }
        }
        else if (id == IDM_STRINGS_EXTRACT_ALL)
        {
            if (g_current_source != nullptr && !g_regions.empty())
            {
                set_status("Extracting ASCII & UTF-16 strings across all regions (capped)...");
                extract_all_strings_from_source(g_current_source, g_regions, -1, g_strings_min_len, g_extracted_strings, &g_string_baselines);
                g_view_mode = ViewMode::StringsView;
                SendMessageA(g_combo_view_mode, CB_SETCURSEL, 3, 0);
                populate_region_list();
                set_status("Extracted " + std::to_string(g_extracted_strings.size()) + " strings across " + std::to_string(g_regions.size()) + " regions.");
            }
            else
            {
                set_status("Open a memory source or triage first to extract strings.");
            }
        }
        else if (id == IDM_HELP_BEHAVIOR_LIMITS)
        {
            std::string limits_info =
                "Deadeye Behavior Tracker - Polling & Behavior Limitations Guide\n\n"
                "HOW IT WORKS:\n"
                "- User-Mode Sampling: Deadeye samples target process memory strictly via ReadProcessMemory without injecting DLLs, hooking syscalls, or pausing threads.\n"
                "- Configurable Interval: Default sampling tick is 1000ms with a strict 50ms time budget per tick to ensure zero UI lag.\n\n"
                "HONEST SAMPLING LIMITATIONS:\n"
                "1. Sub-second Flips: Polling cannot guarantee detection of transitions that flip and revert in <100ms (e.g. RWX decryption that immediately flips back to RX before the next sample).\n"
                "2. Time-Budgeted Subset: On targets with hundreds of watched regions, samples rotate across subsets within the 50ms budget; partial ticks are recorded and displayed in the status bar.\n"
                "3. Corroboration: Detections (SLEEP_MASK_SUSPECT, KEY_ROTATION_SUSPECT, DECRYPT_ON_WAKE) combine time-series observation with static heuristics to maintain a high signal-to-noise ratio.\n\n"
                "SHORTCUTS:\n"
                "- Ctrl+3: Behavior Tracker View\n"
                "- Ctrl+4: Strings View\n"
                "- Ctrl+P: Pin / Unpin region for behavior tracking\n"
                "- Ctrl+B: Record string baseline for decrypt-on-wake diffing\n"
                "- F6: Toggle 'New since baseline' strings filter\n"
                "- F7: Extract strings from selected region\n";
            MessageBoxA(hwnd, limits_info.c_str(), "Deadeye - Polling Limitations", MB_OK | MB_ICONINFORMATION);
        }
        else if (id == IDM_HELP_HEURISTICS)
        {
            std::string info =
                "Live Defensive Triage Heuristics:\n"
                "[+50] INJECTED_PE: MZ/PE header detected inside committed MEM_PRIVATE pages.\n"
                "[+50] BEHAVIOR_UNPACK: Memory flipped to executable with byte mutations or entropy drop.\n"
                "[+65] SLEEP_OBFUSCATION: Region protection/entropy oscillates across heartbeat ticks.\n"
                "[+45] UNLINKED_MODULE: MEM_IMAGE allocation missing from PEB InLoadOrderModuleList.\n"
                "[+40] PRIVATE_RWX: Committed MEM_PRIVATE page with PAGE_EXECUTE_READWRITE.\n"
                "[+35] WRITE_THEN_FLIP: Allocated writable (PAGE_READWRITE), currently executable.\n"
                "[+25] UNBACKED_EXEC: Executable memory not backed by an on-disk image file.\n\n"
                "Entropy & Behavior Profiling Heuristics:\n"
                "[+35] HIGH_ENTROPY_EXEC: Executable region/page with Shannon entropy >= 7.20.\n"
                "[+20] HIGH_ENTROPY_PRIVATE: MEM_PRIVATE non-exec region >= 7.40 over >= 16 KB.\n"
                "[+40] SLEEP_MASK_SUSPECT: Time-series oscillation between low/high entropy or exec/non-exec.\n"
                "[+35] KEY_ROTATION_SUSPECT: High entropy payload with changing content hash & repeating XOR delta.\n"
                "[+35] DECRYPT_ON_WAKE: Sharp entropy drop with newly revealed strings vs baseline.\n\n"
                "Static Binary Heuristics (Mapped PE Offline Analysis):\n"
                "[+50] STATIC_WX_SECTION: Section marked with both Writable and Executable rights (W+X).\n"
                "[+45] STATIC_EP_OUTSIDE_EXEC: Entry point RVA is located outside all executable sections.\n"
                "[+40] STATIC_EXEC_HIGH_ENTROPY: Executable section with Shannon entropy >= 7.20.\n"
                "[+25] STATIC_NONTRIVIAL_OVERLAY: Non-trivial overlay data (> 512 bytes) appended past raw section data.\n\n"
                "Severity Scoring Thresholds:\n"
                "  * CRITICAL: Score >= 80\n"
                "  * HIGH:     Score >= 50\n"
                "  * MEDIUM:   Score >= 25\n"
                "  * LOW:      Score >= 10\n"
                "  * CLEAN:    Score = 0\n\n"
                "Note: Heartbeat polling interval is 1s; sub-second transitions may be missed.";
            MessageBoxA(hwnd, info.c_str(), "Deadeye Heuristics Reference", MB_OK | MB_ICONINFORMATION);
        }
        else if (id == IDM_HELP_ABOUT)
        {
            std::string about =
                "Deadeye v1.0\n"
                "Process Memory Triage Scanner & Real-Time Diff Timeline\n\n"
                "Built with C++17 & Native Win32 for defensive reverse engineering,\n"
                "malware analysis, and detection engineering.\n\n"
                "Repository: https://github.com/Winter0x11/Deadeye";
            MessageBoxA(hwnd, about.c_str(), "About Deadeye", MB_OK | MB_ICONINFORMATION);
        }
        return 0;
    }

    case WM_SCAN_PROGRESS:
    {
        SIZE_T cur = static_cast<SIZE_T>(wp);
        SIZE_T tot = static_cast<SIZE_T>(lp);
        char status[160];
        if (tot > 0)
        {
            std::snprintf(status, sizeof(status), "Evaluating process memory... %llu / %llu regions analyzed",
                          static_cast<unsigned long long>(cur), static_cast<unsigned long long>(tot));
        }
        else
        {
            std::snprintf(status, sizeof(status), "Scanning process memory... %llu MB scanned",
                          static_cast<unsigned long long>(cur));
        }
        set_status(status);
        return 0;
    }

    case WM_SCAN_COMPLETE:
    case WM_TRIAGE_COMPLETE:
    {
        WorkerResult *res = reinterpret_cast<WorkerResult *>(lp);
        if (res != nullptr)
        {
            on_worker_completed(res);
            delete res;
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == IDT_HEARTBEAT)
        {
            evaluate_memory_behavior_heartbeat();

            // Behavior Tracker background worker sampling
            if (g_tracker_active.load() && g_current_source != nullptr && g_current_source->capabilities().is_live && !g_target_process_exited.load())
            {
                bool expected = false;
                if (g_tracker_busy.compare_exchange_strong(expected, true))
                {
                    WorkerTask *task = new WorkerTask();
                    task->task_type = WorkerTaskType::BehaviorTick;
                    task->hwnd = hwnd;
                    task->source = g_current_source;

                    HANDLE th = CreateThread(nullptr, 0, WorkerThreadProc, task, 0, nullptr);
                    if (th != nullptr)
                    {
                        CloseHandle(th);
                    }
                    else
                    {
                        g_tracker_busy.store(false);
                        delete task;
                    }
                }
                else
                {
                    g_tracker_partial_samples++;
                }
            }

            if (g_has_selection && g_selected_region < g_regions.size() && g_view_mode != ViewMode::BehaviorTracker && g_view_mode != ViewMode::StringsView)
            {
                display_selected_region(static_cast<SIZE_T>(-1));
            }
            return 0;
        }
        break;

    case WM_BEHAVIOR_TICK_DONE:
    {
        if (g_tracker_active.load())
        {
            char status_buf[256];
            if (g_target_process_exited.load())
            {
                std::snprintf(status_buf, sizeof(status_buf),
                              "Tracker: Target process exited. Total samples: %llu (partial: %llu).",
                              static_cast<unsigned long long>(g_tracker_total_samples.load()),
                              static_cast<unsigned long long>(g_tracker_partial_samples.load()));
            }
            else
            {
                std::snprintf(status_buf, sizeof(status_buf),
                              "Tracker: %llu samples (%llu partial) @ %ums. Note: Polling limits apply; sub-second flips may be missed. Help: F1",
                              static_cast<unsigned long long>(g_tracker_total_samples.load()),
                              static_cast<unsigned long long>(g_tracker_partial_samples.load()),
                              static_cast<unsigned int>(g_tracker_interval_ms.load()));
            }
            SetWindowTextA(g_lbl_status, status_buf);
        }

        if (g_view_mode == ViewMode::BehaviorTracker)
        {
            populate_region_list();
            if (g_has_selection && g_selected_region < g_watched_regions.size())
            {
                update_triage_details_label(g_selected_region);
            }
        }
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd, IDT_HEARTBEAT);
        g_scan_abort.store(true, std::memory_order_relaxed);
        if (g_h_worker_thread != nullptr)
        {
            WaitForSingleObject(g_h_worker_thread, 1000);
            CloseHandle(g_h_worker_thread);
            g_h_worker_thread = nullptr;
        }
        close_target_proc();
        if (g_mono_font)
            DeleteObject(g_mono_font);
        if (g_ui_font)
            DeleteObject(g_ui_font);
        if (g_ui_font_bold)
            DeleteObject(g_ui_font_bold);
        if (g_br_window)
            DeleteObject(g_br_window);
        if (g_br_control)
            DeleteObject(g_br_control);
        if (g_haccel)
        {
            DestroyAcceleratorTable(g_haccel);
            g_haccel = nullptr;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int run_gui(HINSTANCE hInst, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    HICON hIconBig = static_cast<HICON>(LoadImageA(hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON,
                                                   GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                                                   LR_DEFAULTCOLOR | LR_SHARED));
    HICON hIconSmall = static_cast<HICON>(LoadImageA(hInst, MAKEINTRESOURCEA(IDI_APP), IMAGE_ICON,
                                                     GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                                     LR_DEFAULTCOLOR | LR_SHARED));
    if (hIconBig == nullptr)
    {
        hIconBig = LoadIconA(nullptr, IDI_APPLICATION);
    }

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = "DeadeyeHexViewer";
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hIcon = hIconBig;
    wc.hIconSm = hIconSmall;
    RegisterClassExA(&wc);

    WNDCLASSEXA wcYara = {};
    wcYara.cbSize = sizeof(wcYara);
    wcYara.lpfnWndProc = YaraDlgProc;
    wcYara.hInstance = hInst;
    wcYara.hbrBackground = nullptr;
    wcYara.lpszClassName = "DeadeyeYaraDlg";
    wcYara.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wcYara.hIcon = hIconSmall;
    RegisterClassExA(&wcYara);

    WNDCLASSEXA wcStr = {};
    wcStr.cbSize = sizeof(wcStr);
    wcStr.lpfnWndProc = StringsDlgProc;
    wcStr.hInstance = hInst;
    wcStr.hbrBackground = nullptr;
    wcStr.lpszClassName = "DeadeyeStringsDlg";
    wcStr.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wcStr.hIcon = hIconSmall;
    RegisterClassExA(&wcStr);

    WNDCLASSEXA wcAttach = {};
    wcAttach.cbSize = sizeof(wcAttach);
    wcAttach.lpfnWndProc = AttachDlgProc;
    wcAttach.hInstance = hInst;
    wcAttach.hbrBackground = nullptr;
    wcAttach.lpszClassName = "DeadeyeAttachDlg";
    wcAttach.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wcAttach.hIcon = hIconSmall;
    RegisterClassExA(&wcAttach);

    HWND hwnd = CreateWindowA("DeadeyeHexViewer", "Deadeye",
                              WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                              1220, 740, nullptr, nullptr, hInst, nullptr);

    if (hIconBig != nullptr)
    {
        SendMessageA(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIconBig));
    }
    if (hIconSmall != nullptr)
    {
        SendMessageA(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIconSmall));
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0))
    {
        if (g_haccel != nullptr && TranslateAcceleratorA(hwnd, g_haccel, &msg))
        {
            continue;
        }
        if (!IsDialogMessageA(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

// ============================================================================
// 4. Pure Windows Subsystem Entry Point
// ============================================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;

    // Acquire SeDebugPrivilege so elevated runs can inspect system services
    enable_debug_privilege();

    if (lpCmdLine != nullptr && std::strstr(lpCmdLine, "--json") != nullptr)
    {
        const char *p = std::strstr(lpCmdLine, "--json");
        p += 6;
        while (*p == ' ') p++;
        char pid_str[64] = {};
        char out_path[MAX_PATH] = {};
        if (std::sscanf(p, "%63s %259s", pid_str, out_path) == 2)
        {
            DWORD target_pid = 0;
            if (parse_pid_string(pid_str, target_pid) && target_pid != 0)
            {
                auto live_src = std::make_shared<LiveProcessSource>(target_pid);
                if (live_src->get_raw_handle() != nullptr)
                {
                    std::vector<RegionInfo> regions;
                    std::string err;
                    if (live_src->query_regions(regions, err))
                    {
                        TriageReport report = run_source_triage(live_src, regions);
                        std::string json_data = export_triage_json(report);
                        std::string out_file = out_path;
                        if (out_file.size() >= 2 && out_file.front() == '"' && out_file.back() == '"')
                        {
                            out_file = out_file.substr(1, out_file.size() - 2);
                        }
                        FILE *fp = std::fopen(out_file.c_str(), "wb");
                        if (fp != nullptr)
                        {
                            std::fwrite(json_data.data(), 1, json_data.size(), fp);
                            std::fclose(fp);
                            return 0;
                        }
                    }
                }
            }
            return 1;
        }
    }

    return run_gui(hInstance, nCmdShow);
}
