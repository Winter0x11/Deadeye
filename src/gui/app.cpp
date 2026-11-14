// src/gui/app.cpp
// Deadeye GUI Application State and Window Management Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/app.hpp"
#include "gui/views.hpp"
#include "gui/hexview.hpp"
#include "gui/controls.hpp"
#include "gui/menu.hpp"
#include "gui/attach_dialog.hpp"
#include "gui/yara_dialog.hpp"
#include "gui/strings_dialog.hpp"
#include "gui/pe_options_dialog.hpp"

#include "core/scoring.hpp"
#include "core/util.hpp"
#include "core/pattern.hpp"
#include "core/memsource.hpp"
#include "core/live_source.hpp"
#include "core/pe_source.hpp"
#include "core/triage.hpp"
#include "core/behavior.hpp"
#include "core/json_export.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>

#ifndef IDI_APP
#define IDI_APP 101
#endif

namespace gui {

static AppState g_app_state;

AppState& get_app_state()
{
    return g_app_state;
}

void close_target_proc()
{
    if (get_app_state().target_proc != nullptr)
    {
        CloseHandle(get_app_state().target_proc);
        get_app_state().target_proc = nullptr;
    }
}

HANDLE get_or_open_target_proc(DWORD pid)
{
    if (get_app_state().target_proc != nullptr)
    {
        DWORD exit_code = 0;
        if (get_app_state().current_pid == pid && GetExitCodeProcess(get_app_state().target_proc, &exit_code) && exit_code == STILL_ACTIVE)
        {
            return get_app_state().target_proc;
        }
        close_target_proc();
    }
    get_app_state().target_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    return get_app_state().target_proc;
}

std::shared_ptr<MemorySource> get_active_source()
{
    if (get_app_state().current_source != nullptr)
    {
        return get_app_state().current_source;
    }
    if (get_app_state().current_pid != 0)
    {
        HANDLE proc = get_or_open_target_proc(get_app_state().current_pid);
        get_app_state().current_source = std::make_shared<LiveProcessSource>(get_app_state().current_pid, proc, false, get_app_state().current_pid_label);
        return get_app_state().current_source;
    }
    return nullptr;
}



void set_status(const std::string &text)
{
    SetWindowTextA(get_app_state().lbl_status, text.c_str());
}



void update_theme_brushes()
{
    if (get_app_state().br_window)
        DeleteObject(get_app_state().br_window);
    if (get_app_state().br_control)
        DeleteObject(get_app_state().br_control);
    const ThemeColors &tc = get_theme_colors(get_app_state().theme);
    get_app_state().br_window = CreateSolidBrush(tc.bg_window);
    get_app_state().br_control = CreateSolidBrush(tc.bg_control);
}

void apply_theme_switch(HWND hwnd, AppTheme new_theme)
{
    get_app_state().theme = new_theme;
    update_theme_brushes();
    InvalidateRect(hwnd, nullptr, TRUE);
    if (get_app_state().list_regions) InvalidateRect(get_app_state().list_regions, nullptr, TRUE);
    if (get_app_state().edit_hex) InvalidateRect(get_app_state().edit_hex, nullptr, TRUE);
    if (get_app_state().lbl_triage_reasons) InvalidateRect(get_app_state().lbl_triage_reasons, nullptr, TRUE);
    if (get_app_state().lbl_status) InvalidateRect(get_app_state().lbl_status, nullptr, TRUE);
    HWND btns[] = { get_app_state().btn_attach, get_app_state().btn_load, get_app_state().btn_triage, get_app_state().btn_search, get_app_state().btn_next_hit, get_app_state().btn_export_json, get_app_state().btn_snap, get_app_state().btn_clear_snaps, get_app_state().btn_prev_page, get_app_state().btn_next_page, get_app_state().btn_diff_proc, get_app_state().btn_yara };
    for (HWND b : btns) { if (b) InvalidateRect(b, nullptr, TRUE); }
    set_status((get_app_state().theme == AppTheme::Dark) ? "Theme switched to Modern Dark." : "Theme switched to Classic Light.");
}

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
        ctx.watched_regions = &get_app_state().watched_regions;
        ctx.region_generations = &get_app_state().region_generations;
        ctx.regions = &get_app_state().regions;
        ctx.triage_report = &get_app_state().triage_report;
        ctx.string_baselines = &get_app_state().string_baselines;
        ctx.watch_all_priv_exec = get_app_state().tracker_watch_all_priv_exec.load();
        ctx.rotating_idx = &get_app_state().tracker_rotating_idx;
        ctx.total_samples = &get_app_state().tracker_total_samples;
        ctx.partial_samples = &get_app_state().tracker_partial_samples;
        ctx.target_process_exited = &get_app_state().target_process_exited;

        run_behavior_tracker_tick(source, ctx);
        get_app_state().tracker_busy.store(false);
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

        res->report = run_source_triage(source, res->regions, &get_app_state().scan_abort, triage_cb, hwnd);

        if (get_app_state().scan_abort.load(std::memory_order_relaxed))
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

    for (size_t r_i = 0; r_i < query_regs.size() && !get_app_state().scan_abort.load(std::memory_order_relaxed); ++r_i)
    {
        RegionInfo reg = query_regs[r_i];
        uintptr_t region_base = reg.base;
        SIZE_T region_size = reg.size;

        SIZE_T offset = 0;
        SIZE_T overlap = (res->use_pattern && !res->pat.bytes.empty()) ? (res->pat.bytes.size() - 1) : 0;
        SIZE_T prev_overlap = 0;
        bool pe_found = false;

        while (offset < region_size && !get_app_state().scan_abort.load(std::memory_order_relaxed))
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

    if (!get_app_state().scan_abort.load(std::memory_order_relaxed))
    {
        res->report = run_source_triage(source, res->regions, &get_app_state().scan_abort, nullptr, nullptr);
    }

    if (get_app_state().scan_abort.load(std::memory_order_relaxed))
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
    EnableWindow(get_app_state().btn_attach, enable);
    EnableWindow(get_app_state().btn_load, enable);
    EnableWindow(get_app_state().btn_triage, enable);
    EnableWindow(get_app_state().btn_search, enable);
    EnableWindow(get_app_state().edit_pid, enable);
    EnableWindow(get_app_state().edit_pattern, enable);
}

void on_worker_completed(WorkerResult *res)
{
    if (get_app_state().h_worker_thread != nullptr)
    {
        WaitForSingleObject(get_app_state().h_worker_thread, 100);
        CloseHandle(get_app_state().h_worker_thread);
        get_app_state().h_worker_thread = nullptr;
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
        MessageBoxA(get_app_state().hwnd_main, msg.c_str(), "Deadeye Scanner", MB_ICONERROR);
        return;
    }

    close_target_proc();
    invalidate_hex_cache();

    get_app_state().regions = std::move(res->regions);
    get_app_state().triage_report = std::move(res->report);
    get_app_state().current_pid = res->pid;
    get_app_state().current_pid_label = res->pid_label;
    if (res->source)
    {
        get_app_state().current_source = res->source;
    }
    get_app_state().active_pattern = res->pat;
    get_app_state().has_pattern = res->use_pattern;
    get_app_state().has_selection = false;
    get_app_state().view_offset = 0;

    EnableWindow(get_app_state().btn_next_hit, (get_app_state().has_pattern && res->total_hits > 0) ? TRUE : FALSE);

    if (res->task_type == WorkerTaskType::Triage)
    {
        get_app_state().view_mode = ViewMode::TriageFindings;
        SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 0, 0);
    }

    if (get_app_state().current_source != nullptr && get_app_state().current_source->capabilities().is_live)
    {
        get_app_state().tracker_active.store(true);
        get_app_state().target_process_exited.store(false);

        // Build default watch set: regions with triage score >= 25 or high entropy, plus pinned or watch all priv
        for (const auto &reg : get_app_state().regions)
        {
            int sev = 0;
            for (const auto &f : get_app_state().triage_report.findings)
            {
                if (f.base == reg.base)
                {
                    sev = f.severity_score;
                    break;
                }
            }

            bool is_exec = (reg.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool high_ent = (reg.avg_entropy >= 7.0 || reg.max_entropy >= 7.2);
            bool watch_all_priv = get_app_state().tracker_watch_all_priv_exec.load() && (reg.type == MEM_PRIVATE && is_exec);

            if (sev >= 25 || high_ent || watch_all_priv)
            {
                bool exists = false;
                for (const auto &w : get_app_state().watched_regions)
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
                    nw.key.generation = get_app_state().region_generations[reg.base];
                    nw.size = reg.size;
                    nw.type = reg.type;
                    nw.alloc_protect = reg.alloc_protect;
                    nw.is_pinned = false;
                    get_app_state().watched_regions.push_back(std::move(nw));
                }
            }
        }
    }

    populate_region_list();

    // Select the first finding or region
    if (!get_app_state().visible_indices.empty())
    {
        select_region_in_ui(get_app_state().visible_indices[0], 0, static_cast<SIZE_T>(-1));
    }
    else
    {
        update_diff_combo();
        display_selected_region(static_cast<SIZE_T>(-1));
        SetWindowTextA(get_app_state().lbl_triage_reasons, "Details: Ready.");
    }

    // Calculate threat breakdown
    size_t crit = 0, high = 0, med = 0, low = 0;
    for (const auto &f : get_app_state().triage_report.findings)
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
    if (get_app_state().current_source != nullptr && !get_app_state().current_source->capabilities().is_live)
    {
        std::snprintf(status, sizeof(status),
                      "%s: %zu sections/regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW [Static PE Rules]",
                      get_app_state().current_source->describe().c_str(),
                      get_app_state().regions.size(), crit, high, med, low);
    }
    else if (res->task_type == WorkerTaskType::Triage)
    {
        std::snprintf(status, sizeof(status),
                      "Triage complete for PID %lu (%s): %zu regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW%s",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      get_app_state().regions.size(), crit, high, med, low,
                      res->report.wow64_unsupported ? " (WOW64: PEB unlinked check unsupported)" : "");
    }
    else if (get_app_state().has_pattern)
    {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): %zu regions, %.2f MB scanned | %zu hit(s) in %zu region(s) | Triage: %zu Suspicious",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      get_app_state().regions.size(), mb, res->total_hits, res->regions_with_hits,
                      crit + high + med);
    }
    else
    {
        std::snprintf(status, sizeof(status),
                      "PID %lu (%s): Loaded %zu committed regions (%.2f MB) | Triage: %zu Suspicious (%zu CRIT, %zu HIGH)",
                      static_cast<unsigned long>(res->pid), res->pid_label.c_str(),
                      get_app_state().regions.size(), mb, crit + high + med, crit, high);
    }
    set_status(status);
}

void start_worker_task(WorkerTaskType task_type, bool require_pattern)
{
    if (get_app_state().h_worker_thread != nullptr)
    {
        DWORD exit_code = 0;
        if (GetExitCodeThread(get_app_state().h_worker_thread, &exit_code) && exit_code == STILL_ACTIVE)
        {
            set_status("Operation already in progress. Please wait...");
            return;
        }
        CloseHandle(get_app_state().h_worker_thread);
        get_app_state().h_worker_thread = nullptr;
    }

    char pid_buf[64] = {};
    char pat_buf[512] = {};
    GetWindowTextA(get_app_state().edit_pid, pid_buf, sizeof(pid_buf));
    GetWindowTextA(get_app_state().edit_pattern, pat_buf, sizeof(pat_buf));

    std::string pid_str(pid_buf);
    std::string pat_str(pat_buf);

    DWORD pid = 0;
    std::shared_ptr<MemorySource> active_source = nullptr;
    if (parse_pid_string(pid_str, pid))
    {
        active_source = std::make_shared<LiveProcessSource>(pid);
        get_app_state().current_source = active_source;
        get_app_state().current_pid = pid;
        SetWindowTextA(get_app_state().hwnd_main, "Deadeye - Memory Triage Scanner & Hex Viewer");
        if (get_app_state().chk_heartbeat) EnableWindow(get_app_state().chk_heartbeat, TRUE);
    }
    else if (get_app_state().current_source != nullptr && !get_app_state().current_source->capabilities().is_live)
    {
        active_source = get_app_state().current_source;
    }
    else
    {
        MessageBoxA(get_app_state().hwnd_main, "Enter a valid numeric PID, or select File > Open Memory Source... to inspect a PE/binary file.", "Invalid Target", MB_ICONWARNING);
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
        MessageBoxA(get_app_state().hwnd_main, "Enter a hex pattern to search (e.g. '4D 5A ?? 00'), or click 'Load' / 'Triage'.",
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
            MessageBoxA(get_app_state().hwnd_main, err.c_str(), "Invalid Hex Pattern", MB_ICONWARNING);
            return;
        }
    }

    close_target_proc();
    invalidate_hex_cache();
    enable_ui_controls(FALSE);
    EnableWindow(get_app_state().btn_next_hit, FALSE);

    if (task_type == WorkerTaskType::Triage)
    {
        set_status("Triaging memory in background...");
    }
    else
    {
        set_status(use_pattern ? "Scanning memory in background..." : "Loading memory map in background...");
    }

    WorkerTask *task = new WorkerTask();
    task->hwnd = get_app_state().hwnd_main;
    task->pid = pid;
    task->pid_label = active_source ? active_source->describe() : ("PID " + std::to_string(pid));
    task->pat = pat;
    task->use_pattern = use_pattern;
    task->task_type = task_type;
    task->source = active_source;

    get_app_state().scan_abort.store(false, std::memory_order_relaxed);
    get_app_state().h_worker_thread = CreateThread(nullptr, 0, WorkerThreadProc, task, 0, nullptr);
    if (get_app_state().h_worker_thread == nullptr)
    {
        DWORD err = GetLastError();
        delete task;
        enable_ui_controls(TRUE);
        set_status("[ERROR] CreateThread failed: " + format_win32_error(err));
        MessageBoxA(get_app_state().hwnd_main, "Failed to launch background worker thread.", "Thread Error", MB_ICONERROR);
    }
}

void on_export_json()
{
    if (get_app_state().triage_report.findings.empty() && get_app_state().regions.empty())
    {
        MessageBoxA(get_app_state().hwnd_main, "Please Load or Triage a target process before exporting findings.",
                    "No Data", MB_ICONINFORMATION);
        return;
    }

    if (get_app_state().triage_report.findings.empty())
    {
        auto src = get_active_source();
        if (src != nullptr)
        {
            get_app_state().triage_report = run_source_triage(src, get_app_state().regions);
        }
    }

    char filename_buf[MAX_PATH] = {};
    if (get_app_state().current_source != nullptr && !get_app_state().current_source->capabilities().is_live)
    {
        std::string fn = get_app_state().current_source->get_file_path();
        size_t last_slash = fn.find_last_of("\\/");
        std::string base_fn = (last_slash != std::string::npos) ? fn.substr(last_slash + 1) : fn;
        std::snprintf(filename_buf, sizeof(filename_buf), "deadeye_triage_%s.json", base_fn.c_str());
    }
    else
    {
        std::snprintf(filename_buf, sizeof(filename_buf), "deadeye_triage_pid_%lu.json",
                      static_cast<unsigned long>(get_app_state().current_pid));
    }

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = get_app_state().hwnd_main;
    ofn.lpstrFilter = "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename_buf;
    ofn.nMaxFile = sizeof(filename_buf);
    ofn.lpstrTitle = "Export Triage Report (JSON)";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "json";

    if (GetSaveFileNameA(&ofn))
    {
        std::string json_data = export_triage_json(get_app_state().triage_report, &get_app_state().watched_regions, get_app_state().tracker_partial_samples.load(), get_app_state().tracker_interval_ms.load());
        FILE *fp = std::fopen(filename_buf, "wb");
        if (fp != nullptr)
        {
            std::fwrite(json_data.data(), 1, json_data.size(), fp);
            std::fclose(fp);
            char status[320];
            std::snprintf(status, sizeof(status), "Exported %zu triage findings to %s",
                          get_app_state().triage_report.findings.size(), filename_buf);
            set_status(status);
        }
        else
        {
            MessageBoxA(get_app_state().hwnd_main, "Failed to write JSON file to chosen location.",
                        "Export Error", MB_ICONERROR);
        }
    }
}

// ============================================================================

void on_capture_baseline()
{
    if (get_app_state().current_pid == 0)
    {
        char pid_buf[64] = {};
        GetWindowTextA(get_app_state().edit_pid, pid_buf, sizeof(pid_buf));
        DWORD parsed_pid = 0;
        if (parse_pid_string(pid_buf, parsed_pid) && parsed_pid != 0)
        {
            get_app_state().current_pid = parsed_pid;
        }
        else
        {
            MessageBoxA(get_app_state().hwnd_main, "Please enter a valid numeric target PID first before capturing a baseline.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    std::string err;
    set_status("Capturing full process baseline snapshot (PID " + std::to_string(get_app_state().current_pid) + ")...");
    UpdateWindow(get_app_state().lbl_status);

    if (capture_process_snapshot_session(get_app_state().current_pid, get_app_state().process_baseline, err))
    {
        get_app_state().has_baseline = true;
        char msg[160];
        std::snprintf(msg, sizeof(msg), "Baseline captured: %zu committed regions (%s) for PID %u (%s)",
                      get_app_state().process_baseline.regions.size(),
                      fmt_size_short(get_app_state().process_baseline.total_committed_bytes).c_str(),
                      static_cast<unsigned int>(get_app_state().process_baseline.pid),
                      get_app_state().process_baseline.process_name.c_str());
        set_status(msg);
        MessageBoxA(get_app_state().hwnd_main, msg, "Deadeye Process Diff", MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        set_status("[ERROR] " + err);
        MessageBoxA(get_app_state().hwnd_main, err.c_str(), "Deadeye Process Diff Error", MB_OK | MB_ICONERROR);
    }
}

void on_capture_diff()
{
    if (get_app_state().current_pid == 0)
    {
        char pid_buf[64] = {};
        GetWindowTextA(get_app_state().edit_pid, pid_buf, sizeof(pid_buf));
        DWORD parsed_pid = 0;
        if (parse_pid_string(pid_buf, parsed_pid) && parsed_pid != 0)
        {
            get_app_state().current_pid = parsed_pid;
        }
        else
        {
            MessageBoxA(get_app_state().hwnd_main, "Please enter a valid numeric target PID first.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    if (!get_app_state().has_baseline)
    {
        on_capture_baseline();
        if (get_app_state().has_baseline)
        {
            MessageBoxA(get_app_state().hwnd_main,
                        "Baseline snapshot captured successfully!\n\n"
                        "Now run your target malware sample or trigger suspicious activity,\n"
                        "then click 'Diff Proc' again (or press Ctrl+D) to compute the diff.",
                        "Deadeye Baseline Captured", MB_OK | MB_ICONINFORMATION);
        }
        return;
    }

    std::string err;
    set_status("Capturing current process snapshot and computing diff...");
    UpdateWindow(get_app_state().lbl_status);

    if (capture_process_snapshot_session(get_app_state().current_pid, get_app_state().process_target, err))
    {
        get_app_state().has_target = true;
        compute_process_diff(get_app_state().process_baseline, get_app_state().process_target, get_app_state().process_diffs);

        // Switch to Process Diff view
        get_app_state().view_mode = ViewMode::ProcessDiff;
        SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 2, 0);
        populate_region_list();

        size_t new_cnt = 0, prot_cnt = 0, mod_cnt = 0, del_cnt = 0;
        for (const auto &d : get_app_state().process_diffs)
        {
            if (d.kind == ProcessDiffKind::Appeared) new_cnt++;
            else if (d.kind == ProcessDiffKind::ProtectionChg) prot_cnt++;
            else if (d.kind == ProcessDiffKind::ContentChg) mod_cnt++;
            else if (d.kind == ProcessDiffKind::Disappeared) del_cnt++;
        }

        char msg[220];
        std::snprintf(msg, sizeof(msg),
                      "Diff complete: %zu changes detected | %zu new regions, %zu protection flips, %zu modified, %zu freed",
                      get_app_state().process_diffs.size(), new_cnt, prot_cnt, mod_cnt, del_cnt);
        set_status(msg);
    }
    else
    {
        set_status("[ERROR] " + err);
        MessageBoxA(get_app_state().hwnd_main, err.c_str(), "Deadeye Process Diff Error", MB_OK | MB_ICONERROR);
    }
}

void on_save_diff_session()
{
    if (!get_app_state().has_baseline && !get_app_state().has_target)
    {
        MessageBoxA(get_app_state().hwnd_main, "No process session snapshots to save.", "Deadeye Session Export", MB_OK | MB_ICONWARNING);
        return;
    }

    const ProcessSnapshotSession &session_to_save = get_app_state().has_target ? get_app_state().process_target : get_app_state().process_baseline;

    char file_buf[MAX_PATH] = {};
    std::string def_name = "deadeye_session_" + std::to_string(session_to_save.pid) + ".json";
    std::strncpy(file_buf, def_name.c_str(), sizeof(file_buf) - 1);

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = get_app_state().hwnd_main;
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
            MessageBoxA(get_app_state().hwnd_main, "Process snapshot session exported successfully.", "Deadeye Session Export", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(get_app_state().hwnd_main, "Failed to write session file.", "Deadeye Session Export Error", MB_OK | MB_ICONERROR);
        }
    }
}

void on_load_diff_session()
{
    char file_buf[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = get_app_state().hwnd_main;
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
            if (!get_app_state().has_baseline)
            {
                get_app_state().process_baseline = loaded_session;
                get_app_state().has_baseline = true;
                set_status("Loaded baseline session: " + loaded_session.process_name + " (" + std::to_string(loaded_session.regions.size()) + " regions)");
                MessageBoxA(get_app_state().hwnd_main, ("Loaded baseline snapshot session from:\n" + std::string(ofn.lpstrFile) + "\n\nYou can now capture a live snapshot or load a second session to compare.").c_str(), "Deadeye Session Load", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                get_app_state().process_target = loaded_session;
                get_app_state().has_target = true;
                compute_process_diff(get_app_state().process_baseline, get_app_state().process_target, get_app_state().process_diffs);
                get_app_state().view_mode = ViewMode::ProcessDiff;
                SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 2, 0);
                populate_region_list();
                set_status("Loaded target session & computed diff: " + std::to_string(get_app_state().process_diffs.size()) + " changes identified.");
                MessageBoxA(get_app_state().hwnd_main, ("Compared loaded session with baseline.\nIdentified " + std::to_string(get_app_state().process_diffs.size()) + " differences.").c_str(), "Deadeye Session Diff", MB_OK | MB_ICONINFORMATION);
            }
        }
        else
        {
            MessageBoxA(get_app_state().hwnd_main, "Failed to parse session JSON file.", "Deadeye Session Load Error", MB_OK | MB_ICONERROR);
        }
    }
}

void evaluate_memory_behavior_heartbeat()
{
    if (get_app_state().current_pid == 0) return;
    HANDLE proc = get_or_open_target_proc(get_app_state().current_pid);
    if (!proc) return;

    DWORD now = GetTickCount();
    std::vector<uint8_t> read_buf(64 * 1024);
    bool new_detection = false;

    for (auto &reg : get_app_state().regions)
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
                        for (const auto &prev : get_app_state().revealed_strings)
                        {
                            if (prev.addr == rs.addr && prev.text == rs.text)
                            {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            get_app_state().revealed_strings.push_back(rs);
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
        get_app_state().triage_report = run_process_triage(proc, get_app_state().current_pid, get_app_state().regions, nullptr, nullptr, nullptr);
        populate_region_list();
        set_status("[BEHAVIOR DETECTED] Unpack or sleep obfuscation transition identified during heartbeat!");
    }
}

void on_open_memory_source()
{
    char file_buf[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = get_app_state().hwnd_main;
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
            get_app_state().hwnd_main,
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
            if (!show_pe_map_options_dialog(get_app_state().hwnd_main, pe_base, chosen_base, apply_relocs))
            {
                return;
            }

            new_source = MappedPeSource::open(filepath, chosen_base, apply_relocs, load_err);
            if (!new_source)
            {
                MessageBoxA(get_app_state().hwnd_main, ("Failed to map PE: " + load_err).c_str(), "Deadeye - PE Loader Error", MB_OK | MB_ICONERROR);
                return;
            }
        }
        else
        {
            new_source = RawFileSource::open(filepath, 0x100000000ULL, load_err);
            if (!new_source)
            {
                MessageBoxA(get_app_state().hwnd_main, ("Failed to open file: " + load_err).c_str(), "Deadeye - Raw File Error", MB_OK | MB_ICONERROR);
                return;
            }
        }
    }
    else
    {
        new_source = RawFileSource::open(filepath, 0x100000000ULL, load_err);
        if (!new_source)
        {
            MessageBoxA(get_app_state().hwnd_main, ("Failed to open raw file: " + load_err).c_str(), "Deadeye - Raw File Error", MB_OK | MB_ICONERROR);
            return;
        }
    }

    get_app_state().current_source = new_source;
    get_app_state().current_pid = 0;
    close_target_proc();

    if (get_app_state().chk_heartbeat)
    {
        SendMessageA(get_app_state().chk_heartbeat, BM_SETCHECK, BST_UNCHECKED, 0);
        EnableWindow(get_app_state().chk_heartbeat, FALSE);
    }
    KillTimer(get_app_state().hwnd_main, IDT_HEARTBEAT);

    std::string desc = get_app_state().current_source->describe();
    SetWindowTextA(get_app_state().hwnd_main, ("Deadeye - [" + desc + "]").c_str());
    SetWindowTextA(get_app_state().edit_pid, desc.c_str());

    get_app_state().regions.clear();
    std::string q_err;
    if (!get_app_state().current_source->query_regions(get_app_state().regions, q_err))
    {
        MessageBoxA(get_app_state().hwnd_main, ("Error querying regions: " + q_err).c_str(), "Deadeye - Error", MB_OK | MB_ICONERROR);
        return;
    }

    invalidate_hex_cache();

    get_app_state().triage_report = run_source_triage(get_app_state().current_source, get_app_state().regions);

    PeSummaryInfo pe_summary;
    if (get_app_state().current_source->get_pe_summary(pe_summary))
    {
        SetWindowTextA(get_app_state().lbl_triage_reasons, format_pe_summary(pe_summary).c_str());
    }

    get_app_state().view_mode = ViewMode::TriageFindings;
    if (get_app_state().combo_view_mode)
    {
        SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 0, 0);
    }
    populate_region_list();

    if (!get_app_state().visible_indices.empty())
    {
        select_region_in_ui(get_app_state().visible_indices[0], 0, static_cast<SIZE_T>(-1));
    }
    else
    {
        get_app_state().has_selection = false;
        SetWindowTextA(get_app_state().edit_hex, "");
        update_diff_combo();
    }

    size_t crit = 0, high = 0, med = 0, low = 0;
    for (const auto &f : get_app_state().triage_report.findings)
    {
        if (f.severity_label == "CRIT") crit++;
        else if (f.severity_label == "HIGH") high++;
        else if (f.severity_label == "MED") med++;
        else if (f.severity_label == "LOW") low++;
    }

    char status[320];
    std::snprintf(status, sizeof(status),
                  "%s: %zu sections/regions | Threats: %zu CRIT, %zu HIGH, %zu MED, %zu LOW [Static PE Rules]",
                  desc.c_str(), get_app_state().regions.size(), crit, high, med, low);
    set_status(status);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        get_app_state().hwnd_main = hwnd;
        HINSTANCE hInst = GetModuleHandleA(nullptr);

        get_app_state().ui_font = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        get_app_state().ui_font_bold = CreateFontA(15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        get_app_state().mono_font = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        update_theme_brushes();

        const int M = 8, RH = 24;
        int x = M;

        // Row 1: Top Bar
        HWND lbl_pid = CreateWindowA("STATIC", "PID:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 28, RH, hwnd, nullptr, hInst, nullptr);
        x += 30;

        get_app_state().edit_pid = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                   x, M, 56, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PID), hInst, nullptr);
        x += 60;

        get_app_state().btn_attach = CreateWindowA("BUTTON", "Attach...",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     x, M, 66, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_ATTACH), hInst, nullptr);
        x += 70;

        get_app_state().btn_load = CreateWindowA("BUTTON", "Load",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 48, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_LOAD), hInst, nullptr);
        x += 52;

        get_app_state().btn_triage = CreateWindowA("BUTTON", "Triage",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                     x, M, 58, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_TRIAGE), hInst, nullptr);
        x += 64;

        HWND lbl_pat = CreateWindowA("STATIC", "Search Hex:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                     x, M, 76, RH, hwnd, nullptr, hInst, nullptr);
        x += 78;

        get_app_state().edit_pattern = CreateWindowA("EDIT", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                       x, M, 200, RH, hwnd, reinterpret_cast<HMENU>(ID_EDIT_PATTERN), hInst, nullptr);
        x += 204;

        get_app_state().btn_search = CreateWindowA("BUTTON", "Search",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     x, M, 58, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SEARCH), hInst, nullptr);
        x += 62;

        get_app_state().btn_next_hit = CreateWindowA("BUTTON", "Next Hit",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON | WS_DISABLED,
                                       x, M, 66, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_HIT), hInst, nullptr);
        x += 70;

        get_app_state().chk_hits_only = CreateWindowA("BUTTON", "Hits only",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 78, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HITS_ONLY), hInst, nullptr);
        x += 82;

        get_app_state().chk_heartbeat = CreateWindowA("BUTTON", "Heartbeat (1s)",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                        x, M, 110, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HEARTBEAT), hInst, nullptr);
        x += 114;

        get_app_state().btn_diff_proc = CreateWindowA("BUTTON", "Diff Proc",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                        x, M, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_DIFF_PROC), hInst, nullptr);
        x += 78;

        get_app_state().btn_yara = CreateWindowA("BUTTON", "YARA Rule",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   x, M, 78, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_YARA), hInst, nullptr);

        // Row 2: Filter Bar (Left side) & Hex Timeline Bar (Right side)
        int r2_y = M + RH + 6;

        get_app_state().combo_view_mode = CreateWindowA("COMBOBOX", "",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                          M, r2_y, 168, 160, hwnd, reinterpret_cast<HMENU>(ID_COMBO_VIEW_MODE), hInst, nullptr);
        SendMessageA(get_app_state().combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Triage Findings"));
        SendMessageA(get_app_state().combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Memory Map"));
        SendMessageA(get_app_state().combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Behavior Tracker"));
        SendMessageA(get_app_state().combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Strings"));
        SendMessageA(get_app_state().combo_view_mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("View: Process Diff"));
        SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 0, 0);

        get_app_state().combo_min_sev = CreateWindowA("COMBOBOX", "",
                                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                        M + 172, r2_y, 102, 140, hwnd, reinterpret_cast<HMENU>(ID_COMBO_MIN_SEV), hInst, nullptr);
        SendMessageA(get_app_state().combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: All (0+)"));
        SendMessageA(get_app_state().combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Low (10+)"));
        SendMessageA(get_app_state().combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Med (25+)"));
        SendMessageA(get_app_state().combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: High (50+)"));
        SendMessageA(get_app_state().combo_min_sev, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Min: Crit (80+)"));
        SendMessageA(get_app_state().combo_min_sev, CB_SETCURSEL, 0, 0);

        get_app_state().chk_hide_clean = CreateWindowA("BUTTON", "Hide clean",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                         M + 278, r2_y, 84, RH, hwnd, reinterpret_cast<HMENU>(ID_CHK_HIDE_CLEAN), hInst, nullptr);

        get_app_state().btn_export_json = CreateWindowA("BUTTON", "Export JSON",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          M + 366, r2_y, 88, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_EXPORT_JSON), hInst, nullptr);

        // Right side timeline header controls
        get_app_state().lbl_hex_info = CreateWindowA("STATIC", "Hex View",
                                       WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                       442, r2_y, 300, RH, hwnd, nullptr, hInst, nullptr);

        get_app_state().btn_snap = CreateWindowA("BUTTON", "+ Snap",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                   0, 0, 68, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_SNAP), hInst, nullptr);
        get_app_state().combo_diff = CreateWindowA("COMBOBOX", "",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL | WS_DISABLED,
                                     0, 0, 142, 160, hwnd, reinterpret_cast<HMENU>(ID_COMBO_DIFF), hInst, nullptr);
        get_app_state().btn_clear_snaps = CreateWindowA("BUTTON", "Clear",
                                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                          0, 0, 50, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_CLEAR_SNAPS), hInst, nullptr);
        get_app_state().btn_prev_page = CreateWindowA("BUTTON", "< Prev 64K",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_PREV_PAGE), hInst, nullptr);
        get_app_state().btn_next_page = CreateWindowA("BUTTON", "Next 64K >",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                        0, 0, 74, RH, hwnd, reinterpret_cast<HMENU>(ID_BTN_NEXT_PAGE), hInst, nullptr);

        // Main Panes: Left Owner-Drawn ListBox & Right Hex Edit View
        get_app_state().list_regions = CreateWindowA("LISTBOX", "",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                           WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                                       M, 66, 434, 400, hwnd, reinterpret_cast<HMENU>(ID_LIST_REGIONS), hInst, nullptr);

        get_app_state().edit_hex = CreateWindowA("EDIT", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                       WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                   442, 66, 500, 400, hwnd, reinterpret_cast<HMENU>(ID_EDIT_HEX), hInst, nullptr);
        SendMessageA(get_app_state().edit_hex, EM_SETLIMITTEXT, 0, 0);

        // Details label and Status bar
        get_app_state().lbl_triage_reasons = CreateWindowA("STATIC", "Details: Ready.",
                                             WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                             M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        get_app_state().lbl_status = CreateWindowA("STATIC", "Ready.",
                                     WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                     M, 0, 800, 18, hwnd, nullptr, hInst, nullptr);

        HWND ui_items[] = {
            lbl_pid, get_app_state().edit_pid, get_app_state().btn_attach, get_app_state().btn_load, get_app_state().btn_triage, lbl_pat, get_app_state().edit_pattern, get_app_state().btn_search,
            get_app_state().btn_next_hit, get_app_state().chk_hits_only, get_app_state().chk_heartbeat, get_app_state().btn_diff_proc, get_app_state().btn_yara,
            get_app_state().combo_view_mode, get_app_state().combo_min_sev, get_app_state().chk_hide_clean, get_app_state().btn_export_json,
            get_app_state().lbl_hex_info, get_app_state().btn_snap, get_app_state().combo_diff, get_app_state().btn_clear_snaps,
            get_app_state().btn_prev_page, get_app_state().btn_next_page, get_app_state().lbl_triage_reasons, get_app_state().lbl_status};
        for (size_t i = 0; i < sizeof(ui_items) / sizeof(ui_items[0]); ++i)
        {
            SendMessageA(ui_items[i], WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().ui_font), TRUE);
        }
        SendMessageA(get_app_state().edit_hex, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().mono_font), TRUE);

        // Modernize all push buttons with sleek flat rounded styling and interactive hover effects
        make_button_modern(get_app_state().btn_triage, ModernButtonStyle::Primary);
        make_button_modern(get_app_state().btn_export_json, ModernButtonStyle::Accent);
        make_button_modern(get_app_state().btn_attach, ModernButtonStyle::Accent);
        make_button_modern(get_app_state().btn_load, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_search, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_next_hit, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_snap, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_clear_snaps, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_prev_page, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_next_page, ModernButtonStyle::Standard);
        make_button_modern(get_app_state().btn_diff_proc, ModernButtonStyle::Accent);
        make_button_modern(get_app_state().btn_yara, ModernButtonStyle::Primary);

        // Attach application menu bar
        HMENU hMenu = create_application_menu();
        SetMenu(hwnd, hMenu);

        // Build global keyboard accelerators
        get_app_state().haccel = create_application_accelerators();

        if (GetWindowTextLengthA(get_app_state().edit_pid) > 0)
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
        CheckMenuItem(hMenu, IDM_FILE_THEME_LIGHT, (get_app_state().theme == AppTheme::Light) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_FILE_THEME_DARK, (get_app_state().theme == AppTheme::Dark) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_TRIAGE_FINDINGS, (get_app_state().view_mode == ViewMode::TriageFindings) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_MEMORY_MAP, (get_app_state().view_mode == ViewMode::MemoryMap) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_BEHAVIOR, (get_app_state().view_mode == ViewMode::BehaviorTracker) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_STRINGS, (get_app_state().view_mode == ViewMode::StringsView) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_PROCESS_DIFF, (get_app_state().view_mode == ViewMode::ProcessDiff) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_BEHAVIOR_WATCH_ALL_PRIV, get_app_state().tracker_watch_all_priv_exec.load() ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_STRINGS_TOGGLE_NEW, get_app_state().strings_filter_new_only ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_HIDE_CLEAN, get_app_state().hide_clean ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_VIEW_HITS_ONLY, (SendMessageA(get_app_state().chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED) ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(hMenu, IDM_TIMELINE_HEARTBEAT, (SendMessageA(get_app_state().chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED) ? MF_CHECKED : MF_UNCHECKED);
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
        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(get_app_state().br_control);
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        HWND hctl = reinterpret_cast<HWND>(lp);
        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        if (hctl == get_app_state().edit_hex)
        {
            SetTextColor(hdc, tc.text_normal);
            SetBkColor(hdc, tc.bg_control);
            return reinterpret_cast<INT_PTR>(get_app_state().br_control);
        }
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_window);
        return reinterpret_cast<INT_PTR>(get_app_state().br_window);
    }

    case WM_CTLCOLORLISTBOX:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(get_app_state().br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, get_app_state().br_window);
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

        MoveWindow(get_app_state().lbl_hex_info, right_x, r2_y, info_w, RH, TRUE);
        MoveWindow(get_app_state().btn_snap, btn_snap_x, r2_y, 68, RH, TRUE);
        MoveWindow(get_app_state().combo_diff, combo_x, r2_y, 142, 160, TRUE);
        MoveWindow(get_app_state().btn_clear_snaps, btn_clr_x, r2_y, 50, RH, TRUE);
        MoveWindow(get_app_state().btn_prev_page, btn_prev_x, r2_y, 74, RH, TRUE);
        MoveWindow(get_app_state().btn_next_page, btn_next_x, r2_y, 74, RH, TRUE);

        MoveWindow(get_app_state().list_regions, M, pane_top, list_w, pane_h, TRUE);
        MoveWindow(get_app_state().edit_hex, right_x, pane_top, right_w, pane_h, TRUE);

        MoveWindow(get_app_state().lbl_triage_reasons, M, h - 42, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
        MoveWindow(get_app_state().lbl_status, M, h - 22, (w > M * 2) ? w - M * 2 : 10, 18, TRUE);
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
            if (focus == get_app_state().edit_pattern || focus == get_app_state().edit_hex || focus == get_app_state().edit_pid)
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
            if (GetFocus() == get_app_state().edit_pid)
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
            LRESULT sel = SendMessageA(get_app_state().combo_view_mode, CB_GETCURSEL, 0, 0);
            if (sel == 4)
                get_app_state().view_mode = ViewMode::ProcessDiff;
            else if (sel == 3)
                get_app_state().view_mode = ViewMode::StringsView;
            else if (sel == 2)
                get_app_state().view_mode = ViewMode::BehaviorTracker;
            else if (sel == 1)
                get_app_state().view_mode = ViewMode::MemoryMap;
            else
                get_app_state().view_mode = ViewMode::TriageFindings;

            populate_region_list();
            if (get_app_state().view_mode == ViewMode::ProcessDiff)
            {
                if (!get_app_state().visible_indices.empty())
                {
                    SendMessageA(get_app_state().list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(0);
                }
                else
                {
                    SetWindowTextA(get_app_state().lbl_triage_reasons, "Diff Details: No diffs. Click Diff Proc to compare.");
                }
            }
            else if (get_app_state().view_mode == ViewMode::BehaviorTracker)
            {
                if (!get_app_state().visible_indices.empty())
                {
                    SendMessageA(get_app_state().list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(0);
                    uintptr_t target_base = get_app_state().watched_regions[get_app_state().visible_indices[0]].key.base;
                    for (size_t r = 0; r < get_app_state().regions.size(); ++r)
                    {
                        if (get_app_state().regions[r].base == target_base)
                        {
                            get_app_state().selected_region = r;
                            get_app_state().has_selection = true;
                            get_app_state().view_offset = 0;
                            display_selected_region(static_cast<SIZE_T>(-1));
                            break;
                        }
                    }
                }
                else
                {
                    SetWindowTextA(get_app_state().lbl_triage_reasons, "Behavior Details: No regions watched. Attach live process and run triage, or press Ctrl+P to pin.");
                }
            }
            else if (get_app_state().view_mode == ViewMode::StringsView)
            {
                if (!get_app_state().visible_indices.empty())
                {
                    SendMessageA(get_app_state().list_regions, LB_SETCURSEL, 0, 0);
                    update_triage_details_label(get_app_state().visible_indices[0]);
                    const auto &st = get_app_state().extracted_strings[get_app_state().visible_indices[0]];
                    for (size_t r = 0; r < get_app_state().regions.size(); ++r)
                    {
                        if (st.addr >= get_app_state().regions[r].base && st.addr < get_app_state().regions[r].base + get_app_state().regions[r].size)
                        {
                            get_app_state().selected_region = r;
                            get_app_state().has_selection = true;
                            SIZE_T rel_off = st.addr - get_app_state().regions[r].base;
                            get_app_state().view_offset = (rel_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                            display_selected_region(rel_off);
                            break;
                        }
                    }
                }
                else
                {
                    SetWindowTextA(get_app_state().lbl_triage_reasons, "Strings Details: No strings extracted. Press F7 to extract from selected region.");
                }
            }
            else
            {
                if (!get_app_state().visible_indices.empty())
                {
                    select_region_in_ui(get_app_state().visible_indices[0], 0, static_cast<SIZE_T>(-1));
                }
                else
                {
                    get_app_state().has_selection = false;
                    update_diff_combo();
                    display_selected_region(static_cast<SIZE_T>(-1));
                    SetWindowTextA(get_app_state().lbl_triage_reasons, "Details: Ready.");
                }
            }
        }
        else if (id == ID_COMBO_MIN_SEV && code == CBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(get_app_state().combo_min_sev, CB_GETCURSEL, 0, 0);
            if (sel == 1)
                get_app_state().min_sev_filter = SEV_MIN_LOW;
            else if (sel == 2)
                get_app_state().min_sev_filter = SEV_MIN_MEDIUM;
            else if (sel == 3)
                get_app_state().min_sev_filter = SEV_MIN_HIGH;
            else if (sel == 4)
                get_app_state().min_sev_filter = SEV_MIN_CRITICAL;
            else
                get_app_state().min_sev_filter = 0;
            populate_region_list();
        }
        else if (id == ID_CHK_HIDE_CLEAN)
        {
            get_app_state().hide_clean = (SendMessageA(get_app_state().chk_hide_clean, BM_GETCHECK, 0, 0) == BST_CHECKED);
            populate_region_list();
        }
        else if (id == ID_CHK_HITS_ONLY)
        {
            populate_region_list();
            if (!get_app_state().visible_indices.empty())
            {
                select_region_in_ui(get_app_state().visible_indices[0], 0, static_cast<SIZE_T>(-1));
            }
            else
            {
                get_app_state().has_selection = false;
                update_diff_combo();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_LIST_REGIONS && code == LBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(get_app_state().list_regions, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && static_cast<size_t>(sel) < get_app_state().visible_indices.size())
            {
                size_t reg_idx = get_app_state().visible_indices[static_cast<size_t>(sel)];
                if (get_app_state().view_mode == ViewMode::ProcessDiff)
                {
                    if (reg_idx < get_app_state().process_diffs.size())
                    {
                        update_triage_details_label(reg_idx);
                        uintptr_t target_base = get_app_state().process_diffs[reg_idx].base;
                        for (size_t r = 0; r < get_app_state().regions.size(); ++r)
                        {
                            if (get_app_state().regions[r].base == target_base)
                            {
                                get_app_state().selected_region = r;
                                get_app_state().has_selection = true;
                                get_app_state().view_offset = 0;
                                display_selected_region(static_cast<SIZE_T>(-1));
                                break;
                            }
                        }
                    }
                }
                else if (get_app_state().view_mode == ViewMode::BehaviorTracker)
                {
                    if (reg_idx < get_app_state().watched_regions.size())
                    {
                        update_triage_details_label(reg_idx);
                        uintptr_t target_base = get_app_state().watched_regions[reg_idx].key.base;
                        for (size_t r = 0; r < get_app_state().regions.size(); ++r)
                        {
                            if (get_app_state().regions[r].base == target_base)
                            {
                                get_app_state().selected_region = r;
                                get_app_state().has_selection = true;
                                get_app_state().view_offset = 0;
                                display_selected_region(static_cast<SIZE_T>(-1));
                                break;
                            }
                        }
                    }
                }
                else if (get_app_state().view_mode == ViewMode::StringsView)
                {
                    if (reg_idx < get_app_state().extracted_strings.size())
                    {
                        update_triage_details_label(reg_idx);
                        const auto &st = get_app_state().extracted_strings[reg_idx];
                        for (size_t r = 0; r < get_app_state().regions.size(); ++r)
                        {
                            if (st.addr >= get_app_state().regions[r].base && st.addr < get_app_state().regions[r].base + get_app_state().regions[r].size)
                            {
                                get_app_state().selected_region = r;
                                get_app_state().has_selection = true;
                                SIZE_T rel_off = st.addr - get_app_state().regions[r].base;
                                get_app_state().view_offset = (rel_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                                display_selected_region(rel_off);
                                break;
                            }
                        }
                    }
                }
                else
                {
                    if (reg_idx < get_app_state().regions.size())
                    {
                        SIZE_T first_hit = get_app_state().regions[reg_idx].hits.empty()
                                               ? static_cast<SIZE_T>(-1)
                                               : get_app_state().regions[reg_idx].hits[0];
                        SIZE_T page_off = (first_hit == static_cast<SIZE_T>(-1))
                                              ? 0
                                              : (first_hit / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
                        get_app_state().selected_region = reg_idx;
                        get_app_state().has_selection = true;
                        get_app_state().view_offset = page_off;
                        display_selected_region(first_hit);
                        update_triage_details_label(reg_idx);
                    }
                }
            }
        }
        else if (id == ID_BTN_PREV_PAGE)
        {
            if (get_app_state().has_selection && get_app_state().view_offset >= VIEW_PAGE_SIZE)
            {
                get_app_state().view_offset -= VIEW_PAGE_SIZE;
                invalidate_hex_cache();
                display_selected_region(static_cast<SIZE_T>(-1));
            }
        }
        else if (id == ID_BTN_NEXT_PAGE)
        {
            if (get_app_state().has_selection && get_app_state().selected_region < get_app_state().regions.size() &&
                get_app_state().view_offset + VIEW_PAGE_SIZE < get_app_state().regions[get_app_state().selected_region].size)
            {
                get_app_state().view_offset += VIEW_PAGE_SIZE;
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
            bool checked = (SendMessageA(get_app_state().chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (checked)
            {
                if (get_app_state().has_selection && get_app_state().selected_region < get_app_state().regions.size())
                {
                    RegionInfo &reg = get_app_state().regions[get_app_state().selected_region];
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
            if (focused == get_app_state().edit_hex)
            {
                DWORD sel_start = 0, sel_end = 0;
                SendMessageA(get_app_state().edit_hex, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start), reinterpret_cast<LPARAM>(&sel_end));
                if (sel_start != sel_end)
                {
                    SendMessageA(get_app_state().edit_hex, WM_COPY, 0, 0);
                    return 0;
                }
            }
            if (get_app_state().has_selection && get_app_state().selected_region < get_app_state().regions.size())
            {
                std::string addr_hex = to_hex_string(get_app_state().regions[get_app_state().selected_region].base);
                copy_text_to_clipboard(hwnd, addr_hex);
                set_status("Copied region address " + addr_hex + " to clipboard.");
            }
        }
        else if (id == IDM_EDIT_COPY_HEX)
        {
            int len = GetWindowTextLengthA(get_app_state().edit_hex);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(get_app_state().edit_hex, buf.data(), len + 1);
                copy_text_to_clipboard(hwnd, buf.data());
                set_status("Hex dump copied to clipboard (" + std::to_string(len) + " bytes).");
            }
        }
        else if (id == IDM_EDIT_FIND_PATTERN)
        {
            SetFocus(get_app_state().edit_pattern);
            SendMessageA(get_app_state().edit_pattern, EM_SETSEL, 0, -1);
        }
        else if (id == IDM_EDIT_FIND_NEXT)
        {
            PostMessageA(hwnd, WM_COMMAND, ID_BTN_NEXT_HIT, 0);
        }
        else if (id == IDM_VIEW_TRIAGE_FINDINGS)
        {
            SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 0, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(get_app_state().combo_view_mode));
        }
        else if (id == IDM_VIEW_MEMORY_MAP)
        {
            SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 1, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(get_app_state().combo_view_mode));
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
            bool cur = (SendMessageA(get_app_state().chk_hide_clean, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(get_app_state().chk_hide_clean, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
            SendMessageA(hwnd, WM_COMMAND, ID_CHK_HIDE_CLEAN, 0);
        }
        else if (id == IDM_VIEW_HITS_ONLY)
        {
            bool cur = (SendMessageA(get_app_state().chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(get_app_state().chk_hits_only, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
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
            bool cur = (SendMessageA(get_app_state().chk_heartbeat, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SendMessageA(get_app_state().chk_heartbeat, BM_SETCHECK, cur ? BST_UNCHECKED : BST_CHECKED, 0);
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
            SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 2, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(get_app_state().combo_view_mode));
        }
        else if (id == IDM_VIEW_STRINGS)
        {
            SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 3, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(get_app_state().combo_view_mode));
        }
        else if (id == IDM_VIEW_PROCESS_DIFF)
        {
            SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 4, 0);
            SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_COMBO_VIEW_MODE, CBN_SELCHANGE), reinterpret_cast<LPARAM>(get_app_state().combo_view_mode));
        }
        else if (id == IDM_BEHAVIOR_PIN)
        {
            if (get_app_state().has_selection && get_app_state().selected_region < get_app_state().regions.size())
            {
                const auto &reg = get_app_state().regions[get_app_state().selected_region];
                auto it = std::find_if(get_app_state().watched_regions.begin(), get_app_state().watched_regions.end(),
                    [&](const WatchedRegionState &w) { return w.key.base == reg.base && w.key.alloc_base == reg.alloc_base; });
                if (it != get_app_state().watched_regions.end())
                {
                    it->is_pinned = !it->is_pinned;
                    set_status(std::string(it->is_pinned ? "Pinned region 0x" : "Unpinned region 0x") + to_hex_string(reg.base));
                }
                else
                {
                    WatchedRegionState nw;
                    nw.key.base = reg.base;
                    nw.key.alloc_base = reg.alloc_base;
                    nw.key.generation = get_app_state().region_generations[reg.base];
                    nw.size = reg.size;
                    nw.type = reg.type;
                    nw.alloc_protect = reg.alloc_protect;
                    nw.is_pinned = true;
                    get_app_state().watched_regions.push_back(std::move(nw));
                    set_status("Pinned and watching region 0x" + to_hex_string(reg.base));
                }
                if (get_app_state().view_mode == ViewMode::BehaviorTracker)
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
            bool cur = get_app_state().tracker_watch_all_priv_exec.load();
            get_app_state().tracker_watch_all_priv_exec.store(!cur);
            if (!cur)
            {
                for (const auto &reg : get_app_state().regions)
                {
                    bool is_exec = (reg.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    if (reg.type == MEM_PRIVATE && is_exec)
                    {
                        auto it = std::find_if(get_app_state().watched_regions.begin(), get_app_state().watched_regions.end(),
                            [&](const WatchedRegionState &w) { return w.key.base == reg.base; });
                        if (it == get_app_state().watched_regions.end())
                        {
                            WatchedRegionState nw;
                            nw.key.base = reg.base;
                            nw.key.alloc_base = reg.alloc_base;
                            nw.key.generation = get_app_state().region_generations[reg.base];
                            nw.size = reg.size;
                            nw.type = reg.type;
                            nw.alloc_protect = reg.alloc_protect;
                            nw.is_pinned = false;
                            get_app_state().watched_regions.push_back(std::move(nw));
                        }
                    }
                }
                set_status("Behavior Tracker: Watching all private executable regions (ON).");
            }
            else
            {
                set_status("Behavior Tracker: Watch all private executable regions (OFF).");
            }
            if (get_app_state().view_mode == ViewMode::BehaviorTracker)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_BEHAVIOR_CLEAR)
        {
            for (auto &w : get_app_state().watched_regions)
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
            get_app_state().tracker_total_samples.store(0);
            get_app_state().tracker_partial_samples.store(0);
            set_status("Behavior tracker sample history cleared.");
            if (get_app_state().view_mode == ViewMode::BehaviorTracker)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_STRINGS_BASELINE)
        {
            get_app_state().string_baselines.clear();
            for (const auto &st : get_app_state().extracted_strings)
            {
                get_app_state().string_baselines[st.region_base].insert(st.content_hash);
            }
            for (auto &st : get_app_state().extracted_strings)
            {
                st.is_new = false;
            }
            set_status("String baseline set (" + std::to_string(get_app_state().extracted_strings.size()) + " strings across " +
                       std::to_string(get_app_state().string_baselines.size()) + " regions).");
            if (get_app_state().view_mode == ViewMode::StringsView)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_STRINGS_TOGGLE_NEW)
        {
            get_app_state().strings_filter_new_only = !get_app_state().strings_filter_new_only;
            set_status(get_app_state().strings_filter_new_only ? "Strings View: Showing only NEW strings since baseline." : "Strings View: Showing all extracted strings.");
            if (get_app_state().view_mode == ViewMode::StringsView)
            {
                populate_region_list();
            }
        }
        else if (id == IDM_STRINGS_EXTRACT_SEL)
        {
            if (get_app_state().current_source != nullptr && get_app_state().has_selection && get_app_state().selected_region < get_app_state().regions.size())
            {
                set_status("Extracting ASCII & UTF-16 strings from selected region...");
                extract_all_strings_from_source(get_app_state().current_source, get_app_state().regions, static_cast<int>(get_app_state().selected_region), get_app_state().strings_min_len, get_app_state().extracted_strings, &get_app_state().string_baselines);
                get_app_state().view_mode = ViewMode::StringsView;
                SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 3, 0);
                populate_region_list();
                set_status("Extracted " + std::to_string(get_app_state().extracted_strings.size()) + " strings from region 0x" + to_hex_string(get_app_state().regions[get_app_state().selected_region].base));
            }
            else
            {
                set_status("Select a region first to extract strings.");
            }
        }
        else if (id == IDM_STRINGS_EXTRACT_ALL)
        {
            if (get_app_state().current_source != nullptr && !get_app_state().regions.empty())
            {
                set_status("Extracting ASCII & UTF-16 strings across all regions (capped)...");
                extract_all_strings_from_source(get_app_state().current_source, get_app_state().regions, -1, get_app_state().strings_min_len, get_app_state().extracted_strings, &get_app_state().string_baselines);
                get_app_state().view_mode = ViewMode::StringsView;
                SendMessageA(get_app_state().combo_view_mode, CB_SETCURSEL, 3, 0);
                populate_region_list();
                set_status("Extracted " + std::to_string(get_app_state().extracted_strings.size()) + " strings across " + std::to_string(get_app_state().regions.size()) + " regions.");
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
            if (get_app_state().tracker_active.load() && get_app_state().current_source != nullptr && get_app_state().current_source->capabilities().is_live && !get_app_state().target_process_exited.load())
            {
                bool expected = false;
                if (get_app_state().tracker_busy.compare_exchange_strong(expected, true))
                {
                    WorkerTask *task = new WorkerTask();
                    task->task_type = WorkerTaskType::BehaviorTick;
                    task->hwnd = hwnd;
                    task->source = get_app_state().current_source;

                    HANDLE th = CreateThread(nullptr, 0, WorkerThreadProc, task, 0, nullptr);
                    if (th != nullptr)
                    {
                        CloseHandle(th);
                    }
                    else
                    {
                        get_app_state().tracker_busy.store(false);
                        delete task;
                    }
                }
                else
                {
                    get_app_state().tracker_partial_samples++;
                }
            }

            if (get_app_state().has_selection && get_app_state().selected_region < get_app_state().regions.size() && get_app_state().view_mode != ViewMode::BehaviorTracker && get_app_state().view_mode != ViewMode::StringsView)
            {
                display_selected_region(static_cast<SIZE_T>(-1));
            }
            return 0;
        }
        break;

    case WM_BEHAVIOR_TICK_DONE:
    {
        if (get_app_state().tracker_active.load())
        {
            char status_buf[256];
            if (get_app_state().target_process_exited.load())
            {
                std::snprintf(status_buf, sizeof(status_buf),
                              "Tracker: Target process exited. Total samples: %llu (partial: %llu).",
                              static_cast<unsigned long long>(get_app_state().tracker_total_samples.load()),
                              static_cast<unsigned long long>(get_app_state().tracker_partial_samples.load()));
            }
            else
            {
                std::snprintf(status_buf, sizeof(status_buf),
                              "Tracker: %llu samples (%llu partial) @ %ums. Note: Polling limits apply; sub-second flips may be missed. Help: F1",
                              static_cast<unsigned long long>(get_app_state().tracker_total_samples.load()),
                              static_cast<unsigned long long>(get_app_state().tracker_partial_samples.load()),
                              static_cast<unsigned int>(get_app_state().tracker_interval_ms.load()));
            }
            SetWindowTextA(get_app_state().lbl_status, status_buf);
        }

        if (get_app_state().view_mode == ViewMode::BehaviorTracker)
        {
            populate_region_list();
            if (get_app_state().has_selection && get_app_state().selected_region < get_app_state().watched_regions.size())
            {
                update_triage_details_label(get_app_state().selected_region);
            }
        }
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd, IDT_HEARTBEAT);
        get_app_state().scan_abort.store(true, std::memory_order_relaxed);
        if (get_app_state().h_worker_thread != nullptr)
        {
            WaitForSingleObject(get_app_state().h_worker_thread, 1000);
            CloseHandle(get_app_state().h_worker_thread);
            get_app_state().h_worker_thread = nullptr;
        }
        close_target_proc();
        if (get_app_state().mono_font)
            DeleteObject(get_app_state().mono_font);
        if (get_app_state().ui_font)
            DeleteObject(get_app_state().ui_font);
        if (get_app_state().ui_font_bold)
            DeleteObject(get_app_state().ui_font_bold);
        if (get_app_state().br_window)
            DeleteObject(get_app_state().br_window);
        if (get_app_state().br_control)
            DeleteObject(get_app_state().br_control);
        if (get_app_state().haccel)
        {
            DestroyAcceleratorTable(get_app_state().haccel);
            get_app_state().haccel = nullptr;
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
        if (get_app_state().haccel != nullptr && TranslateAcceleratorA(hwnd, get_app_state().haccel, &msg))
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

} // namespace gui
