// src/gui/pe_integrity_dialog.cpp
// Deadeye PE Integrity & Memory Comparison Dialog Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/pe_integrity_dialog.hpp"
#include "gui/app.hpp"
#include "gui/controls.hpp"
#include "gui/views.hpp"
#include "core/pe_integrity.hpp"
#include "core/util.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <cstdio>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace gui {

#define ID_PEINT_COMBO_MODULE     8101
#define ID_PEINT_BTN_REFRESH      8102
#define ID_PEINT_EDIT_BASE        8103
#define ID_PEINT_EDIT_SIZE        8104
#define ID_PEINT_EDIT_DISKPATH    8105
#define ID_PEINT_BTN_BROWSE       8106
#define ID_PEINT_BTN_VERIFY       8107
#define ID_PEINT_CHK_HOOKS        8108
#define ID_PEINT_CHK_EXPECTED     8109
#define ID_PEINT_BTN_COMPARE      8110
#define ID_PEINT_BTN_CANCEL       8111
#define ID_PEINT_COMBO_CAT_FILTER 8112
#define ID_PEINT_COMBO_SEV_FILTER 8113
#define ID_PEINT_EDIT_SEC_FILTER  8114
#define ID_PEINT_CHK_HIDE_EXP     8115
#define ID_PEINT_LIST_RESULTS     8116
#define ID_PEINT_EDIT_PREVIEW     8117
#define ID_PEINT_BTN_GOTO         8118
#define ID_PEINT_BTN_EXPORT_JSON  8119
#define ID_PEINT_BTN_ADD_TIMELINE 8120
#define ID_PEINT_BTN_CLOSE        8121

#define WM_PE_INTEGRITY_PROGRESS  (WM_USER + 20)
#define WM_PE_INTEGRITY_COMPLETE  (WM_USER + 21)

struct PeIntegrityDialogData
{
    HWND hComboModule = nullptr;
    HWND hBtnRefresh = nullptr;
    HWND hEditBase = nullptr;
    HWND hEditSize = nullptr;
    HWND hEditDiskPath = nullptr;
    HWND hBtnBrowse = nullptr;
    HWND hBtnVerify = nullptr;
    HWND hChkHooks = nullptr;
    HWND hChkExpected = nullptr;
    HWND hBtnCompare = nullptr;
    HWND hBtnCancel = nullptr;
    HWND hComboCatFilter = nullptr;
    HWND hComboSevFilter = nullptr;
    HWND hEditSecFilter = nullptr;
    HWND hChkHideExp = nullptr;
    HWND hLblSummary = nullptr;
    HWND hListResults = nullptr;
    HWND hEditPreview = nullptr;
    HWND hLblStatus = nullptr;
    HWND hBtnGoto = nullptr;
    HWND hBtnExportJson = nullptr;
    HWND hBtnAddTimeline = nullptr;
    HWND hBtnClose = nullptr;

    std::vector<core::LoadedModuleInfo> modules;
    int selected_module_idx = -1;

    core::PeIntegrityReport report;
    std::vector<size_t> filtered_indices;

    std::atomic<bool> is_comparing{false};
    std::atomic<bool> abort_flag{false};
    HANDLE hWorkerThread = nullptr;

    float progress_pct = 0.0f;
    std::string progress_status;
    bool scan_success = false;
    std::string scan_error;
};

struct PeIntegrityThreadParams
{
    HWND hwnd = nullptr;
    PeIntegrityDialogData *data = nullptr;
    HANDLE proc = nullptr;
    uintptr_t live_base = 0;
    std::string disk_path;
    core::PeIntegrityOptions options;
    std::vector<core::LoadedModuleInfo> all_modules;
};

static std::string format_hex_dump_compact(const std::vector<uint8_t> &bytes, size_t max_bytes = 128)
{
    if (bytes.empty())
    {
        return "(empty / 0 bytes)\r\n";
    }

    std::ostringstream ss;
    size_t limit = (std::min)(bytes.size(), max_bytes);
    for (size_t row = 0; row < limit; row += 16)
    {
        char offset_buf[16];
        std::snprintf(offset_buf, sizeof(offset_buf), "+%04zX  ", row);
        ss << offset_buf;

        for (size_t col = 0; col < 16; ++col)
        {
            if (row + col < limit)
            {
                char byte_buf[4];
                std::snprintf(byte_buf, sizeof(byte_buf), "%02X ", bytes[row + col]);
                ss << byte_buf;
            }
            else
            {
                ss << "   ";
            }
            if (col == 7) ss << " ";
        }

        ss << " |";
        for (size_t col = 0; col < 16; ++col)
        {
            if (row + col < limit)
            {
                uint8_t b = bytes[row + col];
                ss << (std::isprint(b) ? static_cast<char>(b) : '.');
            }
        }
        ss << "|\r\n";
    }

    if (bytes.size() > max_bytes)
    {
        ss << "... (" << (bytes.size() - max_bytes) << " additional bytes truncated)\r\n";
    }

    return ss.str();
}

static DWORD WINAPI PeIntegrityWorkerThreadProc(LPVOID lpParam)
{
    auto *params = reinterpret_cast<PeIntegrityThreadParams*>(lpParam);
    if (!params) return 0;

    auto progress_cb = [params](float progress, const std::string &status) {
        if (params->data != nullptr)
        {
            params->data->progress_pct = progress;
            params->data->progress_status = status;
            PostMessageA(params->hwnd, WM_PE_INTEGRITY_PROGRESS, 0, 0);
        }
    };

    std::string err;
    core::PeIntegrityReport report;
    bool ok = core::compare_pe_integrity(
        params->proc,
        params->live_base,
        params->disk_path,
        params->options,
        report,
        err,
        &params->data->abort_flag,
        progress_cb,
        &params->all_modules);

    if (params->data != nullptr)
    {
        params->data->scan_success = ok;
        params->data->scan_error = err;
        params->data->report = std::move(report);
    }

    PostMessageA(params->hwnd, WM_PE_INTEGRITY_COMPLETE, 0, 0);
    delete params;
    return 0;
}

static void update_module_selection(PeIntegrityDialogData *data)
{
    if (!data || !data->hComboModule) return;
    int sel = static_cast<int>(SendMessageA(data->hComboModule, CB_GETCURSEL, 0, 0));
    if (sel < 0 || sel >= static_cast<int>(data->modules.size()))
    {
        data->selected_module_idx = -1;
        SetWindowTextA(data->hEditBase, "");
        SetWindowTextA(data->hEditSize, "");
        SetWindowTextA(data->hEditDiskPath, "");
        return;
    }

    data->selected_module_idx = sel;
    const auto &mod = data->modules[static_cast<size_t>(sel)];

    SetWindowTextA(data->hEditBase, ("0x" + to_hex_string(mod.base_address)).c_str());
    SetWindowTextA(data->hEditSize, fmt_size_short(mod.image_size).c_str());
    SetWindowTextA(data->hEditDiskPath, mod.module_path.c_str());
}

static void refresh_module_list(HWND hwnd, PeIntegrityDialogData *data)
{
    if (!data) return;

    SendMessageA(data->hComboModule, CB_RESETCONTENT, 0, 0);
    data->modules.clear();
    data->selected_module_idx = -1;
    SetWindowTextA(data->hEditBase, "");
    SetWindowTextA(data->hEditSize, "");
    SetWindowTextA(data->hEditDiskPath, "");

    DWORD pid = get_app_state().current_pid;
    HANDLE proc = get_app_state().target_proc;

    if (pid == 0 || proc == nullptr)
    {
        SetWindowTextA(data->hLblStatus, "No target process attached. Please attach to a process first.");
        return;
    }

    std::string err;
    if (!core::enumerate_process_modules(pid, proc, data->modules, err) || data->modules.empty())
    {
        SetWindowTextA(data->hLblStatus, ("Module enumeration failed: " + err).c_str());
        return;
    }

    for (const auto &mod : data->modules)
    {
        std::string label = mod.module_name + " (0x" + to_hex_string(mod.base_address) + " - " + fmt_size_short(mod.image_size) + ")";
        SendMessageA(data->hComboModule, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
    }

    SendMessageA(data->hComboModule, CB_SETCURSEL, 0, 0);
    update_module_selection(data);

    char status[256];
    std::snprintf(status, sizeof(status), "Found %zu loaded module(s) in PID %lu.", data->modules.size(), static_cast<unsigned long>(pid));
    SetWindowTextA(data->hLblStatus, status);
    (void)hwnd;
}

static void populate_filtered_listview(PeIntegrityDialogData *data)
{
    if (!data || !data->hListResults) return;

    HWND hList = data->hListResults;
    SendMessageA(hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hList);
    data->filtered_indices.clear();

    int cat_filter = static_cast<int>(SendMessageA(data->hComboCatFilter, CB_GETCURSEL, 0, 0));
    int sev_filter = static_cast<int>(SendMessageA(data->hComboSevFilter, CB_GETCURSEL, 0, 0));
    bool hide_expected = (SendMessageA(data->hChkHideExp, BM_GETCHECK, 0, 0) == BST_CHECKED);

    char sec_buf[64] = {};
    GetWindowTextA(data->hEditSecFilter, sec_buf, sizeof(sec_buf));
    std::string sec_query = sec_buf;
    std::transform(sec_query.begin(), sec_query.end(), sec_query.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (size_t i = 0; i < data->report.differences.size(); ++i)
    {
        const auto &diff = data->report.differences[i];

        if (hide_expected && diff.is_expected)
        {
            continue;
        }

        // Category filter
        if (cat_filter > 0)
        {
            switch (cat_filter)
            {
            case 1: if (diff.category != core::PeIntegrityCategory::InlineHookCandidate) continue; break;
            case 2: if (diff.category != core::PeIntegrityCategory::ModifiedExecutableCode) continue; break;
            case 3: if (diff.category != core::PeIntegrityCategory::ModifiedNonExecutableData) continue; break;
            case 4: if (diff.category != core::PeIntegrityCategory::ImportAddressTable) continue; break;
            case 5: if (diff.category != core::PeIntegrityCategory::RelocationResolved) continue; break;
            case 6: if (diff.category != core::PeIntegrityCategory::MissingSection && diff.category != core::PeIntegrityCategory::UnexpectedSection) continue; break;
            case 7: if (diff.category != core::PeIntegrityCategory::UnreadableMemory) continue; break;
            default: break;
            }
        }

        // Severity filter
        if (sev_filter > 0)
        {
            switch (sev_filter)
            {
            case 1: if (diff.severity != core::PeIntegritySeverity::Critical) continue; break;
            case 2: if (diff.severity != core::PeIntegritySeverity::Warning) continue; break;
            case 3: if (diff.severity != core::PeIntegritySeverity::Informational) continue; break;
            default: break;
            }
        }

        // Section filter
        if (!sec_query.empty())
        {
            std::string sec_lower = diff.section_name;
            std::transform(sec_lower.begin(), sec_lower.end(), sec_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (sec_lower.find(sec_query) == std::string::npos)
            {
                continue;
            }
        }

        int item_idx = static_cast<int>(data->filtered_indices.size());
        data->filtered_indices.push_back(i);

        LVITEMA item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = item_idx;
        item.iSubItem = 0;
        std::string num_str = std::to_string(item_idx + 1);
        item.pszText = const_cast<char*>(num_str.c_str());
        item.lParam = static_cast<LPARAM>(i);
        ListView_InsertItem(hList, &item);

        std::string cat_str = core::format_integrity_category(diff.category);
        ListView_SetItemText(hList, item_idx, 1, const_cast<char*>(cat_str.c_str()));

        std::string sev_str = core::format_integrity_severity(diff.severity);
        ListView_SetItemText(hList, item_idx, 2, const_cast<char*>(sev_str.c_str()));

        ListView_SetItemText(hList, item_idx, 3, const_cast<char*>(diff.section_name.c_str()));

        std::string va_str = "0x" + to_hex_string(diff.virtual_address);
        ListView_SetItemText(hList, item_idx, 4, const_cast<char*>(va_str.c_str()));

        std::string rva_str = "0x" + to_hex_string(diff.rva);
        ListView_SetItemText(hList, item_idx, 5, const_cast<char*>(rva_str.c_str()));

        std::string off_str = "0x" + to_hex_string(diff.file_offset);
        ListView_SetItemText(hList, item_idx, 6, const_cast<char*>(off_str.c_str()));

        std::string len_str = std::to_string(diff.length);
        ListView_SetItemText(hList, item_idx, 7, const_cast<char*>(len_str.c_str()));

        std::string hook_sym;
        if (diff.is_hook_candidate)
        {
            hook_sym = "HOOK -> 0x" + to_hex_string(diff.hook_target_address);
            if (!diff.hook_target_module.empty()) hook_sym += " (" + diff.hook_target_module + ")";
        }
        else if (!diff.nearest_export_name.empty())
        {
            hook_sym = diff.nearest_export_name;
            if (diff.export_offset != 0)
            {
                hook_sym += (diff.export_offset > 0 ? " +0x" : " -0x") + to_hex_string(std::abs(diff.export_offset));
            }
        }
        ListView_SetItemText(hList, item_idx, 8, const_cast<char*>(hook_sym.c_str()));

        ListView_SetItemText(hList, item_idx, 9, const_cast<char*>(diff.explanation.c_str()));
    }

    SendMessageA(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, nullptr, TRUE);

    // Update summary text
    char sum_buf[256];
    std::snprintf(sum_buf, sizeof(sum_buf), "Showing %zu / %zu diffs (%zu Hook, %zu Code, %zu Data, %zu IAT, %zu Reloc)",
                  data->filtered_indices.size(),
                  data->report.differences.size(),
                  data->report.count_hook_candidates,
                  data->report.count_executable_diffs,
                  data->report.count_data_diffs,
                  data->report.count_iat_diffs,
                  data->report.count_reloc_diffs);
    SetWindowTextA(data->hLblSummary, sum_buf);
}

static void update_preview_pane(PeIntegrityDialogData *data)
{
    if (!data || !data->hListResults || !data->hEditPreview) return;

    int sel = ListView_GetNextItem(data->hListResults, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= static_cast<int>(data->filtered_indices.size()))
    {
        SetWindowTextA(data->hEditPreview, "Select a difference item above to view detailed byte comparison and hook disassembly.");
        return;
    }

    size_t diff_idx = data->filtered_indices[static_cast<size_t>(sel)];
    if (diff_idx >= data->report.differences.size()) return;

    const auto &diff = data->report.differences[diff_idx];

    std::ostringstream ss;
    ss << "=== PE Integrity Difference Details ===\r\n";
    ss << "Category: " << core::format_integrity_category(diff.category)
       << " | Severity: " << core::format_integrity_severity(diff.severity);
    if (diff.is_expected) ss << " [Expected Loader Fixup]";
    ss << "\r\n";

    ss << "Virtual Address: 0x" << to_hex_string(diff.virtual_address)
       << " | RVA: 0x" << to_hex_string(diff.rva)
       << " | File Offset: 0x" << to_hex_string(diff.file_offset)
       << " | Section: " << (diff.section_name.empty() ? "(none)" : diff.section_name)
       << " | Length: " << diff.length << " bytes\r\n";

    if (!diff.nearest_export_name.empty())
    {
        ss << "Nearest Export: " << diff.nearest_export_name;
        if (diff.export_offset != 0)
        {
            ss << (diff.export_offset > 0 ? " +0x" : " -0x") << to_hex_string(std::abs(diff.export_offset));
        }
        ss << "\r\n";
    }

    if (diff.is_hook_candidate)
    {
        ss << "Hook Instruction: " << diff.hook_instruction_desc << "\r\n";
        ss << "Hook Target Address: 0x" << to_hex_string(diff.hook_target_address);
        if (!diff.hook_target_module.empty())
        {
            ss << " (Points to module: " << diff.hook_target_module << ")";
        }
        else
        {
            ss << " (Points outside module boundaries / unbacked memory)";
        }
        ss << "\r\n";
    }

    if (!diff.explanation.empty())
    {
        ss << "Analysis Note: " << diff.explanation << "\r\n";
    }

    ss << "\r\n--- On-Disk Binary Image Bytes (" << diff.disk_bytes.size() << " bytes) ---\r\n";
    ss << format_hex_dump_compact(diff.disk_bytes);

    ss << "\r\n--- Live Target Memory Bytes (" << diff.live_bytes.size() << " bytes) ---\r\n";
    ss << format_hex_dump_compact(diff.live_bytes);

    std::string text = ss.str();
    SetWindowTextA(data->hEditPreview, text.c_str());
}

static void navigate_to_selected_diff(PeIntegrityDialogData *data)
{
    if (!data || !data->hListResults) return;

    int sel = ListView_GetNextItem(data->hListResults, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= static_cast<int>(data->filtered_indices.size()))
    {
        return;
    }

    size_t diff_idx = data->filtered_indices[static_cast<size_t>(sel)];
    if (diff_idx >= data->report.differences.size()) return;

    const auto &diff = data->report.differences[diff_idx];
    uintptr_t target_addr = diff.virtual_address;
    if (target_addr == 0) return;

    for (size_t i = 0; i < get_app_state().regions.size(); ++i)
    {
        const auto &reg = get_app_state().regions[i];
        if (target_addr >= reg.base && target_addr < reg.base + reg.size)
        {
            SIZE_T offset = target_addr - reg.base;
            SIZE_T page_off = (offset / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
            select_region_in_ui(i, page_off, offset);
            set_status("Navigated to PE difference at 0x" + to_hex_string(target_addr));
            SetForegroundWindow(get_app_state().hwnd_main);
            break;
        }
    }
}

static void on_browse_disk_file(HWND hwnd, PeIntegrityDialogData *data)
{
    char file_buf[MAX_PATH] = {};
    GetWindowTextA(data->hEditDiskPath, file_buf, sizeof(file_buf));

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "PE Executables & Libraries (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrTitle = "Select Corresponding On-Disk PE Binary";

    if (GetOpenFileNameA(&ofn))
    {
        SetWindowTextA(data->hEditDiskPath, file_buf);
    }
}

static void on_verify_module_match(HWND hwnd, PeIntegrityDialogData *data)
{
    char path_buf[MAX_PATH] = {};
    GetWindowTextA(data->hEditDiskPath, path_buf, sizeof(path_buf));
    std::string disk_path = path_buf;

    char base_buf[64] = {};
    GetWindowTextA(data->hEditBase, base_buf, sizeof(base_buf));
    std::string base_str = base_buf;

    uintptr_t base_addr = 0;
    while (!base_str.empty() && std::isspace(static_cast<unsigned char>(base_str.front()))) base_str.erase(base_str.begin());
    if (base_str.rfind("0x", 0) == 0 || base_str.rfind("0X", 0) == 0) base_str = base_str.substr(2);
    try {
        base_addr = static_cast<uintptr_t>(std::stoull(base_str, nullptr, 16));
    } catch (...) {}

    if (disk_path.empty() || base_addr == 0)
    {
        MessageBoxA(hwnd, "Please select a loaded module or provide valid disk path and base address.", "Verification Error", MB_OK | MB_ICONWARNING);
        return;
    }

    std::string err;
    if (core::verify_pe_module_match(disk_path, get_app_state().target_proc, base_addr, err))
    {
        MessageBoxA(hwnd, "Verification Successful!\r\nOn-disk PE headers match loaded target module architecture and header fields.", "PE Match Verified", MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        MessageBoxA(hwnd, ("PE Header Verification Warning:\r\n" + err).c_str(), "PE Match Verification", MB_OK | MB_ICONWARNING);
    }
}

static void on_start_comparison(HWND hwnd, PeIntegrityDialogData *data)
{
    if (!data || data->is_comparing.load()) return;

    DWORD pid = get_app_state().current_pid;
    HANDLE proc = get_app_state().target_proc;

    if (pid == 0 || proc == nullptr)
    {
        MessageBoxA(hwnd, "No target process attached. Please attach to a target process first.", "Target Error", MB_OK | MB_ICONWARNING);
        return;
    }

    char path_buf[MAX_PATH] = {};
    GetWindowTextA(data->hEditDiskPath, path_buf, sizeof(path_buf));
    std::string disk_path = path_buf;

    char base_buf[64] = {};
    GetWindowTextA(data->hEditBase, base_buf, sizeof(base_buf));
    std::string base_str = base_buf;
    uintptr_t base_addr = 0;
    while (!base_str.empty() && std::isspace(static_cast<unsigned char>(base_str.front()))) base_str.erase(base_str.begin());
    if (base_str.rfind("0x", 0) == 0 || base_str.rfind("0X", 0) == 0) base_str = base_str.substr(2);
    try {
        base_addr = static_cast<uintptr_t>(std::stoull(base_str, nullptr, 16));
    } catch (...) {}

    if (disk_path.empty() || base_addr == 0)
    {
        MessageBoxA(hwnd, "Please select a loaded module or specify a valid disk path and base address.", "Input Error", MB_OK | MB_ICONWARNING);
        return;
    }

    data->is_comparing.store(true);
    data->abort_flag.store(false);
    data->scan_success = false;
    data->scan_error.clear();

    EnableWindow(data->hBtnCompare, FALSE);
    EnableWindow(data->hBtnRefresh, FALSE);
    EnableWindow(data->hBtnBrowse, FALSE);
    EnableWindow(data->hBtnVerify, FALSE);
    EnableWindow(data->hComboModule, FALSE);
    EnableWindow(data->hBtnCancel, TRUE);

    SetWindowTextA(data->hLblStatus, "Initiating PE memory comparison against disk image...");

    core::PeIntegrityOptions opts;
    opts.perform_hook_analysis = (SendMessageA(data->hChkHooks, BM_GETCHECK, 0, 0) == BST_CHECKED);
    opts.include_expected_differences = (SendMessageA(data->hChkExpected, BM_GETCHECK, 0, 0) == BST_CHECKED);

    auto *params = new PeIntegrityThreadParams();
    params->hwnd = hwnd;
    params->data = data;
    params->proc = proc;
    params->live_base = base_addr;
    params->disk_path = disk_path;
    params->options = opts;
    params->all_modules = data->modules;

    data->hWorkerThread = CreateThread(nullptr, 0, PeIntegrityWorkerThreadProc, params, 0, nullptr);
}

static void on_cancel_comparison(PeIntegrityDialogData *data)
{
    if (data && data->is_comparing.load())
    {
        data->abort_flag.store(true);
        SetWindowTextA(data->hLblStatus, "Cancelling PE comparison...");
        EnableWindow(data->hBtnCancel, FALSE);
    }
}

static void on_export_json(HWND hwnd, PeIntegrityDialogData *data)
{
    if (!data || data->report.metadata.module_name.empty())
    {
        MessageBoxA(hwnd, "No PE integrity report available to export. Run a comparison first.", "Export Error", MB_OK | MB_ICONWARNING);
        return;
    }

    char file_buf[MAX_PATH] = "pe_integrity_report.json";
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.lpstrDefExt = "json";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = "Save PE Integrity Report JSON";

    if (GetSaveFileNameA(&ofn))
    {
        std::string json = core::export_pe_integrity_json(data->report, true);
        std::ofstream out(file_buf, std::ios::binary);
        if (out.is_open())
        {
            out << json;
            out.close();
            SetWindowTextA(data->hLblStatus, ("Exported report to: " + std::string(file_buf)).c_str());
            MessageBoxA(hwnd, ("Successfully exported PE integrity report to:\r\n" + std::string(file_buf)).c_str(), "Report Exported", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(hwnd, "Failed to write JSON report file.", "Export Error", MB_OK | MB_ICONERROR);
        }
    }
}

static void on_add_to_timeline(HWND hwnd, PeIntegrityDialogData *data)
{
    if (!data || data->report.metadata.module_name.empty())
    {
        MessageBoxA(hwnd, "No PE integrity report available. Run a comparison first.", "Timeline Error", MB_OK | MB_ICONWARNING);
        return;
    }

    core::record_integrity_report_to_timeline(get_app_state().timeline, get_app_state().current_pid, data->report);
    SetWindowTextA(data->hLblStatus, "PE Integrity report recorded to Memory Timeline.");
    MessageBoxA(hwnd, "PE Integrity findings successfully recorded to Memory Timeline.\r\n(View via menu: View -> Memory Timeline View or Ctrl+6)", "Recorded to Timeline", MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK PeIntegrityDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<PeIntegrityDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<PeIntegrityDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));
        HINSTANCE hInst = cs->hInstance;

        const ThemeColors &tc = get_theme_colors(get_app_state().theme);

        // Row 1: Module Selection & Address Base/Size
        HWND lblMod = CreateWindowA("STATIC", "Loaded Module:", WS_CHILD | WS_VISIBLE, 12, 12, 110, 20, hwnd, nullptr, hInst, nullptr);
        data->hComboModule = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 125, 10, 420, 200, hwnd, reinterpret_cast<HMENU>(ID_PEINT_COMBO_MODULE), hInst, nullptr);
        data->hBtnRefresh = CreateWindowA("BUTTON", "Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 550, 9, 65, 24, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_REFRESH), hInst, nullptr);

        HWND lblBase = CreateWindowA("STATIC", "Base:", WS_CHILD | WS_VISIBLE, 625, 12, 40, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditBase = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_AUTOHSCROLL, 665, 10, 140, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_EDIT_BASE), hInst, nullptr);

        HWND lblSize = CreateWindowA("STATIC", "Size:", WS_CHILD | WS_VISIBLE, 815, 12, 35, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditSize = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_AUTOHSCROLL, 855, 10, 110, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_EDIT_SIZE), hInst, nullptr);

        // Row 2: On-Disk Image Path, Browse & Verify
        HWND lblDisk = CreateWindowA("STATIC", "On-Disk PE Image:", WS_CHILD | WS_VISIBLE, 12, 42, 110, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditDiskPath = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 125, 40, 680, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_EDIT_DISKPATH), hInst, nullptr);
        data->hBtnBrowse = CreateWindowA("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 815, 39, 75, 24, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_BROWSE), hInst, nullptr);
        data->hBtnVerify = CreateWindowA("BUTTON", "Verify", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 895, 39, 70, 24, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_VERIFY), hInst, nullptr);

        // Row 3: Options & Actions
        data->hChkHooks = CreateWindowA("BUTTON", "Analyze Inline Hooks", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 12, 70, 160, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_CHK_HOOKS), hInst, nullptr);
        SendMessageA(data->hChkHooks, BM_SETCHECK, BST_CHECKED, 0);
        make_checkbox_modern(data->hChkHooks);

        data->hChkExpected = CreateWindowA("BUTTON", "Include Expected Fixups", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 180, 70, 180, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_CHK_EXPECTED), hInst, nullptr);
        SendMessageA(data->hChkExpected, BM_SETCHECK, BST_CHECKED, 0);
        make_checkbox_modern(data->hChkExpected);

        data->hChkHideExp = CreateWindowA("BUTTON", "Hide Expected Fixups", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 370, 70, 160, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_CHK_HIDE_EXP), hInst, nullptr);
        SendMessageA(data->hChkHideExp, BM_SETCHECK, BST_UNCHECKED, 0);
        make_checkbox_modern(data->hChkHideExp);

        data->hBtnCompare = CreateWindowA("BUTTON", "Run Comparison", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 715, 68, 120, 26, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_COMPARE), hInst, nullptr);
        data->hBtnCancel = CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 845, 68, 120, 26, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_CANCEL), hInst, nullptr);
        EnableWindow(data->hBtnCancel, FALSE);

        // Row 4: Filters & Counts
        HWND lblCat = CreateWindowA("STATIC", "Category:", WS_CHILD | WS_VISIBLE, 12, 104, 60, 20, hwnd, nullptr, hInst, nullptr);
        data->hComboCatFilter = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 75, 102, 180, 180, hwnd, reinterpret_cast<HMENU>(ID_PEINT_COMBO_CAT_FILTER), hInst, nullptr);
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("All Categories"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Inline Hook Candidates"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Modified Executable Code"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Modified Data"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Import Address Table (IAT)"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Relocations"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Section Structure Diff"));
        SendMessageA(data->hComboCatFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Unreadable Memory"));
        SendMessageA(data->hComboCatFilter, CB_SETCURSEL, 0, 0);

        HWND lblSev = CreateWindowA("STATIC", "Severity:", WS_CHILD | WS_VISIBLE, 265, 104, 55, 20, hwnd, nullptr, hInst, nullptr);
        data->hComboSevFilter = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 325, 102, 100, 120, hwnd, reinterpret_cast<HMENU>(ID_PEINT_COMBO_SEV_FILTER), hInst, nullptr);
        SendMessageA(data->hComboSevFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("All"));
        SendMessageA(data->hComboSevFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Critical"));
        SendMessageA(data->hComboSevFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Warning"));
        SendMessageA(data->hComboSevFilter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Informational"));
        SendMessageA(data->hComboSevFilter, CB_SETCURSEL, 0, 0);

        HWND lblSec = CreateWindowA("STATIC", "Section:", WS_CHILD | WS_VISIBLE, 435, 104, 50, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditSecFilter = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 490, 102, 80, 22, hwnd, reinterpret_cast<HMENU>(ID_PEINT_EDIT_SEC_FILTER), hInst, nullptr);

        data->hLblSummary = CreateWindowA("STATIC", "Ready to compare.", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS, 580, 104, 385, 20, hwnd, nullptr, hInst, nullptr);

        // Row 5: Results ListView
        data->hListResults = CreateWindowExA(
            0, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            12, 132, 955, 320, hwnd, reinterpret_cast<HMENU>(ID_PEINT_LIST_RESULTS), hInst, nullptr);

        SendMessageA(data->hListResults, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNA col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        col.pszText = const_cast<char*>("#"); col.cx = 45; col.iSubItem = 0;
        ListView_InsertColumn(data->hListResults, 0, &col);

        col.pszText = const_cast<char*>("Category"); col.cx = 165; col.iSubItem = 1;
        ListView_InsertColumn(data->hListResults, 1, &col);

        col.pszText = const_cast<char*>("Severity"); col.cx = 85; col.iSubItem = 2;
        ListView_InsertColumn(data->hListResults, 2, &col);

        col.pszText = const_cast<char*>("Section"); col.cx = 70; col.iSubItem = 3;
        ListView_InsertColumn(data->hListResults, 3, &col);

        col.pszText = const_cast<char*>("Virtual Address"); col.cx = 145; col.iSubItem = 4;
        ListView_InsertColumn(data->hListResults, 4, &col);

        col.pszText = const_cast<char*>("RVA"); col.cx = 85; col.iSubItem = 5;
        ListView_InsertColumn(data->hListResults, 5, &col);

        col.pszText = const_cast<char*>("File Offset"); col.cx = 85; col.iSubItem = 6;
        ListView_InsertColumn(data->hListResults, 6, &col);

        col.pszText = const_cast<char*>("Size"); col.cx = 55; col.iSubItem = 7;
        ListView_InsertColumn(data->hListResults, 7, &col);

        col.pszText = const_cast<char*>("Hook / Symbol"); col.cx = 160; col.iSubItem = 8;
        ListView_InsertColumn(data->hListResults, 8, &col);

        col.pszText = const_cast<char*>("Details & Explanation"); col.cx = 260; col.iSubItem = 9;
        ListView_InsertColumn(data->hListResults, 9, &col);

        // Row 6: Details & Side-by-Side Hex Preview
        data->hEditPreview = CreateWindowA("EDIT", "Select a difference item above to view detailed byte comparison and hook disassembly.",
                                           WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                           12, 460, 955, 160, hwnd, reinterpret_cast<HMENU>(ID_PEINT_EDIT_PREVIEW), hInst, nullptr);

        // Row 7: Status Label & Action Buttons
        data->hLblStatus = CreateWindowA("STATIC", "Ready.", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                         12, 638, 470, 24, hwnd, nullptr, hInst, nullptr);

        data->hBtnGoto = CreateWindowA("BUTTON", "Go To in Hex View", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       490, 634, 125, 26, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_GOTO), hInst, nullptr);

        data->hBtnExportJson = CreateWindowA("BUTTON", "Export JSON...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                             625, 634, 105, 26, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_EXPORT_JSON), hInst, nullptr);

        data->hBtnAddTimeline = CreateWindowA("BUTTON", "Add to Timeline", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                              740, 634, 125, 26, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_ADD_TIMELINE), hInst, nullptr);

        data->hBtnClose = CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        875, 634, 90, 26, hwnd, reinterpret_cast<HMENU>(ID_PEINT_BTN_CLOSE), hInst, nullptr);

        // Apply fonts
        HFONT uif = get_app_state().ui_font;
        HFONT mono = get_app_state().mono_font;
        HWND all_ctrls[] = { lblMod, data->hComboModule, data->hBtnRefresh, lblBase, data->hEditBase,
                             lblSize, data->hEditSize, lblDisk, data->hEditDiskPath, data->hBtnBrowse,
                             data->hBtnVerify, data->hChkHooks, data->hChkExpected, data->hChkHideExp,
                             data->hBtnCompare, data->hBtnCancel, lblCat, data->hComboCatFilter,
                             lblSev, data->hComboSevFilter, lblSec, data->hEditSecFilter,
                             data->hLblSummary, data->hLblStatus, data->hBtnGoto, data->hBtnExportJson,
                             data->hBtnAddTimeline, data->hBtnClose };

        for (HWND c : all_ctrls)
        {
            if (c) SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(uif), TRUE);
        }
        SendMessageA(data->hEditBase, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hEditSize, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hEditDiskPath, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hListResults, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hEditPreview, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);

        // Set ListView colors
        if (get_app_state().theme == AppTheme::Dark)
        {
            ListView_SetBkColor(data->hListResults, tc.bg_control);
            ListView_SetTextBkColor(data->hListResults, tc.bg_control);
            ListView_SetTextColor(data->hListResults, tc.text_normal);
        }
        else
        {
            ListView_SetBkColor(data->hListResults, RGB(255, 255, 255));
            ListView_SetTextBkColor(data->hListResults, RGB(255, 255, 255));
            ListView_SetTextColor(data->hListResults, RGB(0, 0, 0));
        }

        refresh_module_list(hwnd, data);
        return 0;
    }

    case WM_COMMAND:
    {
        WORD id = LOWORD(wp);
        WORD code = HIWORD(wp);

        if (id == ID_PEINT_COMBO_MODULE && code == CBN_SELCHANGE)
        {
            if (data) update_module_selection(data);
        }
        else if (id == ID_PEINT_BTN_REFRESH)
        {
            if (data) refresh_module_list(hwnd, data);
        }
        else if (id == ID_PEINT_BTN_BROWSE)
        {
            if (data) on_browse_disk_file(hwnd, data);
        }
        else if (id == ID_PEINT_BTN_VERIFY)
        {
            if (data) on_verify_module_match(hwnd, data);
        }
        else if (id == ID_PEINT_BTN_COMPARE)
        {
            if (data) on_start_comparison(hwnd, data);
        }
        else if (id == ID_PEINT_BTN_CANCEL)
        {
            if (data) on_cancel_comparison(data);
        }
        else if (id == ID_PEINT_COMBO_CAT_FILTER && code == CBN_SELCHANGE)
        {
            if (data) populate_filtered_listview(data);
        }
        else if (id == ID_PEINT_COMBO_SEV_FILTER && code == CBN_SELCHANGE)
        {
            if (data) populate_filtered_listview(data);
        }
        else if (id == ID_PEINT_EDIT_SEC_FILTER && code == EN_CHANGE)
        {
            if (data) populate_filtered_listview(data);
        }
        else if (id == ID_PEINT_CHK_HIDE_EXP && code == BN_CLICKED)
        {
            if (data) populate_filtered_listview(data);
        }
        else if (id == ID_PEINT_BTN_GOTO)
        {
            if (data) navigate_to_selected_diff(data);
        }
        else if (id == ID_PEINT_BTN_EXPORT_JSON)
        {
            if (data) on_export_json(hwnd, data);
        }
        else if (id == ID_PEINT_BTN_ADD_TIMELINE)
        {
            if (data) on_add_to_timeline(hwnd, data);
        }
        else if (id == ID_PEINT_BTN_CLOSE)
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR *hdr = reinterpret_cast<NMHDR*>(lp);
        if (hdr && hdr->idFrom == ID_PEINT_LIST_RESULTS)
        {
            if (hdr->code == LVN_ITEMCHANGED)
            {
                NMLISTVIEW *nmlv = reinterpret_cast<NMLISTVIEW*>(lp);
                if ((nmlv->uChanged & LVIF_STATE) && (nmlv->uNewState & LVIS_SELECTED))
                {
                    if (data) update_preview_pane(data);
                }
            }
            else if (hdr->code == NM_DBLCLK)
            {
                if (data) navigate_to_selected_diff(data);
            }
        }
        return 0;
    }

    case WM_PE_INTEGRITY_PROGRESS:
    {
        if (data)
        {
            char status[256];
            std::snprintf(status, sizeof(status), "[%.0f%%] %s", data->progress_pct * 100.0f, data->progress_status.c_str());
            SetWindowTextA(data->hLblStatus, status);
        }
        return 0;
    }

    case WM_PE_INTEGRITY_COMPLETE:
    {
        if (data)
        {
            data->is_comparing.store(false);
            if (data->hWorkerThread != nullptr)
            {
                CloseHandle(data->hWorkerThread);
                data->hWorkerThread = nullptr;
            }

            EnableWindow(data->hBtnCompare, TRUE);
            EnableWindow(data->hBtnRefresh, TRUE);
            EnableWindow(data->hBtnBrowse, TRUE);
            EnableWindow(data->hBtnVerify, TRUE);
            EnableWindow(data->hComboModule, TRUE);
            EnableWindow(data->hBtnCancel, FALSE);

            if (!data->scan_success)
            {
                std::string err_msg = data->scan_error.empty() ? "Comparison cancelled or aborted." : data->scan_error;
                SetWindowTextA(data->hLblStatus, ("Comparison error: " + err_msg).c_str());
                MessageBoxA(hwnd, ("PE Integrity Comparison Error:\r\n" + err_msg).c_str(), "Scan Error", MB_OK | MB_ICONERROR);
            }
            else
            {
                populate_filtered_listview(data);
                char status[256];
                std::snprintf(status, sizeof(status), "Comparison complete: %zu differences found (%zu Hook candidates, %zu Code changes, %zu Data modifications).",
                              data->report.differences.size(),
                              data->report.count_hook_candidates,
                              data->report.count_executable_diffs,
                              data->report.count_data_diffs);
                SetWindowTextA(data->hLblStatus, status);

                if (!data->filtered_indices.empty())
                {
                    ListView_SetItemState(data->hListResults, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    update_preview_pane(data);
                }
            }
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORDLG:
    {
        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, tc.text_normal);
        return reinterpret_cast<LRESULT>(get_app_state().br_window);
    }

    case WM_CTLCOLOREDIT:
    {
        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        HDC hdc = reinterpret_cast<HDC>(wp);
        SetBkColor(hdc, tc.bg_control);
        SetTextColor(hdc, tc.text_normal);
        return reinterpret_cast<LRESULT>(get_app_state().br_control);
    }

    case WM_CLOSE:
    {
        DestroyWindow(hwnd);
        return 0;
    }

    case WM_DESTROY:
    {
        if (data)
        {
            data->abort_flag.store(true);
            if (data->hWorkerThread != nullptr)
            {
                WaitForSingleObject(data->hWorkerThread, 500);
                CloseHandle(data->hWorkerThread);
                data->hWorkerThread = nullptr;
            }
            delete data;
        }
        return 0;
    }

    default:
        break;
    }

    return DefWindowProcA(hwnd, msg, wp, lp);
}

void open_pe_integrity_dialog(HWND hParent)
{
    HINSTANCE hInst = GetModuleHandleA(nullptr);
    auto *data = new PeIntegrityDialogData();

    HWND hDlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "DeadeyePeIntegrityDlg",
        "PE Integrity & Memory Comparison",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 995, 715,
        hParent, nullptr, hInst, data);

    if (hDlg != nullptr)
    {
        set_window_dark_mode(hDlg, get_app_state().theme == AppTheme::Dark);

        // Center on parent
        RECT rcParent = {}, rcDlg = {};
        GetWindowRect(hParent, &rcParent);
        GetWindowRect(hDlg, &rcDlg);
        int w = rcDlg.right - rcDlg.left;
        int h = rcDlg.bottom - rcDlg.top;
        int x = rcParent.left + ((rcParent.right - rcParent.left) - w) / 2;
        int y = rcParent.top + ((rcParent.bottom - rcParent.top) - h) / 2;
        SetWindowPos(hDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        ShowWindow(hDlg, SW_SHOW);
    }
    else
    {
        delete data;
    }
}

} // namespace gui
