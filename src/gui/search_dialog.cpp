// src/gui/search_dialog.cpp
// Deadeye Advanced Memory Pattern Search Dialog Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/search_dialog.hpp"
#include "gui/app.hpp"
#include "gui/controls.hpp"
#include "gui/views.hpp"
#include "core/pattern.hpp"
#include "core/util.hpp"

#include <commctrl.h>
#include <cstdio>
#include <string>
#include <vector>
#include <atomic>
#include <thread>

namespace gui {

#define ID_SEARCH_EDIT_QUERY   7001
#define ID_SEARCH_COMBO_TYPE   7002
#define ID_SEARCH_CHK_CASE     7003
#define ID_SEARCH_COMBO_SCOPE  7004
#define ID_SEARCH_EDIT_START   7005
#define ID_SEARCH_EDIT_END     7006
#define ID_SEARCH_BTN_START    7007
#define ID_SEARCH_BTN_STOP     7008
#define ID_SEARCH_BTN_GOTO     7009
#define ID_SEARCH_BTN_CLOSE    7010
#define ID_SEARCH_LIST_RESULTS 7011

#define WM_SEARCH_PROGRESS     (WM_USER + 10)
#define WM_SEARCH_COMPLETE     (WM_USER + 11)

struct SearchDialogData
{
    HWND hEditQuery = nullptr;
    HWND hComboType = nullptr;
    HWND hChkCase = nullptr;
    HWND hComboScope = nullptr;
    HWND hEditStart = nullptr;
    HWND hEditEnd = nullptr;
    HWND hBtnStart = nullptr;
    HWND hBtnStop = nullptr;
    HWND hBtnGoto = nullptr;
    HWND hBtnClose = nullptr;
    HWND hListResults = nullptr;
    HWND hLblStatus = nullptr;

    std::atomic<bool> is_searching{false};
    std::atomic<bool> abort_requested{false};
    HANDLE hSearchThread = nullptr;

    std::vector<PatternMatchResult> results;
    SIZE_T progress_scanned = 0;
    SIZE_T progress_total = 0;
    size_t progress_hits = 0;
};

struct SearchThreadParams
{
    HWND hwnd = nullptr;
    SearchDialogData *data = nullptr;
    SearchOptions options;
    std::shared_ptr<MemorySource> source;
    std::vector<RegionInfo> regions;
    core::ProcessSnapshot snapshot;
    bool search_snapshot = false;
};

static DWORD WINAPI SearchWorkerThreadProc(LPVOID lpParam)
{
    auto *params = reinterpret_cast<SearchThreadParams*>(lpParam);
    if (!params) return 0;

    auto progress_cb = [params](SIZE_T scanned, SIZE_T total, size_t hits) {
        if (params->data != nullptr)
        {
            params->data->progress_scanned = scanned;
            params->data->progress_total = total;
            params->data->progress_hits = hits;
            PostMessageA(params->hwnd, WM_SEARCH_PROGRESS, 0, 0);
        }
    };

    std::vector<PatternMatchResult> res;
    if (params->search_snapshot)
    {
        res = search_snapshot_pattern(params->snapshot, params->options, &params->data->abort_requested, progress_cb);
    }
    else
    {
        res = search_memory_pattern(params->source, params->regions, params->options, &params->data->abort_requested, progress_cb);
    }

    if (params->data != nullptr)
    {
        params->data->results = std::move(res);
    }

    PostMessageA(params->hwnd, WM_SEARCH_COMPLETE, 0, 0);
    delete params;
    return 0;
}

static void populate_results_listview(SearchDialogData *data)
{
    if (!data || !data->hListResults) return;

    HWND hList = data->hListResults;
    SendMessageA(hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hList);

    for (int i = 0; i < static_cast<int>(data->results.size()); ++i)
    {
        const auto &r = data->results[static_cast<size_t>(i)];

        LVITEMA item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = i;
        item.iSubItem = 0;
        char addr_buf[32];
        std::snprintf(addr_buf, sizeof(addr_buf), "0x%016llX", static_cast<unsigned long long>(r.match_address));
        item.pszText = addr_buf;
        item.lParam = static_cast<LPARAM>(i);
        ListView_InsertItem(hList, &item);

        char base_buf[32];
        std::snprintf(base_buf, sizeof(base_buf), "0x%016llX", static_cast<unsigned long long>(r.region_base));
        ListView_SetItemText(hList, i, 1, base_buf);

        std::string sz_str = fmt_size_short(r.region_size);
        ListView_SetItemText(hList, i, 2, const_cast<char*>(sz_str.c_str()));

        std::string prot_str = prot_short(r.protect);
        ListView_SetItemText(hList, i, 3, const_cast<char*>(prot_str.c_str()));

        std::string typ_str = type_short(r.type);
        ListView_SetItemText(hList, i, 4, const_cast<char*>(typ_str.c_str()));

        ListView_SetItemText(hList, i, 5, const_cast<char*>(r.preview_hex.c_str()));
        ListView_SetItemText(hList, i, 6, const_cast<char*>(r.preview_ascii.c_str()));
    }

    SendMessageA(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, nullptr, TRUE);
}

static void navigate_to_selected_result(HWND hwnd, SearchDialogData *data)
{
    (void)hwnd;
    if (!data || !data->hListResults) return;

    int sel = ListView_GetNextItem(data->hListResults, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= static_cast<int>(data->results.size()))
    {
        return;
    }

    const auto &r = data->results[static_cast<size_t>(sel)];
    uintptr_t target_addr = r.match_address;

    // Locate region in app state
    for (size_t i = 0; i < get_app_state().regions.size(); ++i)
    {
        const auto &reg = get_app_state().regions[i];
        if (target_addr >= reg.base && target_addr < reg.base + reg.size)
        {
            SIZE_T offset = target_addr - reg.base;
            SIZE_T page_off = (offset / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
            select_region_in_ui(i, page_off, offset);
            set_status("Navigated to search match at 0x" + to_hex_string(target_addr));
            SetForegroundWindow(get_app_state().hwnd_main);
            break;
        }
    }
}

static bool parse_hex_u64(std::string s, uintptr_t &out_addr)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    if (s.empty()) return false;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
    try {
        out_addr = static_cast<uintptr_t>(std::stoull(s, nullptr, 16));
        return true;
    } catch (...) {
        return false;
    }
}

static void start_pattern_search(HWND hwnd, SearchDialogData *data)
{
    if (data->is_searching.load()) return;

    char query_buf[512] = {};
    GetWindowTextA(data->hEditQuery, query_buf, sizeof(query_buf));
    std::string query(query_buf);

    if (query.empty())
    {
        MessageBoxA(hwnd, "Please enter a search pattern or string.", "Search Error", MB_OK | MB_ICONWARNING);
        return;
    }

    LRESULT type_idx = SendMessageA(data->hComboType, CB_GETCURSEL, 0, 0);
    bool match_case = (SendMessageA(data->hChkCase, BM_GETCHECK, 0, 0) == BST_CHECKED);

    Pattern pat;
    std::string err;
    if (type_idx == 0) // Hex Wildcard
    {
        if (!parse_hex_pattern(query, pat, err))
        {
            MessageBoxA(hwnd, ("Invalid Hex Pattern: " + err).c_str(), "Pattern Error", MB_OK | MB_ICONERROR);
            return;
        }
    }
    else if (type_idx == 1) // ASCII String
    {
        if (!parse_ascii_pattern(query, match_case, pat, err))
        {
            MessageBoxA(hwnd, ("Invalid ASCII String: " + err).c_str(), "Pattern Error", MB_OK | MB_ICONERROR);
            return;
        }
    }
    else // UTF-16LE String
    {
        if (!parse_utf16le_pattern(query, match_case, pat, err))
        {
            MessageBoxA(hwnd, ("Invalid UTF-16 String: " + err).c_str(), "Pattern Error", MB_OK | MB_ICONERROR);
            return;
        }
    }

    LRESULT scope_idx = SendMessageA(data->hComboScope, CB_GETCURSEL, 0, 0);
    SearchOptions opts;
    opts.pattern = pat;
    opts.scope = static_cast<SearchScope>(scope_idx);
    opts.max_results = 10000;

    auto src = get_active_source();
    if (!src && opts.scope != SearchScope::Snapshots)
    {
        MessageBoxA(hwnd, "No memory source loaded. Attach to a process or load a memory file first.", "Search Error", MB_OK | MB_ICONWARNING);
        return;
    }

    if (opts.scope == SearchScope::SelectedRegion)
    {
        if (!get_app_state().has_selection || get_app_state().selected_region >= get_app_state().regions.size())
        {
            MessageBoxA(hwnd, "No region selected in main window.", "Search Error", MB_OK | MB_ICONWARNING);
            return;
        }
        opts.selected_region_idx = get_app_state().selected_region;
    }
    else if (opts.scope == SearchScope::AddressRange)
    {
        char start_buf[64] = {}, end_buf[64] = {};
        GetWindowTextA(data->hEditStart, start_buf, sizeof(start_buf));
        GetWindowTextA(data->hEditEnd, end_buf, sizeof(end_buf));
        uintptr_t range_start_addr = 0, range_end_addr = 0;
        if (!parse_hex_u64(start_buf, range_start_addr) || !parse_hex_u64(end_buf, range_end_addr) || range_start_addr >= range_end_addr)
        {
            MessageBoxA(hwnd, "Please enter valid Start and End hexadecimal addresses (Start < End).", "Search Error", MB_OK | MB_ICONWARNING);
            return;
        }
        opts.range_start = range_start_addr;
        opts.range_end = range_end_addr;
    }
    else if (opts.scope == SearchScope::Snapshots)
    {
        if (get_app_state().snapshot_store.empty())
        {
            MessageBoxA(hwnd, "No process snapshots loaded in store. Capture or load a snapshot first.", "Search Error", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    data->results.clear();
    ListView_DeleteAllItems(data->hListResults);
    data->is_searching.store(true);
    data->abort_requested.store(false);

    EnableWindow(data->hBtnStart, FALSE);
    EnableWindow(data->hBtnStop, TRUE);
    SetWindowTextA(data->hLblStatus, "Searching memory...");

    auto *params = new SearchThreadParams();
    params->hwnd = hwnd;
    params->data = data;
    params->options = opts;
    params->source = src;
    params->regions = get_app_state().regions;
    if (opts.scope == SearchScope::Snapshots && !get_app_state().snapshot_store.empty())
    {
        params->search_snapshot = true;
        params->snapshot = get_app_state().snapshot_store.back();
    }

    data->hSearchThread = CreateThread(nullptr, 0, SearchWorkerThreadProc, params, 0, nullptr);
}

LRESULT CALLBACK SearchDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<SearchDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<SearchDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));
        HINSTANCE hInst = cs->hInstance;

        const ThemeColors &tc = get_theme_colors(get_app_state().theme);

        // Row 1: Query Input & Type
        HWND lblQuery = CreateWindowA("STATIC", "Search Pattern / String:", WS_CHILD | WS_VISIBLE, 12, 12, 160, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditQuery = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 12, 32, 420, 24, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_EDIT_QUERY), hInst, nullptr);

        HWND lblType = CreateWindowA("STATIC", "Type:", WS_CHILD | WS_VISIBLE, 442, 12, 60, 20, hwnd, nullptr, hInst, nullptr);
        data->hComboType = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 442, 32, 210, 120, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_COMBO_TYPE), hInst, nullptr);
        SendMessageA(data->hComboType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Hex Wildcard (e.g. 48 8B ?? ??" ")"));
        SendMessageA(data->hComboType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("ASCII String"));
        SendMessageA(data->hComboType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("UTF-16LE String"));
        SendMessageA(data->hComboType, CB_SETCURSEL, 0, 0);

        data->hChkCase = CreateWindowA("BUTTON", "Match Case", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 664, 34, 95, 20, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_CHK_CASE), hInst, nullptr);
        make_checkbox_modern(data->hChkCase);

        // Row 2: Search Scope & Range
        HWND lblScope = CreateWindowA("STATIC", "Search Scope:", WS_CHILD | WS_VISIBLE, 12, 66, 120, 20, hwnd, nullptr, hInst, nullptr);
        data->hComboScope = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 12, 86, 220, 140, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_COMBO_SCOPE), hInst, nullptr);
        SendMessageA(data->hComboScope, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Entire Readable Memory"));
        SendMessageA(data->hComboScope, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Selected Region Only"));
        SendMessageA(data->hComboScope, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Custom Address Range"));
        SendMessageA(data->hComboScope, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Process Snapshot(s)"));
        SendMessageA(data->hComboScope, CB_SETCURSEL, 0, 0);

        HWND lblStart = CreateWindowA("STATIC", "Start Addr:", WS_CHILD | WS_VISIBLE, 242, 66, 80, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditStart = CreateWindowA("EDIT", "0x00000000", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 242, 86, 140, 24, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_EDIT_START), hInst, nullptr);
        EnableWindow(data->hEditStart, FALSE);

        HWND lblEnd = CreateWindowA("STATIC", "End Addr:", WS_CHILD | WS_VISIBLE, 392, 66, 80, 20, hwnd, nullptr, hInst, nullptr);
        data->hEditEnd = CreateWindowA("EDIT", "0x7FFFFFFF", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 392, 86, 140, 24, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_EDIT_END), hInst, nullptr);
        EnableWindow(data->hEditEnd, FALSE);

        data->hBtnStart = CreateWindowA("BUTTON", "Search", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 544, 85, 78, 26, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_BTN_START), hInst, nullptr);
        data->hBtnStop = CreateWindowA("BUTTON", "Stop", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 628, 85, 68, 26, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_BTN_STOP), hInst, nullptr);
        EnableWindow(data->hBtnStop, FALSE);

        data->hBtnGoto = CreateWindowA("BUTTON", "Go To Hit", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 702, 85, 78, 26, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_BTN_GOTO), hInst, nullptr);

        // Row 3: Results ListView
        data->hListResults = CreateWindowExA(
            0, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            12, 122, 770, 390, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_LIST_RESULTS), hInst, nullptr);

        SendMessageA(data->hListResults, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNA col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        col.pszText = const_cast<char*>("Match Address");
        col.cx = 150;
        col.iSubItem = 0;
        ListView_InsertColumn(data->hListResults, 0, &col);

        col.pszText = const_cast<char*>("Region Base");
        col.cx = 145;
        col.iSubItem = 1;
        ListView_InsertColumn(data->hListResults, 1, &col);

        col.pszText = const_cast<char*>("Size");
        col.cx = 65;
        col.iSubItem = 2;
        ListView_InsertColumn(data->hListResults, 2, &col);

        col.pszText = const_cast<char*>("Prot");
        col.cx = 55;
        col.iSubItem = 3;
        ListView_InsertColumn(data->hListResults, 3, &col);

        col.pszText = const_cast<char*>("Type");
        col.cx = 50;
        col.iSubItem = 4;
        ListView_InsertColumn(data->hListResults, 4, &col);

        col.pszText = const_cast<char*>("Hex Preview");
        col.cx = 170;
        col.iSubItem = 5;
        ListView_InsertColumn(data->hListResults, 5, &col);

        col.pszText = const_cast<char*>("ASCII Preview");
        col.cx = 120;
        col.iSubItem = 6;
        ListView_InsertColumn(data->hListResults, 6, &col);

        // Status Label & Close Button
        data->hLblStatus = CreateWindowA("STATIC", "Ready to search.", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                         12, 520, 670, 24, hwnd, nullptr, hInst, nullptr);

        data->hBtnClose = CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        702, 519, 78, 26, hwnd, reinterpret_cast<HMENU>(ID_SEARCH_BTN_CLOSE), hInst, nullptr);

        // Set Fonts
        HFONT uif = get_app_state().ui_font;
        HFONT mono = get_app_state().mono_font;
        HWND all_ctrls[] = { lblQuery, data->hEditQuery, lblType, data->hComboType, data->hChkCase,
                             lblScope, data->hComboScope, lblStart, data->hEditStart, lblEnd, data->hEditEnd,
                             data->hBtnStart, data->hBtnStop, data->hBtnGoto, data->hBtnClose, data->hLblStatus };
        for (HWND c : all_ctrls)
        {
            if (c) SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(uif), TRUE);
        }
        SendMessageA(data->hEditQuery, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hEditStart, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hEditEnd, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);
        SendMessageA(data->hListResults, WM_SETFONT, reinterpret_cast<WPARAM>(mono), TRUE);

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
            ListView_SetTextColor(data->hListResults, RGB(20, 20, 20));
        }

        SetFocus(data->hEditQuery);
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);

        if (id == ID_SEARCH_COMBO_SCOPE && code == CBN_SELCHANGE)
        {
            LRESULT sel = SendMessageA(data->hComboScope, CB_GETCURSEL, 0, 0);
            BOOL is_range = (sel == 2);
            EnableWindow(data->hEditStart, is_range);
            EnableWindow(data->hEditEnd, is_range);
        }
        else if (id == ID_SEARCH_BTN_START || id == IDOK)
        {
            if (data) start_pattern_search(hwnd, data);
        }
        else if (id == ID_SEARCH_BTN_STOP)
        {
            if (data)
            {
                data->abort_requested.store(true);
                SetWindowTextA(data->hLblStatus, "Aborting search...");
            }
        }
        else if (id == ID_SEARCH_BTN_GOTO)
        {
            if (data) navigate_to_selected_result(hwnd, data);
        }
        else if (id == ID_SEARCH_BTN_CLOSE || id == IDCANCEL)
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR *nm = reinterpret_cast<NMHDR*>(lp);
        if (nm && nm->idFrom == ID_SEARCH_LIST_RESULTS)
        {
            if (nm->code == NM_DBLCLK)
            {
                if (data) navigate_to_selected_result(hwnd, data);
                return 0;
            }
        }
        break;
    }

    case WM_SEARCH_PROGRESS:
    {
        if (data)
        {
            char status[256];
            std::snprintf(status, sizeof(status), "Scanning: %s / %s | %zu match(es) found...",
                          fmt_size_short(data->progress_scanned).c_str(),
                          fmt_size_short(data->progress_total).c_str(),
                          data->progress_hits);
            SetWindowTextA(data->hLblStatus, status);
        }
        return 0;
    }

    case WM_SEARCH_COMPLETE:
    {
        if (data)
        {
            data->is_searching.store(false);
            if (data->hSearchThread != nullptr)
            {
                CloseHandle(data->hSearchThread);
                data->hSearchThread = nullptr;
            }

            EnableWindow(data->hBtnStart, TRUE);
            EnableWindow(data->hBtnStop, FALSE);

            populate_results_listview(data);

            char status[256];
            std::snprintf(status, sizeof(status), "Search completed: %zu match(es) found in %s scanned.",
                          data->results.size(),
                          fmt_size_short(data->progress_scanned).c_str());
            SetWindowTextA(data->hLblStatus, status);
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

    case WM_DESTROY:
    {
        if (data)
        {
            data->abort_requested.store(true);
            if (data->hSearchThread != nullptr)
            {
                WaitForSingleObject(data->hSearchThread, 500);
                CloseHandle(data->hSearchThread);
                data->hSearchThread = nullptr;
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

void open_advanced_pattern_search_dialog(HWND hParent)
{
    HINSTANCE hInst = GetModuleHandleA(nullptr);
    auto *data = new SearchDialogData();

    HWND hDlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "DeadeyeSearchDlg",
        "Advanced Memory Pattern Search",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 810, 595,
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
