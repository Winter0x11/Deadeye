// src/gui/attach_dialog.cpp
// Deadeye Process Attach Dialog Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/attach_dialog.hpp"
#include "gui/app.hpp"
#include "gui/controls.hpp"
#include "gui/menu.hpp"

#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <string>
#include <vector>

namespace gui {

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
            if (c) SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().ui_font), TRUE);
        }
        if (data->hList)
        {
            SendMessageA(data->hList, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().ui_font), TRUE);
        }

        make_button_modern(data->hBtnAttach, ModernButtonStyle::Primary);
        make_button_modern(data->hBtnCancel, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnRefresh, ModernButtonStyle::Standard);

        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        if (get_app_state().theme == AppTheme::Dark)
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
        if (get_app_state().edit_pid != nullptr)
        {
            SetWindowTextA(get_app_state().edit_pid, pid_str.c_str());
        }

        std::string msg_text = "Attaching to " + state.selected_name + " (PID " + pid_str + ")...";
        set_status(msg_text);

        PostMessageA(hParent, WM_COMMAND, ID_BTN_TRIAGE, 0);
    }
}

} // namespace gui
