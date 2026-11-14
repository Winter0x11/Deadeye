// src/gui/strings_dialog.cpp
// Deadeye Revealed Strings Dialog Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/strings_dialog.hpp"
#include "gui/app.hpp"
#include "gui/controls.hpp"
#include "core/behavior.hpp"
#include "core/util.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <fstream>
#include <cstdio>
#include <vector>
#include <string>

namespace gui {

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
    for (const auto &s : get_app_state().revealed_strings)
    {
        if (!filter.empty() && s.text.find(filter) == std::string::npos && s.category.find(filter) == std::string::npos)
            continue;

        char abuf[32];
        std::snprintf(abuf, sizeof(abuf), "0x%016llX", static_cast<unsigned long long>(s.addr));
        text += s.category + "  " + abuf + "  " + s.text + "\r\n";
    }
    if (text.empty())
    {
        if (get_app_state().revealed_strings.empty())
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
            SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().ui_font), TRUE);

        SendMessageA(data->hListStrings, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().mono_font), TRUE);

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

} // namespace gui
