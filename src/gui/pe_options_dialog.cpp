// src/gui/pe_options_dialog.cpp
// Deadeye PE Mapping Options Dialog Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/pe_options_dialog.hpp"
#include "gui/app.hpp"
#include <cstdio>
#include <string>

namespace gui {

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

        AppState &app = get_app_state();
        HWND lbl1 = CreateWindowExA(0, "STATIC", "Target Virtual Base Address (hex):",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 16, 380, 20, hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
        SendMessageA(lbl1, WM_SETFONT, reinterpret_cast<WPARAM>(app.ui_font), TRUE);

        char base_str[32];
        std::snprintf(base_str, sizeof(base_str), "0x%016llX", static_cast<unsigned long long>(state->base_address));

        state->h_edit_base = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", base_str,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            20, 40, 380, 26, hwnd, reinterpret_cast<HMENU>(101), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(state->h_edit_base, WM_SETFONT, reinterpret_cast<WPARAM>(app.ui_font), TRUE);

        state->h_chk_relocs = CreateWindowExA(0, "BUTTON", "Apply base relocations (if mapped base != ImageBase)",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            20, 78, 380, 24, hwnd, reinterpret_cast<HMENU>(102), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(state->h_chk_relocs, WM_SETFONT, reinterpret_cast<WPARAM>(app.ui_font), TRUE);
        SendMessageA(state->h_chk_relocs, BM_SETCHECK, state->apply_relocs ? BST_CHECKED : BST_UNCHECKED, 0);

        HWND btn_ok = CreateWindowExA(0, "BUTTON", "OK",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            195, 120, 95, 30, hwnd, reinterpret_cast<HMENU>(IDOK), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(btn_ok, WM_SETFONT, reinterpret_cast<WPARAM>(app.ui_font_bold ? app.ui_font_bold : app.ui_font), TRUE);

        HWND btn_cancel = CreateWindowExA(0, "BUTTON", "Cancel",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            305, 120, 95, 30, hwnd, reinterpret_cast<HMENU>(IDCANCEL), GetModuleHandleA(nullptr), nullptr);
        SendMessageA(btn_cancel, WM_SETFONT, reinterpret_cast<WPARAM>(app.ui_font), TRUE);

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

} // namespace gui
