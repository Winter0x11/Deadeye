// src/gui/controls.cpp
// Deadeye GUI Controls, Themes, and Visual Styling

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/controls.hpp"
#include "gui/app.hpp"
#include <cstring>

namespace gui {

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

const ThemeColors& get_theme_colors(AppTheme theme)
{
    return (theme == AppTheme::Light) ? g_theme_light : g_theme_dark;
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

// Modern Flat / Fluent Button Rendering Engine
struct ModernButtonData {
    WNDPROC old_proc = nullptr;
    ModernButtonStyle style = ModernButtonStyle::Standard;
    bool is_hovered = false;
};

static const char* const DEADEYE_BTN_PROP = "DEADEYE_MODERN_BTN_DATA";

static LRESULT CALLBACK ModernButtonSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
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
        AppState &state = get_app_state();
        const ThemeColors& tc = get_theme_colors(state.theme);
        HBRUSH brParent = CreateSolidBrush(tc.bg_window);
        FillRect(memDC, &rc, brParent);
        DeleteObject(brParent);

        bool is_enabled = (IsWindowEnabled(hwnd) != FALSE);
        bool is_pressed = ((SendMessageA(hwnd, BM_GETSTATE, 0, 0) & BST_PUSHED) != 0);
        bool is_hovered = (data->is_hovered && is_enabled);
        bool is_focused = (GetFocus() == hwnd && is_enabled);
        bool is_dark    = (state.theme == AppTheme::Dark);

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
        HFONT btn_font = (data->style == ModernButtonStyle::Primary) ? state.ui_font_bold : state.ui_font;
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

void make_button_modern(HWND btn, ModernButtonStyle style, AppTheme theme) {
    (void)theme;
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

} // namespace gui
