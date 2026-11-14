// src/gui/controls.hpp
// Deadeye GUI Controls, Themes, and Visual Styling
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>

namespace gui {

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

const ThemeColors& get_theme_colors(AppTheme theme);

enum class ModernButtonStyle {
    Standard,
    Primary, // "Triage"
    Accent   // "Export JSON"
};

void make_button_modern(HWND btn, ModernButtonStyle style, AppTheme theme = AppTheme::Dark);
void copy_text_to_clipboard(HWND hwnd, const std::string &text);
void enable_debug_privilege();

} // namespace gui
