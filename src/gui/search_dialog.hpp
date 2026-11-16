// src/gui/search_dialog.hpp
// Deadeye Advanced Memory Pattern Search Dialog
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

namespace gui {

LRESULT CALLBACK SearchDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void open_advanced_pattern_search_dialog(HWND hParent);

} // namespace gui
