// src/gui/strings_dialog.hpp
// Deadeye Revealed Strings Dialog
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>

namespace gui {

void populate_strings_view(HWND hEdit, const std::string &filter);
LRESULT CALLBACK StringsDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void open_revealed_strings_dialog(HWND hParent);

} // namespace gui
