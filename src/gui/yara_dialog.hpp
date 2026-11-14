// src/gui/yara_dialog.hpp
// Deadeye YARA Rule Generator & False Positive Validator Dialog
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

namespace gui {

LRESULT CALLBACK YaraDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void open_yara_dialog(HWND hParent);

} // namespace gui
