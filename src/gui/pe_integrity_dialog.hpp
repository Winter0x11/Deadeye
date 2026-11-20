// src/gui/pe_integrity_dialog.hpp
// Deadeye PE Integrity & Memory Comparison Dialog
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

namespace gui {

LRESULT CALLBACK PeIntegrityDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void open_pe_integrity_dialog(HWND hParent);

} // namespace gui
