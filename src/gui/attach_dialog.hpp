// src/gui/attach_dialog.hpp
// Deadeye Process Attach Dialog
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

namespace gui {

LRESULT CALLBACK AttachDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
void open_attach_process_dialog(HWND hParent);

} // namespace gui
