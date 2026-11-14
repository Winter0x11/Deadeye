// src/gui/pe_options_dialog.hpp
// Deadeye PE Mapping Options Dialog
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>

namespace gui {

bool show_pe_map_options_dialog(HWND parent, uintptr_t default_base, uintptr_t &out_base, bool &out_apply_relocs);

} // namespace gui
