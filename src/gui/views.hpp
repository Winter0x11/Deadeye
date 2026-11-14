// src/gui/views.hpp
// Deadeye GUI Region List and Visual Triage Views
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstddef>

namespace gui {

void populate_region_list();
void update_triage_details_label(size_t reg_idx);
void select_region_in_ui(size_t region_idx, SIZE_T view_offset, SIZE_T focus_offset);
void draw_region_list_item(DRAWITEMSTRUCT *dis);

} // namespace gui
