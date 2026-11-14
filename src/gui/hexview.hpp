// src/gui/hexview.hpp
// Deadeye GUI Memory Hex Viewer and Snapshot Diff Engine
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace gui {

struct DiffPair
{
    bool active = false;
    std::string title;
    const std::vector<uint8_t> *ref_data = nullptr;
    const std::vector<uint8_t> *cmp_data = nullptr;
    SIZE_T ref_view_offset = 0;
    SIZE_T cmp_view_offset = 0;
};

DiffPair get_active_diff_pair();
void invalidate_hex_cache();
void display_selected_region(SIZE_T focus_offset);
void update_diff_combo();
void on_take_snapshot();
void on_clear_snapshots();
void on_next_hit();

} // namespace gui
