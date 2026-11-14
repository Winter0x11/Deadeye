// src/gui/hexview.cpp
// Deadeye GUI Memory Hex Viewer and Snapshot Diff Engine Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/hexview.hpp"
#include "gui/app.hpp"
#include "gui/views.hpp"
#include "gui/controls.hpp"
#include "core/util.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace gui {

void invalidate_hex_cache()
{
    AppState &app = get_app_state();
    app.last_hex_dump.clear();
    app.last_hex_info.clear();
}

DiffPair get_active_diff_pair()
{
    DiffPair dp = {false, "", nullptr, nullptr, 0, 0};
    if (!get_app_state().has_selection || get_app_state().selected_region >= get_app_state().regions.size())
        return dp;
    const RegionInfo &reg = get_app_state().regions[get_app_state().selected_region];
    if (reg.snapshots.empty())
        return dp;

    LRESULT sel = SendMessageA(get_app_state().combo_diff, CB_GETCURSEL, 0, 0);
    if (sel <= 0 || sel == CB_ERR)
        return dp;

    size_t snap_count = reg.snapshots.size();
    if (static_cast<size_t>(sel) <= snap_count)
    {
        size_t idx = static_cast<size_t>(sel - 1);
        dp.active = true;
        dp.title = "Live vs " + reg.snapshots[idx].label;
        dp.ref_data = &reg.snapshots[idx].data;
        dp.cmp_data = nullptr; // Live
        dp.ref_view_offset = reg.snapshots[idx].view_offset;
        dp.cmp_view_offset = get_app_state().view_offset;
        return dp;
    }

    size_t pair_idx = static_cast<size_t>(sel - 1 - snap_count);
    if (pair_idx + 1 < snap_count)
    {
        dp.active = true;
        dp.title = reg.snapshots[pair_idx].label + " vs " + reg.snapshots[pair_idx + 1].label;
        dp.ref_data = &reg.snapshots[pair_idx].data;
        dp.cmp_data = &reg.snapshots[pair_idx + 1].data;
        dp.ref_view_offset = reg.snapshots[pair_idx].view_offset;
        dp.cmp_view_offset = reg.snapshots[pair_idx + 1].view_offset;
        return dp;
    }
    return dp;
}

std::string build_hex_dump(const uint8_t *buf, size_t buf_len, uintptr_t view_addr,
                           const std::vector<SIZE_T> &region_hits, SIZE_T view_offset,
                           size_t pat_len, SIZE_T focus_offset, int &out_focus_line,
                           const uint8_t *ref_buf, size_t ref_len, bool diff_active,
                           size_t &out_chg_bytes, size_t &out_new_bytes, size_t &out_zeroed_bytes)
{
    out_focus_line = -1;
    out_chg_bytes = 0;
    out_new_bytes = 0;
    out_zeroed_bytes = 0;

    if (buf_len == 0)
    {
        return "(No readable bytes in this page)\r\n";
    }

    std::vector<uint8_t> hit_byte(buf_len, 0);
    if (get_app_state().has_pattern && pat_len > 0)
    {
        for (size_t i = 0; i < region_hits.size(); ++i)
        {
            SIZE_T h = region_hits[i];
            if (h + pat_len <= view_offset || h >= view_offset + buf_len)
            {
                continue;
            }
            for (size_t j = 0; j < pat_len; ++j)
            {
                if (h + j >= view_offset && h + j < view_offset + buf_len)
                {
                    hit_byte[(h + j) - view_offset] = 1;
                }
            }
        }
    }

    std::string out;
    out.reserve(buf_len * 6 + 256);
    out += "    Address           00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  0123456789ABCDEF\r\n";
    out += "    ----------------  -----------------------  -----------------------  ----------------\r\n";

    size_t num_rows = (buf_len + 15) / 16;
    int line_counter = 2;

    for (size_t row = 0; row < num_rows; ++row)
    {
        size_t rs = row * 16;
        size_t re = rs + 16;
        if (re > buf_len)
            re = buf_len;

        bool row_has_hit = false;
        bool row_has_diff = false;

        for (size_t i = rs; i < re; ++i)
        {
            if (hit_byte[i] != 0)
            {
                row_has_hit = true;
            }
            if (diff_active && ref_buf != nullptr)
            {
                if (i < ref_len)
                {
                    if (buf[i] != ref_buf[i])
                    {
                        row_has_diff = true;
                        out_chg_bytes++;
                        if (ref_buf[i] == 0 && buf[i] != 0)
                            out_new_bytes++;
                        else if (ref_buf[i] != 0 && buf[i] == 0)
                            out_zeroed_bytes++;
                    }
                }
                else
                {
                    row_has_diff = true;
                    out_chg_bytes++;
                    if (buf[i] != 0)
                        out_new_bytes++;
                }
            }
        }

        if (focus_offset != static_cast<SIZE_T>(-1) &&
            focus_offset >= view_offset + rs && focus_offset < view_offset + re)
        {
            out_focus_line = line_counter;
        }

        if (row_has_hit && row_has_diff)
        {
            out += "!>> ";
        }
        else if (row_has_diff)
        {
            out += "CHG ";
        }
        else if (row_has_hit)
        {
            out += ">>> ";
        }
        else
        {
            out += "    ";
        }

        out += fmt_addr(view_addr + rs);
        out += "  ";

        char hx[8];
        for (size_t i = rs; i < rs + 16; ++i)
        {
            if (i == rs + 8)
                out += " ";
            if (i < re)
            {
                std::snprintf(hx, sizeof(hx), "%02X ", buf[i]);
                out += hx;
            }
            else
            {
                out += "   ";
            }
        }
        out += " ";

        for (size_t i = rs; i < rs + 16; ++i)
        {
            if (i < re)
            {
                uint8_t b = buf[i];
                out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            }
            else
            {
                out += ' ';
            }
        }
        out += "\r\n";
        line_counter++;

        // Sub-row for changed bytes in diff timeline
        if (row_has_diff && ref_buf != nullptr)
        {
            out += "        old:          ";
            for (size_t i = rs; i < rs + 16; ++i)
            {
                if (i == rs + 8)
                    out += " ";
                if (i < re && i < ref_len && buf[i] != ref_buf[i])
                {
                    std::snprintf(hx, sizeof(hx), "%02X ", ref_buf[i]);
                    out += hx;
                }
                else
                {
                    out += "   ";
                }
            }
            out += " ";
            for (size_t i = rs; i < rs + 16; ++i)
            {
                if (i < re && i < ref_len && buf[i] != ref_buf[i])
                {
                    uint8_t b = ref_buf[i];
                    out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
                }
                else
                {
                    out += ' ';
                }
            }
            out += "\r\n";
            line_counter++;
        }
    }
    return out;
}

void display_selected_region(SIZE_T focus_offset);
void populate_region_list();
void update_triage_details_label(size_t reg_idx);

void update_diff_combo()
{
    SendMessageA(get_app_state().combo_diff, CB_RESETCONTENT, 0, 0);
    SendMessageA(get_app_state().combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Diff: Off (Normal)"));

    if (!get_app_state().has_selection || get_app_state().selected_region >= get_app_state().regions.size())
    {
        SendMessageA(get_app_state().combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(get_app_state().btn_snap, FALSE);
        EnableWindow(get_app_state().combo_diff, FALSE);
        EnableWindow(get_app_state().btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(get_app_state().btn_snap, TRUE);
    const RegionInfo &reg = get_app_state().regions[get_app_state().selected_region];

    if (reg.snapshots.empty())
    {
        SendMessageA(get_app_state().combo_diff, CB_SETCURSEL, 0, 0);
        EnableWindow(get_app_state().combo_diff, FALSE);
        EnableWindow(get_app_state().btn_clear_snaps, FALSE);
        return;
    }

    EnableWindow(get_app_state().combo_diff, TRUE);
    EnableWindow(get_app_state().btn_clear_snaps, TRUE);

    for (size_t i = 0; i < reg.snapshots.size(); ++i)
    {
        std::string item = "Live vs " + reg.snapshots[i].label;
        SendMessageA(get_app_state().combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
    }

    if (reg.snapshots.size() >= 2)
    {
        for (size_t i = 0; i + 1 < reg.snapshots.size(); ++i)
        {
            std::string item = reg.snapshots[i].label + " vs " + reg.snapshots[i + 1].label;
            SendMessageA(get_app_state().combo_diff, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
        }
    }

    LRESULT count = SendMessageA(get_app_state().combo_diff, CB_GETCOUNT, 0, 0);
    WPARAM sel = (reg.snapshots.size() > 0) ? static_cast<WPARAM>(reg.snapshots.size()) : 0;
    if (sel >= static_cast<WPARAM>(count))
        sel = 0;
    SendMessageA(get_app_state().combo_diff, CB_SETCURSEL, sel, 0);
}

void on_take_snapshot()
{
    if (!get_app_state().has_selection || get_app_state().selected_region >= get_app_state().regions.size())
        return;
    RegionInfo &reg = get_app_state().regions[get_app_state().selected_region];

    if (get_app_state().view_offset >= reg.size)
        get_app_state().view_offset = 0;
    SIZE_T remaining = reg.size - get_app_state().view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    auto src = get_active_source();
    if (src == nullptr)
    {
        set_status("[ERROR] No memory source available");
        return;
    }

    Snapshot snap;
    snap.data.resize(to_read);
    SIZE_T bytes_read = src->read(reg.base + get_app_state().view_offset, to_read, snap.data.data());

    if (bytes_read == 0)
    {
        set_status("[ERROR] Could not capture snapshot: memory unreadable at 0x" + fmt_addr(reg.base + get_app_state().view_offset));
        return;
    }
    snap.data.resize(bytes_read);
    snap.view_offset = get_app_state().view_offset;
    snap.timestamp_ms = GetTickCount();

    size_t snap_num = reg.snapshots.size() + 1;
    char label_buf[64];
    if (reg.snapshots.empty())
    {
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (0.0s)", snap_num);
    }
    else
    {
        DWORD elapsed_ms = snap.timestamp_ms - reg.snapshots[0].timestamp_ms;
        double sec = static_cast<double>(elapsed_ms) / 1000.0;
        std::snprintf(label_buf, sizeof(label_buf), "Snap #%zu (+%.1fs)", snap_num, sec);
    }
    snap.label = label_buf;

    reg.snapshots.push_back(snap);
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < get_app_state().visible_indices.size(); ++vis)
    {
        if (get_app_state().visible_indices[vis] == get_app_state().selected_region)
        {
            SendMessageA(get_app_state().list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }

    char status[192];
    std::snprintf(status, sizeof(status),
                  "Captured %s for region 0x%016llX (%zu bytes) | %zu snapshot(s) in timeline",
                  snap.label.c_str(),
                  static_cast<unsigned long long>(reg.base + get_app_state().view_offset),
                  bytes_read, reg.snapshots.size());
    set_status(status);
    display_selected_region(static_cast<SIZE_T>(-1));
}

void on_clear_snapshots()
{
    if (!get_app_state().has_selection || get_app_state().selected_region >= get_app_state().regions.size())
        return;
    RegionInfo &reg = get_app_state().regions[get_app_state().selected_region];
    size_t count = reg.snapshots.size();
    reg.snapshots.clear();
    invalidate_hex_cache();
    update_diff_combo();
    populate_region_list();
    for (size_t vis = 0; vis < get_app_state().visible_indices.size(); ++vis)
    {
        if (get_app_state().visible_indices[vis] == get_app_state().selected_region)
        {
            SendMessageA(get_app_state().list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    display_selected_region(static_cast<SIZE_T>(-1));

    char status[128];
    std::snprintf(status, sizeof(status), "Cleared %zu snapshot(s) for current region.", count);
    set_status(status);
}

void display_selected_region(SIZE_T focus_offset)
{
    if (!get_app_state().has_selection || get_app_state().selected_region >= get_app_state().regions.size())
    {
        SetWindowTextA(get_app_state().lbl_hex_info, "Hex View: (no region selected)");
        SetWindowTextA(get_app_state().edit_hex, "");
        get_app_state().last_hex_info.clear();
        get_app_state().last_hex_dump.clear();
        EnableWindow(get_app_state().btn_prev_page, FALSE);
        EnableWindow(get_app_state().btn_next_page, FALSE);
        return;
    }

    const RegionInfo &reg = get_app_state().regions[get_app_state().selected_region];
    if (get_app_state().view_offset >= reg.size)
    {
        get_app_state().view_offset = 0;
    }

    SIZE_T remaining = reg.size - get_app_state().view_offset;
    SIZE_T to_read = (remaining < VIEW_PAGE_SIZE) ? remaining : VIEW_PAGE_SIZE;

    EnableWindow(get_app_state().btn_prev_page, get_app_state().view_offset > 0 ? TRUE : FALSE);
    EnableWindow(get_app_state().btn_next_page, (get_app_state().view_offset + to_read < reg.size) ? TRUE : FALSE);

    DiffPair dp = get_active_diff_pair();
    std::vector<uint8_t> buf;
    SIZE_T bytes_read = 0;
    BOOL ok = TRUE;
    DWORD read_err = 0;

    if (dp.active && dp.cmp_data != nullptr)
    {
        buf = *dp.cmp_data;
        bytes_read = buf.size();
    }
    else
    {
        auto src = get_active_source();
        if (src == nullptr)
        {
            std::string msg = "[ERROR] No memory source available\r\n";
            SetWindowTextA(get_app_state().edit_hex, msg.c_str());
            get_app_state().last_hex_dump = msg;
            return;
        }

        buf.resize(to_read);
        bytes_read = src->read(reg.base + get_app_state().view_offset, to_read, buf.data());

        if (bytes_read == 0)
        {
            std::string msg = "[WARN] Memory unreadable at 0x" + fmt_addr(reg.base + get_app_state().view_offset) + "\r\n";
            SetWindowTextA(get_app_state().edit_hex, msg.c_str());
            get_app_state().last_hex_dump = msg;
            return;
        }
        buf.resize(bytes_read);
    }

    const uint8_t *ref_ptr = nullptr;
    size_t ref_len = 0;
    bool offset_mismatch = false;
    uintptr_t display_addr = reg.base + get_app_state().view_offset;
    SIZE_T display_view_offset = get_app_state().view_offset;

    if (dp.active)
    {
        if (dp.cmp_data != nullptr)
        {
            display_view_offset = dp.cmp_view_offset;
            display_addr = reg.base + display_view_offset;
            if (dp.ref_view_offset != dp.cmp_view_offset)
            {
                offset_mismatch = true;
            }
            else
            {
                ref_ptr = dp.ref_data->data();
                ref_len = dp.ref_data->size();
            }
        }
        else
        {
            if (dp.ref_view_offset == get_app_state().view_offset)
            {
                ref_ptr = dp.ref_data->data();
                ref_len = dp.ref_data->size();
            }
            else
            {
                offset_mismatch = true;
            }
        }
    }

    int focus_line = -1;
    size_t chg_bytes = 0, new_bytes = 0, zeroed_bytes = 0;
    std::string dump = build_hex_dump(buf.data(), bytes_read, display_addr,
                                      reg.hits, display_view_offset, get_app_state().active_pattern.bytes.size(),
                                      focus_offset, focus_line,
                                      ref_ptr, ref_len, dp.active && !offset_mismatch,
                                      chg_bytes, new_bytes, zeroed_bytes);

    if (offset_mismatch)
    {
        char warn_note[256];
        if (dp.cmp_data != nullptr)
        {
            std::snprintf(warn_note, sizeof(warn_note),
                          "[Note: Snapshots belong to different page offsets (0x%llX vs 0x%llX). Cannot diff across different offsets.]\r\n\r\n",
                          static_cast<unsigned long long>(dp.ref_view_offset),
                          static_cast<unsigned long long>(dp.cmp_view_offset));
        }
        else
        {
            std::snprintf(warn_note, sizeof(warn_note),
                          "[Note: Selected snapshot belongs to offset 0x%llX; current page is 0x%llX. Navigate back or take a new snapshot.]\r\n\r\n",
                          static_cast<unsigned long long>(dp.ref_view_offset),
                          static_cast<unsigned long long>(get_app_state().view_offset));
        }
        dump = warn_note + dump;
        if (focus_line >= 0)
            focus_line += 2;
    }

    if (!ok)
    {
        dump = "[WARN] Partial read (" + std::to_string(bytes_read) + "/" + std::to_string(to_read) +
               " bytes): " + format_win32_error(read_err) + "\r\n\r\n" + dump;
        if (focus_line >= 0)
            focus_line += 2;
    }

    char info[360];
    std::string det_tag;
    if (reg.is_pe_in_private)
        det_tag = " [! INJECTED PE]";
    else if (reg.private_rwx)
        det_tag = " [! RWX]";
    else if (reg.is_unbacked_exec)
        det_tag = " [! UNBACKED EXEC]";

    if (dp.active && !offset_mismatch)
    {
        std::snprintf(info, sizeof(info),
                      "Reg %zu/%zu | Base 0x%016llX | AllocBase 0x%016llX | %s | %s%s | Diff [%s]: %zu chg (%zu new, %zu wiped)",
                      get_app_state().selected_region + 1, get_app_state().regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      static_cast<unsigned long long>(reg.alloc_base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      det_tag.c_str(),
                      dp.title.c_str(), chg_bytes, new_bytes, zeroed_bytes);
    }
    else
    {
        std::snprintf(info, sizeof(info),
                      "Reg %zu/%zu | Base 0x%016llX | AllocBase 0x%016llX | %s | %s%s | Showing 0x%llX..0x%llX of 0x%llX",
                      get_app_state().selected_region + 1, get_app_state().regions.size(),
                      static_cast<unsigned long long>(reg.base),
                      static_cast<unsigned long long>(reg.alloc_base),
                      type_full(reg.type).c_str(),
                      prot_full(reg.protect).c_str(),
                      det_tag.c_str(),
                      static_cast<unsigned long long>(display_view_offset),
                      static_cast<unsigned long long>(display_view_offset + to_read),
                      static_cast<unsigned long long>(reg.size));
    }

    if (get_app_state().last_hex_info != info)
    {
        SetWindowTextA(get_app_state().lbl_hex_info, info);
        get_app_state().last_hex_info = info;
    }

    if (get_app_state().last_hex_dump != dump)
    {
        int first_line = static_cast<int>(SendMessageA(get_app_state().edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(get_app_state().edit_hex, WM_SETREDRAW, FALSE, 0);
        SetWindowTextA(get_app_state().edit_hex, dump.c_str());
        if (focus_line > 3)
        {
            SendMessageA(get_app_state().edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(focus_line - 3));
        }
        else if (first_line > 0)
        {
            SendMessageA(get_app_state().edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>(first_line));
        }
        else
        {
            SendMessageA(get_app_state().edit_hex, EM_SETSEL, 0, 0);
            SendMessageA(get_app_state().edit_hex, EM_SCROLLCARET, 0, 0);
        }
        SendMessageA(get_app_state().edit_hex, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(get_app_state().edit_hex, nullptr, TRUE);
        get_app_state().last_hex_dump = dump;
    }
    else if (focus_line > 3)
    {
        int cur = static_cast<int>(SendMessageA(get_app_state().edit_hex, EM_GETFIRSTVISIBLELINE, 0, 0));
        SendMessageA(get_app_state().edit_hex, EM_LINESCROLL, 0, static_cast<LPARAM>((focus_line - 3) - cur));
    }
}

void on_next_hit()
{
    if (!get_app_state().has_pattern || get_app_state().regions.empty())
        return;

    size_t total_hits = 0;
    for (size_t i = 0; i < get_app_state().regions.size(); ++i)
    {
        total_hits += get_app_state().regions[i].hits.size();
    }
    if (total_hits == 0)
        return;

    get_app_state().hit_cursor_index += 1;
    if (get_app_state().hit_cursor_region >= get_app_state().regions.size() ||
        get_app_state().hit_cursor_index >= get_app_state().regions[get_app_state().hit_cursor_region].hits.size())
    {
        get_app_state().hit_cursor_index = 0;
        size_t r = (get_app_state().hit_cursor_region + 1) % get_app_state().regions.size();
        while (get_app_state().regions[r].hits.empty())
        {
            r = (r + 1) % get_app_state().regions.size();
        }
        get_app_state().hit_cursor_region = r;
    }

    SIZE_T hit_off = get_app_state().regions[get_app_state().hit_cursor_region].hits[get_app_state().hit_cursor_index];
    SIZE_T page_off = (hit_off / VIEW_PAGE_SIZE) * VIEW_PAGE_SIZE;
    select_region_in_ui(get_app_state().hit_cursor_region, page_off, hit_off);

    char status[160];
    std::snprintf(status, sizeof(status),
                  "Hit at 0x%016llX (region %zu, hit %zu/%zu in region)",
                  static_cast<unsigned long long>(get_app_state().regions[get_app_state().hit_cursor_region].base + hit_off),
                  get_app_state().hit_cursor_region + 1,
                  get_app_state().hit_cursor_index + 1,
                  get_app_state().regions[get_app_state().hit_cursor_region].hits.size());
    set_status(status);
}

} // namespace gui
