// src/gui/views.cpp
// Deadeye GUI Region List and Visual Triage Views Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/views.hpp"
#include "gui/app.hpp"
#include "gui/hexview.hpp"
#include "gui/controls.hpp"
#include "core/util.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace gui {

void update_triage_details_label(size_t reg_idx)
{
    if (get_app_state().view_mode == ViewMode::ProcessDiff)
    {
        if (reg_idx < get_app_state().process_diffs.size())
        {
            const auto &d = get_app_state().process_diffs[reg_idx];
            std::string kind_str = (d.kind == ProcessDiffKind::Appeared) ? "NEW" :
                                   (d.kind == ProcessDiffKind::Disappeared) ? "REMOVED" :
                                   (d.kind == ProcessDiffKind::ProtectionChg) ? "PROT_CHG" : "MODIFIED";
            std::string text = "Diff Details [" + kind_str + "]: 0x" + to_hex_string(d.base) + " (" + fmt_size_short(d.size) + ") | " + d.summary;
            SetWindowTextA(get_app_state().lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(get_app_state().lbl_triage_reasons, "Diff Details: Ready.");
        }
        return;
    }

    if (get_app_state().view_mode == ViewMode::BehaviorTracker)
    {
        if (reg_idx < get_app_state().watched_regions.size())
        {
            const auto &w = get_app_state().watched_regions[reg_idx];
            std::string text = "Behavior [Score " + std::to_string(w.behavior_score) + "]: " +
                               (w.evidence_summary.empty() ? "Monitoring region. Samples collected: " + std::to_string(w.ring_samples.size()) : w.evidence_summary);
            SetWindowTextA(get_app_state().lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(get_app_state().lbl_triage_reasons, "Behavior Details: Ready. Press Ctrl+P to pin selected region.");
        }
        return;
    }

    if (get_app_state().view_mode == ViewMode::StringsView)
    {
        if (reg_idx < get_app_state().extracted_strings.size())
        {
            const auto &st = get_app_state().extracted_strings[reg_idx];
            std::string text = "String at 0x" + to_hex_string(st.addr) + " [" + st.encoding + ", len " +
                               std::to_string(st.length) + "] " +
                               (st.is_new ? "[NEW SINCE BASELINE] " : "") + st.tag_hint + ": " + st.text;
            SetWindowTextA(get_app_state().lbl_triage_reasons, text.c_str());
        }
        else
        {
            SetWindowTextA(get_app_state().lbl_triage_reasons, "Strings Details: Ready. F7 to extract, Ctrl+B to set baseline.");
        }
        return;
    }

    if (reg_idx >= get_app_state().regions.size())
    {
        SetWindowTextA(get_app_state().lbl_triage_reasons, "Details: Ready.");
        return;
    }
    const RegionInfo &reg = get_app_state().regions[reg_idx];

    const TriageFinding *match = nullptr;
    for (const auto &f : get_app_state().triage_report.findings)
    {
        if (f.region_index == reg_idx)
        {
            match = &f;
            break;
        }
    }

    bool synthetic = (get_app_state().current_source != nullptr && get_app_state().current_source->capabilities().protection_is_synthetic);

    std::string text;
    if (match != nullptr && !match->reasons.empty())
    {
        text = "Details [" + match->severity_label + " " + std::to_string(match->severity_score) + "]: ";
        for (size_t i = 0; i < match->reasons.size(); ++i)
        {
            text += match->reasons[i];
            if (i + 1 < match->reasons.size())
                text += " | ";
        }
        if (synthetic)
        {
            text = "[Synthetic Protection] " + text;
        }
    }
    else
    {
        text = "Details [CLEAN 0]: Normal " + type_full(reg.type) + " memory (" +
               prot_full(reg.protect) + "), AllocBase " + to_hex_string(reg.alloc_base);
        if (synthetic)
        {
            text = "[Synthetic Protection] " + text;
        }
    }

    // Append per-region average, max, and compact ASCII profile of page entropies
    if (reg.avg_entropy >= 0.0)
    {
        char ent_buf[160];
        std::snprintf(ent_buf, sizeof(ent_buf), " | Entropy: avg %.2f, max %.2f [%s]%s",
                      reg.avg_entropy, reg.max_entropy, reg.entropy_ascii_profile.c_str(),
                      reg.entropy_sampled ? " (sampled)" : "");
        text += ent_buf;
    }

    SetWindowTextA(get_app_state().lbl_triage_reasons, text.c_str());
}

void populate_region_list()
{
    SendMessageA(get_app_state().list_regions, WM_SETREDRAW, FALSE, 0);
    SendMessageA(get_app_state().list_regions, LB_RESETCONTENT, 0, 0);
    get_app_state().visible_indices.clear();

    bool hits_only = (SendMessageA(get_app_state().chk_hits_only, BM_GETCHECK, 0, 0) == BST_CHECKED);

    if (get_app_state().view_mode == ViewMode::ProcessDiff)
    {
        if (get_app_state().process_diffs.empty())
        {
            SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No process diffs. Capture baseline (Ctrl+B), then diff (Ctrl+D)."));
        }
        else
        {
            for (size_t i = 0; i < get_app_state().process_diffs.size(); ++i)
            {
                const auto &d = get_app_state().process_diffs[i];
                std::string badge;
                switch (d.kind)
                {
                    case ProcessDiffKind::Appeared: badge = "[+NEW   ]"; break;
                    case ProcessDiffKind::Disappeared: badge = "[-FREED ]"; break;
                    case ProcessDiffKind::ProtectionChg: badge = "[!PROT  ]"; break;
                    case ProcessDiffKind::ContentChg: badge = "[~MODIF ]"; break;
                    default: badge = "[ UNCHG ]"; break;
                }

                char row[256];
                std::snprintf(row, sizeof(row), "%-9s %016llX %s %-4s %-8s %s",
                              badge.c_str(),
                              static_cast<unsigned long long>(d.base),
                              fmt_size_short(d.size).c_str(),
                              type_short(d.type).c_str(),
                              prot_short(d.new_protect ? d.new_protect : d.old_protect).c_str(),
                              d.summary.c_str());

                SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                get_app_state().visible_indices.push_back(i);
            }
        }
        SendMessageA(get_app_state().list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(get_app_state().list_regions, nullptr, TRUE);
        return;
    }

    if (get_app_state().view_mode == ViewMode::BehaviorTracker)
    {
        if (get_app_state().watched_regions.empty())
        {
            SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No watched regions. Attach live process & triage, or press Ctrl+P to pin selected region."));
        }
        else
        {
            for (size_t i = 0; i < get_app_state().watched_regions.size(); ++i)
            {
                const auto &w = get_app_state().watched_regions[i];
                char sev_badge[32];
                std::snprintf(sev_badge, sizeof(sev_badge), "[SCR %3d]", w.behavior_score);

                std::string flg_str;
                for (const auto &flg : w.behavior_flags)
                {
                    if (flg == "SLEEP_MASK_SUSPECT") flg_str += "!SMSP ";
                    else if (flg == "KEY_ROTATION_SUSPECT") flg_str += "!KROT ";
                    else if (flg == "DECRYPT_ON_WAKE") flg_str += "!DWAK ";
                }
                if (flg_str.empty()) flg_str = "      ";
                while (flg_str.size() < 14) flg_str.push_back(' ');

                char hbuf[32];
                if (w.ring_samples.empty())
                {
                    strcpy(hbuf, "H:--/--");
                }
                else
                {
                    double min_e = 10.0, max_e = -1.0;
                    for (const auto &s : w.ring_samples)
                    {
                        if (!s.is_unreadable)
                        {
                            if (s.avg_entropy < min_e) min_e = s.avg_entropy;
                            if (s.avg_entropy > max_e) max_e = s.avg_entropy;
                        }
                    }
                    if (max_e >= 0.0)
                        std::snprintf(hbuf, sizeof(hbuf), "H:%.1f-%.1f", min_e, max_e);
                    else
                        strcpy(hbuf, "H:unreadable");
                }

                double last_chg = 0.0;
                if (!w.ring_samples.empty()) last_chg = w.ring_samples.back().changed_fraction * 100.0;
                DWORD last_prot = w.ring_samples.empty() ? w.alloc_protect : w.ring_samples.back().protect;

                char row[256];
                std::snprintf(row, sizeof(row), "%-11s %-14s %016llX %4zus %-11s %2dc %3.0f%% %-4s %s",
                              sev_badge, flg_str.c_str(),
                              static_cast<unsigned long long>(w.key.base),
                              w.ring_samples.size(),
                              hbuf,
                              w.sleep_evidence.cycles,
                              last_chg,
                              prot_short(last_prot).c_str(),
                              w.is_pinned ? "[PIN]" : "");

                SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                get_app_state().visible_indices.push_back(i);
            }
        }
        SendMessageA(get_app_state().list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(get_app_state().list_regions, nullptr, TRUE);
        return;
    }

    if (get_app_state().view_mode == ViewMode::StringsView)
    {
        if (get_app_state().extracted_strings.empty())
        {
            SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("No strings extracted. Press F7 to extract selected region, or use Strings -> Extract All."));
        }
        else
        {
            char pat_buf[256] = {};
            GetWindowTextA(get_app_state().edit_pattern, pat_buf, sizeof(pat_buf));
            std::string q_str(pat_buf);
            for (char &c : q_str) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            for (size_t i = 0; i < get_app_state().extracted_strings.size(); ++i)
            {
                const auto &st = get_app_state().extracted_strings[i];
                if (get_app_state().strings_filter_new_only && !st.is_new)
                    continue;

                if (!q_str.empty())
                {
                    std::string text_lower = st.text;
                    for (char &c : text_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (text_lower.find(q_str) == std::string::npos)
                        continue;
                }

                char row[512];
                std::snprintf(row, sizeof(row), "%016llX %-8s %-4zu %-14s %-6s %s",
                              static_cast<unsigned long long>(st.addr),
                              st.encoding.c_str(),
                              st.length,
                              st.tag_hint.c_str(),
                              st.is_new ? "[NEW]" : "     ",
                              st.text.c_str());

                SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
                get_app_state().visible_indices.push_back(i);
            }
        }
        SendMessageA(get_app_state().list_regions, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(get_app_state().list_regions, nullptr, TRUE);
        return;
    }

    if (get_app_state().view_mode == ViewMode::TriageFindings)
    {
        for (size_t i = 0; i < get_app_state().triage_report.findings.size(); ++i)
        {
            const TriageFinding &f = get_app_state().triage_report.findings[i];
            if (f.region_index >= get_app_state().regions.size())
                continue;
            const RegionInfo &r = get_app_state().regions[f.region_index];

            if (f.severity_score < get_app_state().min_sev_filter)
                continue;
            if (get_app_state().hide_clean && f.severity_score == 0)
                continue;
            if (hits_only && r.hits.empty())
                continue;

            char sev_badge[32];
            std::snprintf(sev_badge, sizeof(sev_badge), "[%-4s %3d]", f.severity_label.c_str(), f.severity_score);

            std::string flg_str;
            for (const auto &flg : f.flags)
            {
                if (flg == "INJECTED_PE")
                    flg_str += "!PE ";
                else if (flg == "UNLINKED_MODULE")
                    flg_str += "!UNL ";
                else if (flg == "PRIVATE_RWX")
                    flg_str += "!RWX ";
                else if (flg == "WRITE_THEN_FLIP")
                    flg_str += "!FLIP ";
                else if (flg == "UNBACKED_EXEC")
                    flg_str += "!X ";
                else if (flg == "BEHAVIOR_UNPACK")
                    flg_str += "!UNPK ";
                else if (flg == "SLEEP_OBFUSCATION")
                    flg_str += "!SLP ";
                else if (flg == "STATIC_WX_SECTION")
                    flg_str += "!W+X ";
                else if (flg == "STATIC_EP_OUTSIDE_EXEC")
                    flg_str += "!EP ";
                else if (flg == "STATIC_EXEC_HIGH_ENTROPY")
                    flg_str += "!ENT ";
                else if (flg == "STATIC_NONTRIVIAL_OVERLAY")
                    flg_str += "!OVL ";
                else if (flg == "HIGH_ENTROPY_EXEC")
                    flg_str += "!HENT ";
                else if (flg == "HIGH_ENTROPY_PRIVATE")
                    flg_str += "!HPVT ";
                else if (flg == "SLEEP_MASK_SUSPECT")
                    flg_str += "!SMSP ";
                else if (flg == "KEY_ROTATION_SUSPECT")
                    flg_str += "!KROT ";
                else if (flg == "DECRYPT_ON_WAKE")
                    flg_str += "!DWAK ";
            }
            if (flg_str.empty())
                flg_str = "      ";
            while (flg_str.size() < 14)
                flg_str.push_back(' ');

            std::string tag;
            if (!r.hits.empty())
            {
                tag += " [" + std::to_string(r.hits.size()) + "h]";
            }
            if (!r.snapshots.empty())
            {
                tag += " (" + std::to_string(r.snapshots.size()) + "s)";
            }

            char row[256];
            std::snprintf(row, sizeof(row), "%-11s %-14s %016llX %s %-4s %-4s%s",
                          sev_badge, flg_str.c_str(),
                          static_cast<unsigned long long>(f.base),
                          fmt_size_short(f.size).c_str(),
                          type_short(f.type).c_str(),
                          prot_short(f.protect).c_str(),
                          tag.c_str());

            SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
            get_app_state().visible_indices.push_back(f.region_index);
        }
    }
    else
    {
        // ViewMode::MemoryMap
        for (size_t i = 0; i < get_app_state().regions.size(); ++i)
        {
            const RegionInfo &r = get_app_state().regions[i];
            if (hits_only && r.hits.empty())
                continue;

            // Find severity for filtering in map mode
            int sev = 0;
            for (const auto &f : get_app_state().triage_report.findings)
            {
                if (f.region_index == i)
                {
                    sev = f.severity_score;
                    break;
                }
            }

            if (sev < get_app_state().min_sev_filter)
                continue;
            if (get_app_state().hide_clean && sev == 0)
                continue;

            char row[256];
            std::string tag;
            if (!r.hits.empty())
            {
                char hbuf[48];
                if (r.hits_truncated)
                {
                    std::snprintf(hbuf, sizeof(hbuf), " [%zu+ hits (capped)]", r.hits.size());
                }
                else
                {
                    std::snprintf(hbuf, sizeof(hbuf), " [%zu hit%s]", r.hits.size(), r.hits.size() == 1 ? "" : "s");
                }
                tag += hbuf;
            }
            if (!r.snapshots.empty())
            {
                char sbuf[32];
                std::snprintf(sbuf, sizeof(sbuf), " (%zu snap%s)", r.snapshots.size(), r.snapshots.size() == 1 ? "" : "s");
                tag += sbuf;
            }

            std::string flag = "    ";
            if (r.is_pe_in_private)
                flag = "!PE ";
            else if (r.private_rwx)
                flag = "!RWX";
            else if (r.write_then_flip)
                flag = "!FLP";
            else if (r.is_unlinked_image)
                flag = "!UNL";
            else if (r.is_unbacked_exec)
                flag = "!X  ";

            if (!r.section_name.empty())
            {
                tag = " [" + r.section_name + "]" + tag;
            }

            if (r.avg_entropy >= 0.0)
            {
                char hbuf[32];
                std::snprintf(hbuf, sizeof(hbuf), " H:%.1f/%.1f", r.avg_entropy, r.max_entropy);
                tag += hbuf;
            }

            std::snprintf(row, sizeof(row), "%016llX %s %s %s %s%s",
                          static_cast<unsigned long long>(r.base),
                          fmt_size_short(r.size).c_str(),
                          type_short(r.type).c_str(),
                          prot_short(r.protect).c_str(),
                          flag.c_str(),
                          tag.c_str());

            SendMessageA(get_app_state().list_regions, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row));
            get_app_state().visible_indices.push_back(i);
        }
    }

    SendMessageA(get_app_state().list_regions, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(get_app_state().list_regions, nullptr, TRUE);
}

void select_region_in_ui(size_t region_idx, SIZE_T view_offset, SIZE_T focus_offset)
{
    if (region_idx >= get_app_state().regions.size())
        return;
    get_app_state().selected_region = region_idx;
    get_app_state().has_selection = true;
    get_app_state().view_offset = view_offset;

    for (size_t vis = 0; vis < get_app_state().visible_indices.size(); ++vis)
    {
        if (get_app_state().visible_indices[vis] == region_idx)
        {
            SendMessageA(get_app_state().list_regions, LB_SETCURSEL, static_cast<WPARAM>(vis), 0);
            break;
        }
    }
    update_diff_combo();
    invalidate_hex_cache();
    display_selected_region(focus_offset);
    update_triage_details_label(region_idx);
}

// Visual Triage List Item Drawing Handler
void draw_region_list_item(DRAWITEMSTRUCT *dis)
{
    if (dis->itemID == static_cast<UINT>(-1))
        return;

    const ThemeColors &tc = get_theme_colors(get_app_state().theme);
    size_t vis_idx = static_cast<size_t>(dis->itemID);

    if (get_app_state().visible_indices.empty() || vis_idx >= get_app_state().visible_indices.size())
    {
        HDC hdc = dis->hDC;
        HBRUSH hbr = CreateSolidBrush(tc.bg_control);
        FillRect(hdc, &dis->rcItem, hbr);
        DeleteObject(hbr);

        char buf[256] = {};
        SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(buf));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, tc.text_muted);
        HGDIOBJ old_font = SelectObject(hdc, get_app_state().mono_font);
        RECT text_rc = dis->rcItem;
        text_rc.left += 6;
        DrawTextA(hdc, buf, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, old_font);
        return;
    }

    size_t reg_idx = get_app_state().visible_indices[vis_idx];

    bool is_selected = (dis->itemState & ODS_SELECTED) != 0;

    COLORREF bg_color = tc.row_image_bg;
    COLORREF text_color = tc.row_image_text;

    if (get_app_state().view_mode == ViewMode::ProcessDiff)
    {
        if (reg_idx < get_app_state().process_diffs.size())
        {
            const auto &d = get_app_state().process_diffs[reg_idx];
            switch (d.kind)
            {
                case ProcessDiffKind::Appeared:
                    bg_color = tc.row_diff_new_bg;
                    text_color = tc.row_diff_new_text;
                    break;
                case ProcessDiffKind::ProtectionChg:
                    bg_color = tc.row_diff_chg_bg;
                    text_color = tc.row_diff_chg_text;
                    break;
                case ProcessDiffKind::ContentChg:
                    bg_color = tc.row_diff_mod_bg;
                    text_color = tc.row_diff_mod_text;
                    break;
                case ProcessDiffKind::Disappeared:
                    bg_color = tc.row_diff_del_bg;
                    text_color = tc.row_diff_del_text;
                    break;
                default:
                    break;
            }
        }
    }
    else if (get_app_state().view_mode == ViewMode::BehaviorTracker)
    {
        if (reg_idx < get_app_state().watched_regions.size())
        {
            const auto &w = get_app_state().watched_regions[reg_idx];
            if (w.behavior_score >= SEV_MIN_CRITICAL)
            {
                bg_color = tc.row_pe_bg;
                text_color = tc.row_pe_text;
            }
            else if (w.behavior_score >= SEV_MIN_HIGH)
            {
                bg_color = tc.row_rwx_bg;
                text_color = tc.row_rwx_text;
            }
            else if (w.behavior_score >= SEV_MIN_MEDIUM)
            {
                bg_color = tc.row_flip_bg;
                text_color = tc.row_flip_text;
            }
            else
            {
                bg_color = tc.row_priv_bg;
                text_color = tc.row_priv_text;
            }
        }
    }
    else if (get_app_state().view_mode == ViewMode::StringsView)
    {
        if (reg_idx < get_app_state().extracted_strings.size())
        {
            const auto &st = get_app_state().extracted_strings[reg_idx];
            if (st.is_new)
            {
                bg_color = tc.row_diff_new_bg;
                text_color = tc.row_diff_new_text;
            }
            else
            {
                bg_color = tc.row_priv_bg;
                text_color = tc.row_priv_text;
            }
        }
    }
    else
    {
        if (reg_idx >= get_app_state().regions.size())
            return;
        const RegionInfo &reg = get_app_state().regions[reg_idx];

        // Apply highlight colors based on region threat indicators
        if (reg.is_pe_in_private)
        {
            bg_color = tc.row_pe_bg;
            text_color = tc.row_pe_text;
        }
        else if (reg.private_rwx)
        {
            bg_color = tc.row_rwx_bg;
            text_color = tc.row_rwx_text;
        }
        else if (reg.write_then_flip)
        {
            bg_color = tc.row_flip_bg;
            text_color = tc.row_flip_text;
        }
        else if (reg.is_unlinked_image)
        {
            bg_color = tc.row_unlinked_bg;
            text_color = tc.row_unlinked_text;
        }
        else if (reg.is_unbacked_exec)
        {
            bg_color = tc.row_unbacked_bg;
            text_color = tc.row_unbacked_text;
        }
        else if (reg.type == MEM_PRIVATE)
        {
            bg_color = tc.row_priv_bg;
            text_color = tc.row_priv_text;
        }
        else if (reg.type == MEM_MAPPED)
        {
            bg_color = tc.row_mapped_bg;
            text_color = tc.row_mapped_text;
        }
    }

    if (is_selected)
    {
        bg_color = tc.row_sel_bg;
        text_color = tc.row_sel_text;
    }

    HDC hdc = dis->hDC;
    HBRUSH hbr = CreateSolidBrush(bg_color);
    FillRect(hdc, &dis->rcItem, hbr);
    DeleteObject(hbr);

    char buf[512] = {};
    SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(buf));

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, text_color);
    HGDIOBJ old_font = SelectObject(hdc, get_app_state().mono_font);

    RECT text_rc = dis->rcItem;
    text_rc.left += 6; // Left margin padding
    DrawTextA(hdc, buf, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(hdc, old_font);
}

} // namespace gui
