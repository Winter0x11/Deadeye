// src/gui/yara_dialog.cpp
// Deadeye YARA Rule Generator & False Positive Validator Dialog Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/yara_dialog.hpp"
#include "gui/app.hpp"
#include "gui/controls.hpp"
#include "core/behavior.hpp"
#include "core/pattern.hpp"
#include "core/util.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

namespace gui {

struct YaraDialogData
{
    std::string rule_text;
    uintptr_t base_addr = 0;
    DWORD pid = 0;
    HWND hEditRule = nullptr;
    HWND hEditReport = nullptr;
    HWND hBtnTestFP = nullptr;
    HWND hBtnCopy = nullptr;
    HWND hBtnSave = nullptr;
    HWND hBtnClose = nullptr;
};

LRESULT CALLBACK YaraDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<YaraDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<YaraDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));

        HINSTANCE hInst = cs->hInstance;

        HWND lbl1 = CreateWindowA("STATIC", "Generated YARA Rule (Auto-Wildcarded for Displacements, Relocations & Immediates):",
                                  WS_CHILD | WS_VISIBLE, 12, 12, 730, 18, hwnd, nullptr, hInst, nullptr);

        data->hEditRule = CreateWindowA("EDIT", data->rule_text.c_str(),
                                        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
                                        12, 34, 740, 240, hwnd, reinterpret_cast<HMENU>(3001), hInst, nullptr);

        data->hBtnTestFP = CreateWindowA("BUTTON", "Run False-Positive Test",
                                         WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         12, 284, 200, 28, hwnd, reinterpret_cast<HMENU>(3002), hInst, nullptr);

        data->hBtnCopy = CreateWindowA("BUTTON", "Copy Rule",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       222, 284, 100, 28, hwnd, reinterpret_cast<HMENU>(3003), hInst, nullptr);

        data->hBtnSave = CreateWindowA("BUTTON", "Save .yar File...",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       332, 284, 130, 28, hwnd, reinterpret_cast<HMENU>(3004), hInst, nullptr);

        data->hBtnClose = CreateWindowA("BUTTON", "Close",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        652, 284, 100, 28, hwnd, reinterpret_cast<HMENU>(3005), hInst, nullptr);

        HWND lbl2 = CreateWindowA("STATIC", "False-Positive Test Status & Clean Software Verification:",
                                  WS_CHILD | WS_VISIBLE, 12, 322, 730, 18, hwnd, nullptr, hInst, nullptr);

        data->hEditReport = CreateWindowA("EDIT", "Ready. Click 'Run False-Positive Test' to scan all active running processes on the system.",
                                          WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL |
                                              ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                          12, 344, 740, 220, hwnd, reinterpret_cast<HMENU>(3006), hInst, nullptr);

        HWND ui_ctrls[] = { lbl1, data->hBtnTestFP, data->hBtnCopy, data->hBtnSave, data->hBtnClose, lbl2 };
        for (HWND c : ui_ctrls)
            SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().ui_font), TRUE);

        SendMessageA(data->hEditRule, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().mono_font), TRUE);
        SendMessageA(data->hEditReport, WM_SETFONT, reinterpret_cast<WPARAM>(get_app_state().mono_font), TRUE);

        make_button_modern(data->hBtnTestFP, ModernButtonStyle::Primary);
        make_button_modern(data->hBtnCopy, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnSave, ModernButtonStyle::Accent);
        make_button_modern(data->hBtnClose, ModernButtonStyle::Standard);

        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        if (id == 3002) // Run FP Test
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hEditRule);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hEditRule, buf.data(), len + 1);
            std::string rule_str = buf.data();

            std::string hex_str;
            size_t str_pos = rule_str.find("strings:");
            if (str_pos != std::string::npos)
            {
                size_t sig_brace_start = rule_str.find('{', str_pos);
                if (sig_brace_start != std::string::npos)
                {
                    size_t sig_brace_end = rule_str.find('}', sig_brace_start);
                    if (sig_brace_end != std::string::npos && sig_brace_end > sig_brace_start)
                    {
                        hex_str = rule_str.substr(sig_brace_start + 1, sig_brace_end - sig_brace_start - 1);
                    }
                }
            }
            if (hex_str.empty())
            {
                size_t first_brace = rule_str.find('{');
                if (first_brace != std::string::npos)
                {
                    size_t second_brace = rule_str.find('{', first_brace + 1);
                    if (second_brace != std::string::npos)
                    {
                        size_t second_brace_end = rule_str.find('}', second_brace);
                        if (second_brace_end != std::string::npos && second_brace_end > second_brace)
                        {
                            hex_str = rule_str.substr(second_brace + 1, second_brace_end - second_brace - 1);
                        }
                    }
                }
            }
            if (hex_str.empty())
            {
                hex_str = rule_str;
            }

            Pattern pat;
            std::string perr;
            if (!parse_pattern(hex_str, pat, perr))
            {
                SetWindowTextA(data->hEditReport, ("[ERROR] Invalid signature pattern: " + perr).c_str());
                return 0;
            }

            SetWindowTextA(data->hEditReport, "Scanning all running processes on the system... Please wait...");
            UpdateWindow(data->hEditReport);

            FalsePositiveReport rep = test_rule_false_positives(pat, data->pid);

            std::ostringstream ss;
            ss << "======================================================================\r\n";
            ss << "                     FALSE-POSITIVE TEST REPORT                       \r\n";
            ss << "======================================================================\r\n\r\n";
            ss << "Target PID (Excluded):      " << data->pid << "\r\n";
            ss << "Running Processes Scanned:  " << rep.total_processes_scanned << " (out of " << rep.total_processes_checked << " total)\r\n";
            ss << "Executable Memory Searched: " << fmt_size_short(rep.total_bytes_scanned) << "\r\n";
            ss << "Scan Time:                  " << rep.elapsed_ms << " ms\r\n\r\n";

            if (rep.matches.empty())
            {
                ss << ">>> RESULT: [PASSED - 0 FALSE POSITIVES] <<<\r\n";
                ss << "The generated signature did not match any clean running software on this system.\r\n";
                ss << "This rule is highly specific and safe for deployment in detection pipelines.\r\n";
            }
            else
            {
                ss << ">>> RESULT: [WARNING - " << rep.matches.size() << " FALSE POSITIVES DETECTED] <<<\r\n";
                ss << "Matches were detected in clean system software:\r\n";
                for (const auto &m : rep.matches)
                {
                    char abuf[32];
                    std::snprintf(abuf, sizeof(abuf), "0x%016llX", static_cast<unsigned long long>(m.match_addr));
                    ss << "  * " << m.process_name << " (PID " << m.pid << ") at " << abuf << "\r\n";
                }
                ss << "\r\nRecommendation: Restrict wildcards or include anchor instruction prefixes.\r\n";
            }

            SetWindowTextA(data->hEditReport, ss.str().c_str());
        }
        else if (id == 3003) // Copy Rule
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hEditRule);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hEditRule, buf.data(), len + 1);
            copy_text_to_clipboard(hwnd, buf.data());
            MessageBoxA(hwnd, "YARA rule copied to clipboard.", "Deadeye YARA", MB_OK | MB_ICONINFORMATION);
        }
        else if (id == 3004) // Save .yar
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hEditRule);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hEditRule, buf.data(), len + 1);

            char file_buf[MAX_PATH] = "deadeye_rule.yar";
            OPENFILENAMEA ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = "YARA Rules (*.yar;*.yara)\0*.yar;*.yara\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = file_buf;
            ofn.nMaxFile = sizeof(file_buf);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = "yar";

            if (GetSaveFileNameA(&ofn))
            {
                std::ofstream f(ofn.lpstrFile, std::ios::binary);
                if (f.is_open())
                {
                    f.write(buf.data(), len);
                    MessageBoxA(hwnd, "Rule saved successfully.", "Deadeye YARA", MB_OK | MB_ICONINFORMATION);
                }
            }
        }
        else if (id == 3005) // Close
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_theme_colors(get_app_state().theme);
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(get_app_state().br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, get_app_state().br_window);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
    {
        HWND hOwner = GetWindow(hwnd, GW_OWNER);
        if (hOwner)
        {
            EnableWindow(hOwner, TRUE);
            SetActiveWindow(hOwner);
        }
        if (data) delete data;
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

void open_yara_dialog(HWND hParent)
{
    uintptr_t target_base = 0;
    if (get_app_state().view_mode == ViewMode::ProcessDiff)
    {
        if (get_app_state().selected_region < get_app_state().process_diffs.size())
        {
            target_base = get_app_state().process_diffs[get_app_state().selected_region].base + get_app_state().view_offset;
        }
    }
    else
    {
        if (get_app_state().selected_region < get_app_state().regions.size())
        {
            target_base = get_app_state().regions[get_app_state().selected_region].base + get_app_state().view_offset;
        }
    }

    if (target_base == 0)
    {
        MessageBoxA(hParent, "Please select a memory region or bytes in hex view first.", "Deadeye YARA Generator", MB_OK | MB_ICONWARNING);
        return;
    }

    std::vector<uint8_t> target_bytes;

    // Check if user selected text in hex dump
    DWORD sel_start = 0, sel_end = 0;
    SendMessageA(get_app_state().edit_hex, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start), reinterpret_cast<LPARAM>(&sel_end));
    if (sel_start != sel_end)
    {
        int len = GetWindowTextLengthA(get_app_state().edit_hex);
        if (len > 0)
        {
            std::vector<char> full_text(len + 1);
            GetWindowTextA(get_app_state().edit_hex, full_text.data(), len + 1);
            std::string sel_text(full_text.data() + sel_start, full_text.data() + sel_end);

            std::istringstream iss(sel_text);
            std::string tok;
            while (iss >> tok)
            {
                if (tok.size() == 2 && isxdigit(static_cast<unsigned char>(tok[0])) && isxdigit(static_cast<unsigned char>(tok[1])))
                {
                    uint8_t b = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
                    target_bytes.push_back(b);
                }
            }
        }
    }

    if (target_bytes.empty())
    {
        // Read 64 bytes at current view offset
        HANDLE proc = get_or_open_target_proc(get_app_state().current_pid);
        if (proc)
        {
            target_bytes.resize(64);
            SIZE_T bytes_read = 0;
            ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(target_base), target_bytes.data(), 64, &bytes_read);
            target_bytes.resize(bytes_read);
        }
    }

    if (target_bytes.empty())
    {
        MessageBoxA(hParent, "Could not read memory bytes at current location to generate rule.", "Deadeye YARA Generator", MB_OK | MB_ICONWARNING);
        return;
    }

    std::string rule_name = "sig_mem_pid" + std::to_string(get_app_state().current_pid) + "_" + to_hex_string(target_base).substr(8);
    YaraWildcardResult wres = auto_wildcard_bytes(target_bytes.data(), target_bytes.size(), target_base, get_app_state().current_pid, rule_name);
    std::string rule_text = generate_yara_rule_text(wres, target_base, get_app_state().current_pid, rule_name);

    YaraDialogData *data = new YaraDialogData();
    data->rule_text = rule_text;
    data->base_addr = target_base;
    data->pid = get_app_state().current_pid;

    EnableWindow(hParent, FALSE);

    RECT parent_rc;
    GetWindowRect(hParent, &parent_rc);
    int dlg_w = 780, dlg_h = 620;
    int dlg_x = parent_rc.left + (parent_rc.right - parent_rc.left - dlg_w) / 2;
    int dlg_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - dlg_h) / 2;
    if (dlg_x < 10) dlg_x = 10;
    if (dlg_y < 10) dlg_y = 10;

    CreateWindowExA(WS_EX_DLGMODALFRAME, "DeadeyeYaraDlg",
                    "YARA Rule Generator & False-Positive Validator",
                    WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                    dlg_x, dlg_y, dlg_w, dlg_h, hParent, nullptr, GetModuleHandleA(nullptr), data);
}

} // namespace gui
