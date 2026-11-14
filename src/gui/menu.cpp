// src/gui/menu.cpp
// Deadeye GUI Menu and Accelerators Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/menu.hpp"

namespace gui {

HMENU create_application_menu()
{
    HMENU hMenuBar = CreateMenu();

    // 1. File Menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_ATTACH, "&Attach to Process...\tCtrl+A");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_OPEN_SOURCE, "&Open Memory Source...\tCtrl+O");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_TRIAGE, "Run Defensive &Triage\tCtrl+T");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXPORT_JSON, "&Export Triage JSON...\tCtrl+S");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);

    HMENU hThemeMenu = CreatePopupMenu();
    AppendMenuA(hThemeMenu, MF_STRING, IDM_FILE_THEME_LIGHT, "&Light Mode");
    AppendMenuA(hThemeMenu, MF_STRING, IDM_FILE_THEME_DARK, "&Dark Mode");
    AppendMenuA(hFileMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(hThemeMenu), "&Theme");

    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "E&xit\tAlt+F4");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), "&File");

    // 2. Edit Menu
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_ADDR, "&Copy Region Address\tCtrl+C");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_HEX, "Copy &Hex Dump\tCtrl+Shift+C");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_PATTERN, "&Find Hex Pattern...\tCtrl+F");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_NEXT, "Find &Next Hit\tF3");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_GENERATE_YARA, "Generate &YARA Rule from Selection...\tCtrl+Y");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hEditMenu), "&Edit");

    // 3. View Menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_TRIAGE_FINDINGS, "&Triage Findings View\tCtrl+1");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MEMORY_MAP, "&Memory Map View\tCtrl+2");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_BEHAVIOR, "&Behavior Tracker View\tCtrl+3");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_STRINGS, "&Strings View\tCtrl+4");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_PROCESS_DIFF, "&Process Diff View\tCtrl+5");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_HIDE_CLEAN, "&Hide Clean Regions");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_HITS_ONLY, "&Hits Only Filter");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_REFRESH, "&Refresh Memory Walk\tF5");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hViewMenu), "&View");

    // 4. Behavior Menu
    HMENU hBehaviorMenu = CreatePopupMenu();
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_BEHAVIOR_PIN, "&Pin / Unpin Selected Region\tCtrl+P");
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_BEHAVIOR_WATCH_ALL_PRIV, "Watch &All Private Executable Regions");
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_BEHAVIOR_CLEAR, "&Clear Sample History");
    AppendMenuA(hBehaviorMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hBehaviorMenu, MF_STRING, IDM_HELP_BEHAVIOR_LIMITS, "Polling &Limitations & Detection Guide...");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hBehaviorMenu), "&Behavior");

    // 5. Strings Menu
    HMENU hStringsMenu = CreatePopupMenu();
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_BASELINE, "Set String &Baseline\tCtrl+B");
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_TOGGLE_NEW, "Toggle &New Since Baseline Filter\tF6");
    AppendMenuA(hStringsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_EXTRACT_SEL, "Extract Strings from &Selected Region\tF7");
    AppendMenuA(hStringsMenu, MF_STRING, IDM_STRINGS_EXTRACT_ALL, "Extract Strings across &All Regions");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hStringsMenu), "&Strings");

    // 6. Diff Menu
    HMENU hDiffMenu = CreatePopupMenu();
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_CAPTURE_BASELINE, "Capture &Baseline Snapshot\tCtrl+B");
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_CAPTURE_CURRENT, "Compare with &Current (Diff)\tCtrl+D");
    AppendMenuA(hDiffMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_SAVE_SESSION, "&Save Diff Session to JSON...");
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_LOAD_SESSION, "&Load Diff Session from JSON...");
    AppendMenuA(hDiffMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hDiffMenu, MF_STRING, IDM_DIFF_VIEW_STRINGS, "View Newly &Revealed Strings...\tCtrl+U");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hDiffMenu), "&Diff");

    // 7. Timeline Menu
    HMENU hTimelineMenu = CreatePopupMenu();
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_SNAP, "&Take Snapshot\tCtrl+N");
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_CLEAR, "&Clear All Snapshots");
    AppendMenuA(hTimelineMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_HEARTBEAT, "&Live Memory Heartbeat (1s)");
    AppendMenuA(hTimelineMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_PREV_PAGE, "&Previous 64K Page\tPgUp");
    AppendMenuA(hTimelineMenu, MF_STRING, IDM_TIMELINE_NEXT_PAGE, "&Next 64K Page\tPgDn");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hTimelineMenu), "&Timeline");

    // 8. Help Menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_HEURISTICS, "&Defensive Heuristics Guide...");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_BEHAVIOR_LIMITS, "&Behavior Polling Limitations...");
    AppendMenuA(hHelpMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "&About Deadeye...");
    AppendMenuA(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelpMenu), "&Help");

    return hMenuBar;
}

HACCEL create_application_accelerators()
{
    ACCEL accels[] = {
        { FCONTROL | FVIRTKEY, 'A', IDM_FILE_ATTACH },
        { FCONTROL | FVIRTKEY, 'O', IDM_FILE_OPEN_SOURCE },
        { FCONTROL | FVIRTKEY, 'T', ID_BTN_TRIAGE },
        { FCONTROL | FVIRTKEY, 'S', ID_BTN_EXPORT_JSON },
        { FCONTROL | FVIRTKEY, 'F', IDM_EDIT_FIND_PATTERN },
        { FVIRTKEY, VK_F3, ID_BTN_NEXT_HIT },
        { FVIRTKEY, VK_F5, ID_BTN_LOAD },
        { FCONTROL | FVIRTKEY, 'C', IDM_EDIT_COPY_ADDR },
        { FCONTROL | FSHIFT | FVIRTKEY, 'C', IDM_EDIT_COPY_HEX },
        { FCONTROL | FVIRTKEY, 'N', ID_BTN_SNAP },
        { FCONTROL | FVIRTKEY, '1', IDM_VIEW_TRIAGE_FINDINGS },
        { FCONTROL | FVIRTKEY, '2', IDM_VIEW_MEMORY_MAP },
        { FCONTROL | FVIRTKEY, '3', IDM_VIEW_BEHAVIOR },
        { FCONTROL | FVIRTKEY, '4', IDM_VIEW_STRINGS },
        { FCONTROL | FVIRTKEY, '5', IDM_VIEW_PROCESS_DIFF },
        { FCONTROL | FVIRTKEY, 'P', IDM_BEHAVIOR_PIN },
        { FCONTROL | FVIRTKEY, 'B', IDM_STRINGS_BASELINE },
        { FVIRTKEY, VK_F6, IDM_STRINGS_TOGGLE_NEW },
        { FVIRTKEY, VK_F7, IDM_STRINGS_EXTRACT_SEL },
        { FCONTROL | FVIRTKEY, 'D', IDM_DIFF_CAPTURE_CURRENT },
        { FCONTROL | FVIRTKEY, 'Y', ID_BTN_YARA },
        { FCONTROL | FVIRTKEY, 'U', IDM_DIFF_VIEW_STRINGS }
    };
    return CreateAcceleratorTableA(accels, static_cast<int>(sizeof(accels) / sizeof(accels[0])));
}

} // namespace gui
