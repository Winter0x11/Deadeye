// src/main.cpp
// Deadeye Defensive Process Memory Triage Scanner
// Application Entry Point

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <cstring>
#include <cstdio>
#include <memory>
#include <vector>
#include <string>

#include "core/util.hpp"
#include "core/memsource.hpp"
#include "core/live_source.hpp"
#include "core/triage.hpp"
#include "core/json_export.hpp"
#include "gui/app.hpp"

#ifdef _MSC_VER
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;

    // Acquire SeDebugPrivilege so elevated runs can inspect system services
    enable_debug_privilege();

    if (lpCmdLine != nullptr && std::strstr(lpCmdLine, "--json") != nullptr)
    {
        const char *p = std::strstr(lpCmdLine, "--json");
        p += 6;
        while (*p == ' ') p++;
        char pid_str[64] = {};
        char out_path[MAX_PATH] = {};
        if (std::sscanf(p, "%63s %259s", pid_str, out_path) == 2)
        {
            DWORD target_pid = 0;
            if (parse_pid_string(pid_str, target_pid) && target_pid != 0)
            {
                auto live_src = std::make_shared<LiveProcessSource>(target_pid);
                if (live_src->get_raw_handle() != nullptr)
                {
                    std::vector<RegionInfo> regions;
                    std::string err;
                    if (live_src->query_regions(regions, err))
                    {
                        TriageReport report = run_source_triage(live_src, regions);
                        std::string json_data = export_triage_json(report);
                        std::string out_file = out_path;
                        if (out_file.size() >= 2 && out_file.front() == '"' && out_file.back() == '"')
                        {
                            out_file = out_file.substr(1, out_file.size() - 2);
                        }
                        FILE *fp = std::fopen(out_file.c_str(), "wb");
                        if (fp != nullptr)
                        {
                            std::fwrite(json_data.data(), 1, json_data.size(), fp);
                            std::fclose(fp);
                            return 0;
                        }
                    }
                }
            }
            return 1;
        }
    }

    return gui::run_gui(hInstance, nCmdShow);
}
