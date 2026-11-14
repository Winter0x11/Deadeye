// src/core/live_source.hpp
// Deadeye Defensive Triage Live Process MemorySource
#pragma once

#include "core/memsource.hpp"
#include <tlhelp32.h>

bool query_peb_modules_x64(HANDLE proc, std::vector<LoadedModuleRange> &out_modules, bool &out_wow64);
bool query_process_regions(HANDLE proc, std::vector<RegionInfo> &out_regions, std::string &err_msg);

class LiveProcessSource : public MemorySource
{
private:
    DWORD m_pid = 0;
    std::string m_process_name;
    HANDLE m_proc = nullptr;
    bool m_owns_handle = false;

    HANDLE get_handle();

public:
    LiveProcessSource(DWORD pid, const std::string &name = "");
    LiveProcessSource(DWORD pid, HANDLE proc, bool take_ownership, const std::string &name = "");
    ~LiveProcessSource() override;

    LiveProcessSource(const LiveProcessSource &) = delete;
    LiveProcessSource &operator=(const LiveProcessSource &) = delete;

    std::string describe() const override;
    MemorySourceKind kind() const override;
    MemorySourceCapabilities capabilities() const override;
    DWORD get_pid() const override;
    HANDLE get_raw_handle();

    bool query_regions(std::vector<RegionInfo> &out_regions, std::string &out_err) override;
    SIZE_T read(uintptr_t addr, SIZE_T len, uint8_t *out_buf) override;
    bool query_peb_modules(std::vector<LoadedModuleRange> &modules, bool &wow64_unsupported) override;
};
