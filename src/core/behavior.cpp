// src/core/behavior.cpp
// Deadeye Defensive Triage Behavior Analysis, Diffing, and YARA Generation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "core/behavior.hpp"
#include "core/scoring.hpp"
#include "core/util.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <psapi.h>
#include <tlhelp32.h>

// Light classification tags for extracted strings (labeled as hints)
std::string classify_string_tag(const std::string &s)
{
    // URL
    if (s.rfind("http://", 0) == 0 || s.rfind("https://", 0) == 0)
        return "[URL] (hint)";

    // IPv4 Literal: 4 decimal numbers separated by dots
    size_t dots = 0;
    bool is_ip = true;
    for (char c : s)
    {
        if (c == '.') dots++;
        else if (!std::isdigit(static_cast<unsigned char>(c))) { is_ip = false; break; }
    }
    if (is_ip && dots == 3 && s.size() >= 7 && s.size() <= 15)
        return "[IP] (hint)";

    // Probable Domain: ends with known TLD, contains valid domain characters
    static const char *TLDS[] = { ".com", ".net", ".org", ".io", ".gov", ".edu", ".ru", ".cn", ".xyz", ".biz", ".info", ".online", ".site" };
    for (const char *tld : TLDS)
    {
        size_t tlen = std::strlen(tld);
        if (s.size() > tlen && s.compare(s.size() - tlen, tlen, tld) == 0)
        {
            bool valid = true;
            for (char c : s)
            {
                if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-')
                { valid = false; break; }
            }
            if (valid) return "[DOMAIN] (hint)";
        }
    }

    // File path hint: starts with X:\ or \\ network share
    if ((s.size() >= 3 && std::isalpha(static_cast<unsigned char>(s[0])) && s[1] == ':' && s[2] == '\\') ||
        (s.size() >= 2 && s[0] == '\\' && s[1] == '\\'))
        return "[PATH] (hint)";

    // Registry path hint: starts with HKEY_, HKLM\, HKCU\, or HKCR\ key
    if (s.rfind("HKEY_", 0) == 0 || s.rfind("HKLM\\", 0) == 0 || s.rfind("HKCU\\", 0) == 0 || s.rfind("HKCR\\", 0) == 0)
        return "[REG] (hint)";

    return "              ";
}

std::string categorize_extracted_string(const std::string &s)
{
    if (s.rfind("http://", 0) == 0 || s.rfind("https://", 0) == 0 || s.rfind("ftp://", 0) == 0 ||
        s.find("api.") != std::string::npos || s.find(".onion") != std::string::npos)
        return "[URL] ";

    size_t dots = 0;
    bool is_ip = true;
    for (char c : s)
    {
        if (c == '.') dots++;
        else if (!std::isdigit(static_cast<unsigned char>(c))) { is_ip = false; break; }
    }
    if (is_ip && dots == 3 && s.size() >= 7 && s.size() <= 15)
        return "[IP]  ";

    if (s.find(":\\") != std::string::npos || s.find("System32") != std::string::npos ||
        s.find("AppData") != std::string::npos || s.find("Temp\\") != std::string::npos)
        return "[PATH]";

    if (s.find("powershell") != std::string::npos || s.find("cmd.exe") != std::string::npos ||
        s.find("-enc") != std::string::npos || s.find("bypass") != std::string::npos ||
        s.find("wscript") != std::string::npos || s.find("bitsadmin") != std::string::npos ||
        s.find("whoami") != std::string::npos || s.find("net user") != std::string::npos)
        return "[CMD] ";

    if (s.rfind("HKLM\\", 0) == 0 || s.rfind("HKCU\\", 0) == 0 ||
        s.find("CurrentVersion\\Run") != std::string::npos || s.find("Software\\Microsoft") != std::string::npos)
        return "[REG] ";

    return "[STR] ";
}

std::vector<RevealedString> extract_strings_from_buffer(const uint8_t *data, size_t len, uintptr_t base_addr, size_t min_len)
{
    std::vector<RevealedString> results;
    if (len < min_len) return results;

    // ASCII extraction
    std::string cur_str;
    size_t cur_start = 0;
    for (size_t i = 0; i < len; ++i)
    {
        uint8_t b = data[i];
        if (b >= 32 && b <= 126)
        {
            if (cur_str.empty()) cur_start = i;
            cur_str.push_back(static_cast<char>(b));
        }
        else
        {
            if (cur_str.size() >= min_len)
            {
                RevealedString rs;
                rs.text = cur_str;
                rs.category = categorize_extracted_string(cur_str);
                rs.addr = base_addr + cur_start;
                results.push_back(rs);
            }
            cur_str.clear();
        }
    }
    if (cur_str.size() >= min_len)
    {
        RevealedString rs;
        rs.text = cur_str;
        rs.category = categorize_extracted_string(cur_str);
        rs.addr = base_addr + cur_start;
        results.push_back(rs);
    }

    // UTF-16LE extraction
    std::string cur_wstr;
    size_t cur_wstart = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
    {
        uint8_t c = data[i];
        uint8_t zero = data[i + 1];
        if (zero == 0 && c >= 32 && c <= 126)
        {
            if (cur_wstr.empty()) cur_wstart = i;
            cur_wstr.push_back(static_cast<char>(c));
        }
        else
        {
            if (cur_wstr.size() >= min_len)
            {
                RevealedString rs;
                rs.text = cur_wstr;
                rs.category = categorize_extracted_string(cur_wstr);
                rs.addr = base_addr + cur_wstart;
                results.push_back(rs);
            }
            cur_wstr.clear();
        }
    }
    if (cur_wstr.size() >= min_len)
    {
        RevealedString rs;
        rs.text = cur_wstr;
        rs.category = categorize_extracted_string(cur_wstr);
        rs.addr = base_addr + cur_wstart;
        results.push_back(rs);
    }

    return results;
}

// Extracts ASCII and UTF-16LE strings with memory/length capping and baseline comparison
void extract_all_strings_from_source(
    std::shared_ptr<MemorySource> source,
    const std::vector<RegionInfo> &regions,
    int selected_idx,
    size_t min_len,
    std::vector<ExtractedStringItem> &out_strings,
    const std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> *baselines)
{
    out_strings.clear();
    if (!source || regions.empty()) return;

    size_t start_r = (selected_idx >= 0 && selected_idx < static_cast<int>(regions.size())) ? static_cast<size_t>(selected_idx) : 0;
    size_t end_r = (selected_idx >= 0 && selected_idx < static_cast<int>(regions.size())) ? (start_r + 1) : regions.size();

    const size_t MAX_TOTAL_STRINGS = 20000;
    const size_t MAX_STRINGS_PER_REGION = 5000;

    std::vector<uint8_t> read_buf(64 * 1024);

    for (size_t r = start_r; r < end_r && out_strings.size() < MAX_TOTAL_STRINGS; ++r)
    {
        const auto &reg = regions[r];
        if (reg.size == 0) continue;

        size_t strings_in_reg = 0;
        SIZE_T bytes_scanned = 0;
        SIZE_T total_to_scan = std::min<SIZE_T>(reg.size, 1024 * 1024); // Cap scan to 1 MB per region

        while (bytes_scanned < total_to_scan && strings_in_reg < MAX_STRINGS_PER_REGION && out_strings.size() < MAX_TOTAL_STRINGS)
        {
            SIZE_T chunk = std::min<SIZE_T>(read_buf.size(), total_to_scan - bytes_scanned);
            SIZE_T n_read = source->read(reg.base + bytes_scanned, chunk, read_buf.data());
            if (n_read < min_len)
            {
                bytes_scanned += chunk;
                continue;
            }

            // ASCII extraction
            std::string cur_str;
            size_t cur_start = 0;
            for (size_t i = 0; i < n_read; ++i)
            {
                uint8_t b = read_buf[i];
                if (b >= 32 && b <= 126)
                {
                    if (cur_str.empty()) cur_start = i;
                    cur_str.push_back(static_cast<char>(b));
                }
                else
                {
                    if (cur_str.size() >= min_len)
                    {
                        ExtractedStringItem item;
                        item.addr = reg.base + bytes_scanned + cur_start;
                        item.encoding = "ASCII";
                        item.length = cur_str.size();
                        item.tag_hint = classify_string_tag(cur_str);
                        item.content_hash = fnv1a64(reinterpret_cast<const uint8_t*>(cur_str.data()), cur_str.size());
                        item.region_base = reg.base;
                        if (baselines && baselines->count(reg.base) > 0)
                        {
                            item.is_new = (baselines->at(reg.base).count(item.content_hash) == 0);
                        }
                        item.text = (cur_str.size() > 256) ? (cur_str.substr(0, 256) + "...") : cur_str;
                        out_strings.push_back(item);
                        strings_in_reg++;
                        if (strings_in_reg >= MAX_STRINGS_PER_REGION || out_strings.size() >= MAX_TOTAL_STRINGS)
                            break;
                    }
                    cur_str.clear();
                }
            }
            if (cur_str.size() >= min_len && strings_in_reg < MAX_STRINGS_PER_REGION && out_strings.size() < MAX_TOTAL_STRINGS)
            {
                ExtractedStringItem item;
                item.addr = reg.base + bytes_scanned + cur_start;
                item.encoding = "ASCII";
                item.length = cur_str.size();
                item.tag_hint = classify_string_tag(cur_str);
                item.content_hash = fnv1a64(reinterpret_cast<const uint8_t*>(cur_str.data()), cur_str.size());
                item.region_base = reg.base;
                if (baselines && baselines->count(reg.base) > 0)
                {
                    item.is_new = (baselines->at(reg.base).count(item.content_hash) == 0);
                }
                item.text = (cur_str.size() > 256) ? (cur_str.substr(0, 256) + "...") : cur_str;
                out_strings.push_back(item);
                strings_in_reg++;
            }

            // UTF-16LE extraction
            std::string cur_wstr;
            size_t cur_wstart = 0;
            for (size_t i = 0; i + 1 < n_read; i += 2)
            {
                uint8_t c = read_buf[i];
                uint8_t zero = read_buf[i + 1];
                if (zero == 0 && c >= 32 && c <= 126)
                {
                    if (cur_wstr.empty()) cur_wstart = i;
                    cur_wstr.push_back(static_cast<char>(c));
                }
                else
                {
                    if (cur_wstr.size() >= min_len)
                    {
                        ExtractedStringItem item;
                        item.addr = reg.base + bytes_scanned + cur_wstart;
                        item.encoding = "UTF-16";
                        item.length = cur_wstr.size();
                        item.tag_hint = classify_string_tag(cur_wstr);
                        item.content_hash = fnv1a64(reinterpret_cast<const uint8_t*>(cur_wstr.data()), cur_wstr.size());
                        item.region_base = reg.base;
                        if (baselines && baselines->count(reg.base) > 0)
                        {
                            item.is_new = (baselines->at(reg.base).count(item.content_hash) == 0);
                        }
                        item.text = (cur_wstr.size() > 256) ? (cur_wstr.substr(0, 256) + "...") : cur_wstr;
                        out_strings.push_back(item);
                        strings_in_reg++;
                        if (strings_in_reg >= MAX_STRINGS_PER_REGION || out_strings.size() >= MAX_TOTAL_STRINGS)
                            break;
                    }
                    cur_wstr.clear();
                }
            }
            if (cur_wstr.size() >= min_len && strings_in_reg < MAX_STRINGS_PER_REGION && out_strings.size() < MAX_TOTAL_STRINGS)
            {
                ExtractedStringItem item;
                item.addr = reg.base + bytes_scanned + cur_wstart;
                item.encoding = "UTF-16";
                item.length = cur_wstr.size();
                item.tag_hint = classify_string_tag(cur_wstr);
                item.content_hash = fnv1a64(reinterpret_cast<const uint8_t*>(cur_wstr.data()), cur_wstr.size());
                item.region_base = reg.base;
                if (baselines && baselines->count(reg.base) > 0)
                {
                    item.is_new = (baselines->at(reg.base).count(item.content_hash) == 0);
                }
                item.text = (cur_wstr.size() > 256) ? (cur_wstr.substr(0, 256) + "...") : cur_wstr;
                out_strings.push_back(item);
                strings_in_reg++;
            }

            bytes_scanned += chunk;
        }
    }
}

// Appends sample to ring buffer (capped at 120 samples per region)
void add_sample_to_ring(WatchedRegionState &wreg, const RegionSampleRecord &rec)
{
    if (wreg.ring_samples.size() >= RING_BUFFER_CAP)
    {
        wreg.ring_samples.erase(wreg.ring_samples.begin());
    }
    wreg.ring_samples.push_back(rec);
    wreg.total_samples++;
}

// Evaluates behavioral detections over watched region sample history
void evaluate_watched_region_detections(
    std::shared_ptr<MemorySource> source,
    WatchedRegionState &wreg,
    const std::unordered_map<uintptr_t, std::unordered_set<uint64_t>> *baselines)
{
    (void)source;
    wreg.behavior_flags.clear();
    wreg.behavior_score = 0;
    std::string evidence_str;

    if (wreg.ring_samples.size() < 2) return;

    bool is_exec = (wreg.alloc_protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) != 0;
    for (const auto &s : wreg.ring_samples)
    {
        if ((s.protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) != 0)
        {
            is_exec = true;
            break;
        }
    }
    bool is_suspicious_static = is_exec || (wreg.type == MEM_PRIVATE);

    // 1. SLEEP_MASK_SUSPECT:
    // Oscillations between low-entropy (< 5.5) and high-entropy (> 7.0),
    // and/or protection cycles through executable <-> non-executable or NOACCESS states, at least 3 full cycles.
    int cycles = 0;
    double min_ent = 99.0;
    double max_ent = -1.0;
    std::string protect_seq;
    DWORD last_prot = 0;
    bool in_dormant_state = false;
    uint64_t first_cycle_t = 0;
    uint64_t last_cycle_t = 0;

    for (size_t i = 0; i < wreg.ring_samples.size(); ++i)
    {
        const auto &s = wreg.ring_samples[i];
        if (!s.is_unreadable && s.avg_entropy > 0.0)
        {
            if (s.avg_entropy < min_ent) min_ent = s.avg_entropy;
            if (s.avg_entropy > max_ent) max_ent = s.avg_entropy;
        }

        if (s.protect != last_prot && s.protect != 0)
        {
            if (!protect_seq.empty()) protect_seq += "->";
            protect_seq += prot_short(s.protect);
            last_prot = s.protect;
        }

        bool cur_dormant = ((s.protect & (PAGE_NOACCESS | PAGE_READWRITE | PAGE_READONLY)) != 0) || (s.avg_entropy > 7.0);
        bool cur_active = ((s.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0) && (s.avg_entropy < 6.0 && s.avg_entropy > 0.0);

        if (!in_dormant_state && cur_dormant)
        {
            in_dormant_state = true;
        }
        else if (in_dormant_state && cur_active)
        {
            cycles++;
            in_dormant_state = false;
            if (first_cycle_t == 0) first_cycle_t = s.timestamp_ms;
            last_cycle_t = s.timestamp_ms;
        }
    }

    if (min_ent > 10.0) min_ent = 0.0;
    if (max_ent < 0.0) max_ent = 0.0;

    if (cycles >= 3)
    {
        double period_ms = (cycles > 1 && last_cycle_t > first_cycle_t) ?
            static_cast<double>(last_cycle_t - first_cycle_t) / static_cast<double>(cycles - 1) : 2000.0;

        wreg.sleep_evidence.cycles = cycles;
        wreg.sleep_evidence.period_ms = period_ms;
        wreg.sleep_evidence.min_entropy = min_ent;
        wreg.sleep_evidence.max_entropy = max_ent;
        wreg.sleep_evidence.protect_seq = protect_seq;

        int score = is_suspicious_static ? WEIGHT_SLEEP_MASK_SUSPECT : (WEIGHT_SLEEP_MASK_SUSPECT / 2);
        wreg.behavior_score += score;
        wreg.behavior_flags.push_back("SLEEP_MASK_SUSPECT");

        char buf[256];
        std::snprintf(buf, sizeof(buf), "[SLEEP_MASK] %d cycles (~%.0fms), H: %.2f-%.2f, Seq: %s",
                      cycles, period_ms, min_ent, max_ent, protect_seq.c_str());
        if (!evidence_str.empty()) evidence_str += " | ";
        evidence_str += buf;
    }

    // 2. KEY_ROTATION_SUSPECT:
    // High entropy while content hash changes with large changed-byte fraction.
    // XOR delta image check: test repeating period P in [1, 64].
    const RegionSampleRecord *s1 = nullptr;
    const RegionSampleRecord *s2 = nullptr;

    for (auto it = wreg.ring_samples.rbegin(); it != wreg.ring_samples.rend(); ++it)
    {
        if (!it->is_unreadable && it->avg_entropy >= 6.8 && it->sample_bytes.size() >= 256)
        {
            if (!s2)
            {
                s2 = &(*it);
            }
            else if (!s1)
            {
                if (it->content_hash != s2->content_hash && it->changed_fraction >= 0.25)
                {
                    s1 = &(*it);
                    break;
                }
            }
        }
    }

    if (s1 && s2)
    {
        size_t L = (std::min)(s1->sample_bytes.size(), s2->sample_bytes.size());
        if (L >= 256)
        {
            std::vector<uint8_t> delta(L);
            for (size_t i = 0; i < L; ++i)
            {
                delta[i] = s1->sample_bytes[i] ^ s2->sample_bytes[i];
            }

            size_t best_period = 0;
            for (size_t P = 1; P <= 64 && P < L / 2; ++P)
            {
                size_t comparisons = L - P;
                size_t matches = 0;
                for (size_t i = 0; i < comparisons; ++i)
                {
                    if (delta[i] == delta[i + P])
                        matches++;
                }
                if (matches == comparisons && comparisons >= 128)
                {
                    best_period = P;
                    break;
                }
            }

            if (best_period > 0)
            {
                wreg.key_evidence.xor_period = best_period;
                wreg.key_evidence.avg_entropy = s2->avg_entropy;
                wreg.key_evidence.avg_changed_frac = s2->changed_fraction;
                wreg.key_evidence.candidate_delta_key.assign(delta.begin(), delta.begin() + best_period);
                wreg.key_evidence.note = "Candidate delta key represents XOR difference between consecutive states, not recovered plaintext key.";

                int score = is_suspicious_static ? WEIGHT_KEY_ROTATION_SUSPECT : (WEIGHT_KEY_ROTATION_SUSPECT / 2);
                wreg.behavior_score += score;
                wreg.behavior_flags.push_back("KEY_ROTATION_SUSPECT");

                std::string key_hex;
                for (size_t b = 0; b < best_period && b < 16; ++b)
                {
                    char h[4];
                    std::snprintf(h, sizeof(h), "%02X ", delta[b]);
                    key_hex += h;
                }

                char buf[256];
                std::snprintf(buf, sizeof(buf), "[KEY_ROTATION] re-keyed with repeating XOR key, period %zu, candidate delta key bytes: %s(note: delta key)",
                              best_period, key_hex.c_str());
                if (!evidence_str.empty()) evidence_str += " | ";
                evidence_str += buf;
            }
        }
    }

    // 3. DECRYPT_ON_WAKE:
    // Entropy drops sharply (high -> low) and new strings appear vs baseline.
    for (size_t i = 1; i < wreg.ring_samples.size(); ++i)
    {
        const auto &prev = wreg.ring_samples[i - 1];
        const auto &curr = wreg.ring_samples[i];
        if (!prev.is_unreadable && !curr.is_unreadable &&
            prev.avg_entropy >= 6.8 && curr.avg_entropy <= 5.8 && (prev.avg_entropy - curr.avg_entropy) >= 1.2)
        {
            if (baselines && baselines->count(wreg.key.base) > 0)
            {
                const auto &base_set = baselines->at(wreg.key.base);
                auto revealed = extract_strings_from_buffer(curr.sample_bytes.data(), curr.sample_bytes.size(), wreg.key.base, 6);
                size_t new_count = 0;
                std::vector<std::string> sample_strs;
                for (const auto &rs : revealed)
                {
                    uint64_t h = fnv1a64(reinterpret_cast<const uint8_t*>(rs.text.data()), rs.text.size());
                    if (base_set.count(h) == 0)
                    {
                        new_count++;
                        if (sample_strs.size() < 10)
                        {
                            sample_strs.push_back(rs.text);
                        }
                    }
                }

                if (new_count > 0)
                {
                    wreg.decrypt_evidence.entropy_before = prev.avg_entropy;
                    wreg.decrypt_evidence.entropy_after = curr.avg_entropy;
                    wreg.decrypt_evidence.new_strings_count = new_count;
                    wreg.decrypt_evidence.sample_strings = sample_strs;

                    int score = is_suspicious_static ? WEIGHT_DECRYPT_ON_WAKE : (WEIGHT_DECRYPT_ON_WAKE / 2);
                    wreg.behavior_score += score;
                    wreg.behavior_flags.push_back("DECRYPT_ON_WAKE");

                    char buf[256];
                    std::snprintf(buf, sizeof(buf), "[DECRYPT_ON_WAKE] H: %.2f->%.2f, %zu new strings vs baseline",
                                  prev.avg_entropy, curr.avg_entropy, new_count);
                    if (!evidence_str.empty()) evidence_str += " | ";
                    evidence_str += buf;
                    break;
                }
            }
        }
    }

    wreg.evidence_summary = evidence_str;
}

// Background worker thread behavior sampling tick
bool run_behavior_tracker_tick(
    std::shared_ptr<MemorySource> source,
    BehaviorTrackerContext &ctx)
{
    if (!source || !source->capabilities().is_live) return false;
    DWORD pid = source->get_pid();
    if (pid == 0) return false;

    HANDLE proc = ctx.proc;
    bool close_proc = false;
    if (!proc)
    {
        proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        close_proc = true;
    }
    if (!proc)
    {
        if (ctx.target_process_exited) ctx.target_process_exited->store(true);
        return false;
    }

    DWORD exit_code = 0;
    if (GetExitCodeProcess(proc, &exit_code) && exit_code != STILL_ACTIVE)
    {
        if (ctx.target_process_exited) ctx.target_process_exited->store(true);
        if (close_proc) CloseHandle(proc);
        return false;
    }

    if (!ctx.watched_regions || !ctx.region_generations || !ctx.regions || !ctx.triage_report ||
        !ctx.total_samples || !ctx.partial_samples || !ctx.rotating_idx)
    {
        if (close_proc) CloseHandle(proc);
        return false;
    }

    auto &watched_regions = *ctx.watched_regions;
    auto &region_generations = *ctx.region_generations;
    const auto &regions = *ctx.regions;
    const auto &triage_report = *ctx.triage_report;

    // Populate initial watch set if empty
    if (watched_regions.empty() && !regions.empty())
    {
        for (const auto &reg : regions)
        {
            bool is_exec = (reg.protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) != 0;
            bool high_ent = (reg.avg_entropy >= 7.2 || reg.max_entropy >= 7.2);
            bool priv_exec = (reg.type == MEM_PRIVATE && is_exec);

            int sev = 0;
            for (const auto &f : triage_report.findings)
            {
                if (f.base == reg.base) { sev = f.severity_score; break; }
            }

            if (sev >= 25 || high_ent || (ctx.watch_all_priv_exec && priv_exec))
            {
                WatchedRegionState ws;
                ws.key.base = reg.base;
                ws.key.alloc_base = reg.alloc_base;
                ws.key.generation = region_generations[reg.base];
                ws.size = reg.size;
                ws.type = reg.type;
                ws.alloc_protect = reg.alloc_protect;
                ws.is_pinned = false;
                watched_regions.push_back(ws);
            }
        }
    }

    size_t N = watched_regions.size();
    if (N == 0)
    {
        if (close_proc) CloseHandle(proc);
        return false;
    }

    auto tick_start = std::chrono::steady_clock::now();
    ctx.total_samples->fetch_add(1);
    bool was_partial = false;
    uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());

    size_t start_idx = (*ctx.rotating_idx) % N;
    size_t sampled_in_tick = 0;

    for (size_t step = 0; step < N; ++step)
    {
        size_t idx = (start_idx + step) % N;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tick_start).count();
        if (elapsed_ms >= 50 && sampled_in_tick > 0)
        {
            was_partial = true;
            *ctx.rotating_idx = idx;
            break;
        }

        WatchedRegionState &wreg = watched_regions[idx];
        if (wreg.is_deallocated) continue;

        sampled_in_tick++;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(wreg.key.base), &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            wreg.is_deallocated = true;
            RegionSampleRecord rec;
            rec.timestamp_ms = now_ms;
            rec.state = MEM_FREE;
            rec.is_unreadable = true;
            add_sample_to_ring(wreg, rec);
            continue;
        }

        if (mbi.State == MEM_FREE)
        {
            wreg.is_deallocated = true;
            RegionSampleRecord rec;
            rec.timestamp_ms = now_ms;
            rec.state = MEM_FREE;
            rec.is_unreadable = true;
            add_sample_to_ring(wreg, rec);
            continue;
        }

        // Handle size or allocation base change without mixing up identities
        if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) != wreg.key.alloc_base || mbi.RegionSize != wreg.size)
        {
            region_generations[wreg.key.base]++;
            wreg.key.alloc_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            wreg.key.generation = region_generations[wreg.key.base];
            wreg.size = mbi.RegionSize;
        }

        RegionSampleRecord rec;
        rec.timestamp_ms = now_ms;
        rec.protect = mbi.Protect;
        rec.state = mbi.State;

        // If NOACCESS or GUARD, record without attempting read
        if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
        {
            rec.is_unreadable = true;
            rec.content_hash = 0;
            rec.avg_entropy = 0.0;
            rec.changed_fraction = 0.0;
            add_sample_to_ring(wreg, rec);
            evaluate_watched_region_detections(source, wreg, ctx.string_baselines);
            continue;
        }

        // Readable: Read capped bytes (up to 64 KB)
        SIZE_T to_read = (wreg.size < 64 * 1024) ? wreg.size : (64 * 1024);
        std::vector<uint8_t> read_buf(to_read);
        SIZE_T bytes_read = 0;
        if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(wreg.key.base), read_buf.data(), to_read, &bytes_read) && bytes_read >= 512)
        {
            rec.is_unreadable = false;
            rec.content_hash = fnv1a64(read_buf.data(), bytes_read);
            rec.avg_entropy = calculate_shannon_entropy(read_buf.data(), bytes_read);

            SIZE_T save_len = (bytes_read < 4096) ? bytes_read : 4096;
            rec.sample_bytes.assign(read_buf.data(), read_buf.data() + save_len);

            if (!wreg.ring_samples.empty())
            {
                const RegionSampleRecord *prev = nullptr;
                for (auto it = wreg.ring_samples.rbegin(); it != wreg.ring_samples.rend(); ++it)
                {
                    if (!it->is_unreadable && !it->sample_bytes.empty())
                    {
                        prev = &(*it);
                        break;
                    }
                }
                if (prev != nullptr)
                {
                    size_t cmp_len = (std::min)(rec.sample_bytes.size(), prev->sample_bytes.size());
                    if (cmp_len > 0)
                    {
                        size_t diff_bytes = 0;
                        for (size_t i = 0; i < cmp_len; ++i)
                        {
                            if (rec.sample_bytes[i] != prev->sample_bytes[i])
                                diff_bytes++;
                        }
                        rec.changed_fraction = static_cast<double>(diff_bytes) / static_cast<double>(cmp_len);
                    }
                }
            }
        }
        else
        {
            rec.is_unreadable = true;
        }

        add_sample_to_ring(wreg, rec);
        evaluate_watched_region_detections(source, wreg, ctx.string_baselines);
    }

    if (was_partial)
    {
        ctx.partial_samples->fetch_add(1);
    }
    else
    {
        *ctx.rotating_idx = (start_idx + sampled_in_tick) % N;
    }

    if (close_proc) CloseHandle(proc);
    return true;
}

bool capture_process_snapshot_session(DWORD pid, ProcessSnapshotSession &out_session, std::string &out_err, HANDLE proc_handle)
{
    bool close_proc = false;
    HANDLE proc = proc_handle;
    if (!proc)
    {
        proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        close_proc = true;
    }
    if (!proc)
    {
        DWORD err = GetLastError();
        out_err = "Cannot open target process (PID " + std::to_string(pid) + "): " + format_win32_error(err);
        return false;
    }

    out_session = ProcessSnapshotSession{};
    out_session.pid = pid;

    char proc_path[MAX_PATH] = {};
    if (GetProcessImageFileNameA(proc, proc_path, MAX_PATH))
    {
        std::string p(proc_path);
        size_t last_slash = p.find_last_of("\\/");
        out_session.process_name = (last_slash != std::string::npos) ? p.substr(last_slash + 1) : p;
    }
    else
    {
        out_session.process_name = "PID " + std::to_string(pid);
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char time_buf[64];
    std::snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    out_session.timestamp_str = time_buf;

    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> read_buffer(256 * 1024);

    while (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT)
        {
            ProcessRegionSnapshot snap;
            snap.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            snap.size = mbi.RegionSize;
            snap.state = mbi.State;
            snap.type = mbi.Type;
            snap.protect = mbi.Protect;
            snap.alloc_protect = mbi.AllocationProtect;
            snap.alloc_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);

            out_session.total_committed_bytes += mbi.RegionSize;

            bool is_guard = (mbi.Protect & PAGE_GUARD) != 0;
            bool no_access = (mbi.Protect & PAGE_NOACCESS) != 0;
            snap.is_readable = !is_guard && !no_access;

            snap.is_unbacked = (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)));
            snap.is_rwx = (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)));
            snap.is_write_then_flip = (mbi.AllocationProtect & (PAGE_READWRITE | PAGE_WRITECOPY)) &&
                                      (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

            if (snap.is_readable)
            {
                SIZE_T to_read = std::min<SIZE_T>(mbi.RegionSize, read_buffer.size());
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(proc, mbi.BaseAddress, read_buffer.data(), to_read, &bytes_read) && bytes_read > 0)
                {
                    snap.content_hash = fnv1a64(read_buffer.data(), bytes_read);
                    snap.entropy = calculate_shannon_entropy(read_buffer.data(), bytes_read);
                    if (bytes_read >= 2 && read_buffer[0] == 'M' && read_buffer[1] == 'Z')
                    {
                        snap.has_pe = true;
                    }
                }
            }
            out_session.regions.push_back(snap);
        }

        uintptr_t next_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next_addr <= addr) break;
        addr = next_addr;
    }

    if (close_proc) CloseHandle(proc);
    return !out_session.regions.empty();
}

void compute_process_diff(const ProcessSnapshotSession &base, const ProcessSnapshotSession &cur, std::vector<ProcessDiffItem> &out_diffs)
{
    out_diffs.clear();
    std::unordered_map<uintptr_t, const ProcessRegionSnapshot*> base_map;
    for (const auto &r : base.regions)
    {
        base_map[r.base] = &r;
    }

    std::unordered_set<uintptr_t> seen_in_cur;

    for (const auto &cr : cur.regions)
    {
        seen_in_cur.insert(cr.base);
        auto it = base_map.find(cr.base);
        if (it == base_map.end())
        {
            ProcessDiffItem item;
            item.kind = ProcessDiffKind::Appeared;
            item.base = cr.base;
            item.size = cr.size;
            item.type = cr.type;
            item.old_protect = 0;
            item.new_protect = cr.protect;
            item.new_entropy = cr.entropy;
            item.new_hash = cr.content_hash;
            item.has_pe = cr.has_pe;
            item.is_rwx = cr.is_rwx;
            item.is_unbacked = cr.is_unbacked;
            item.summary = "New committed region (" + fmt_size_short(cr.size) + " " + type_short(cr.type) + " " + prot_short(cr.protect) + ")";
            if (cr.has_pe) item.summary += " [!PE Injected]";
            if (cr.is_rwx) item.summary += " [!RWX Shellcode]";
            out_diffs.push_back(item);
        }
        else
        {
            const auto &br = *(it->second);
            bool prot_changed = (br.protect != cr.protect);
            bool hash_changed = (br.content_hash != cr.content_hash);

            if (prot_changed || hash_changed)
            {
                ProcessDiffItem item;
                item.base = cr.base;
                item.size = cr.size;
                item.type = cr.type;
                item.old_protect = br.protect;
                item.new_protect = cr.protect;
                item.old_entropy = br.entropy;
                item.new_entropy = cr.entropy;
                item.old_hash = br.content_hash;
                item.new_hash = cr.content_hash;
                item.has_pe = cr.has_pe;
                item.is_rwx = cr.is_rwx;
                item.is_unbacked = cr.is_unbacked;

                bool was_writable = (br.protect & (PAGE_READWRITE | PAGE_WRITECOPY)) != 0;
                bool now_exec = (cr.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
                if (was_writable && now_exec)
                {
                    item.is_unpack = true;
                }

                if (prot_changed)
                {
                    item.kind = ProcessDiffKind::ProtectionChg;
                    item.summary = "Protection flipped: " + prot_short(br.protect) + " -> " + prot_short(cr.protect);
                    if (item.is_unpack) item.summary += " [!Unpack Candidate]";
                }
                else
                {
                    item.kind = ProcessDiffKind::ContentChg;
                    char sbuf[128];
                    std::snprintf(sbuf, sizeof(sbuf), "Content modified: entropy %.2f -> %.2f", br.entropy, cr.entropy);
                    item.summary = sbuf;
                }
                out_diffs.push_back(item);
            }
        }
    }

    for (const auto &br : base.regions)
    {
        if (seen_in_cur.find(br.base) == seen_in_cur.end())
        {
            ProcessDiffItem item;
            item.kind = ProcessDiffKind::Disappeared;
            item.base = br.base;
            item.size = br.size;
            item.type = br.type;
            item.old_protect = br.protect;
            item.new_protect = 0;
            item.old_entropy = br.entropy;
            item.old_hash = br.content_hash;
            item.summary = "Region deallocated / freed (" + fmt_size_short(br.size) + " " + type_short(br.type) + ")";
            out_diffs.push_back(item);
        }
    }
}

bool save_process_session_to_file(const ProcessSnapshotSession &session, const std::string &filepath)
{
    std::ofstream out(filepath, std::ios::binary);
    if (!out.is_open()) return false;

    out << "{\n";
    out << "  \"deadeye_session\": \"1.0\",\n";
    out << "  \"pid\": " << session.pid << ",\n";
    out << "  \"process_name\": \"" << escape_json(session.process_name) << "\",\n";
    out << "  \"timestamp\": \"" << session.timestamp_str << "\",\n";
    out << "  \"total_committed_bytes\": " << session.total_committed_bytes << ",\n";
    out << "  \"region_count\": " << session.regions.size() << ",\n";
    out << "  \"regions\": [\n";

    for (size_t i = 0; i < session.regions.size(); ++i)
    {
        const auto &r = session.regions[i];
        out << "    {\n";
        char hx[32];
        std::snprintf(hx, sizeof(hx), "0x%016llX", static_cast<unsigned long long>(r.base));
        out << "      \"base\": \"" << hx << "\",\n";
        out << "      \"size\": " << r.size << ",\n";
        out << "      \"state\": " << r.state << ",\n";
        out << "      \"type\": " << r.type << ",\n";
        out << "      \"protect\": " << r.protect << ",\n";
        out << "      \"alloc_protect\": " << r.alloc_protect << ",\n";
        std::snprintf(hx, sizeof(hx), "0x%016llX", static_cast<unsigned long long>(r.alloc_base));
        out << "      \"alloc_base\": \"" << hx << "\",\n";
        std::snprintf(hx, sizeof(hx), "0x%016llX", static_cast<unsigned long long>(r.content_hash));
        out << "      \"content_hash\": \"" << hx << "\",\n";
        out << "      \"entropy\": " << r.entropy << ",\n";
        out << "      \"has_pe\": " << (r.has_pe ? "true" : "false") << ",\n";
        out << "      \"is_unbacked\": " << (r.is_unbacked ? "true" : "false") << ",\n";
        out << "      \"is_rwx\": " << (r.is_rwx ? "true" : "false") << ",\n";
        out << "      \"is_write_then_flip\": " << (r.is_write_then_flip ? "true" : "false") << "\n";
        out << "    }" << (i + 1 < session.regions.size() ? "," : "") << "\n";
    }

    out << "  ]\n";
    out << "}\n";
    return true;
}

bool load_process_session_from_file(const std::string &filepath, ProcessSnapshotSession &session)
{
    std::ifstream in(filepath);
    if (!in.is_open()) return false;

    session = ProcessSnapshotSession{};
    ProcessRegionSnapshot cur_reg{};
    bool in_regions_list = false;
    bool in_region = false;

    std::string line;
    while (std::getline(in, line))
    {
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        std::string trimmed = line.substr(first);
        while (!trimmed.empty() && (trimmed.back() == '\r' || trimmed.back() == '\n' || trimmed.back() == ' ' || trimmed.back() == '\t'))
        {
            trimmed.pop_back();
        }

        if (line.find("\"regions\":") != std::string::npos)
        {
            in_regions_list = true;
            continue;
        }

        if (!in_regions_list)
        {
            try
            {
                if (line.find("\"pid\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "pid");
                    if (!v.empty()) session.pid = static_cast<DWORD>(std::stoul(v));
                }
                else if (line.find("\"process_name\":") != std::string::npos)
                {
                    session.process_name = extract_json_str_val(line, "process_name");
                }
                else if (line.find("\"timestamp\":") != std::string::npos)
                {
                    session.timestamp_str = extract_json_str_val(line, "timestamp");
                }
                else if (line.find("\"total_committed_bytes\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "total_committed_bytes");
                    if (!v.empty()) session.total_committed_bytes = std::stoull(v);
                }
            }
            catch (const std::exception &)
            {
                // Ignore malformed header field gracefully
            }
            continue;
        }

        if (trimmed == "{" && !in_region)
        {
            in_region = true;
            cur_reg = ProcessRegionSnapshot{};
        }
        else if ((trimmed == "}" || trimmed == "},") && in_region)
        {
            session.regions.push_back(cur_reg);
            in_region = false;
        }
        else if (trimmed == "]" || trimmed == "],")
        {
            in_regions_list = false;
        }
        else if (in_region)
        {
            try
            {
                if (line.find("\"base\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "base");
                    if (!v.empty()) cur_reg.base = std::stoull(v, nullptr, 16);
                }
                else if (line.find("\"size\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "size");
                    if (!v.empty()) cur_reg.size = std::stoull(v);
                }
                else if (line.find("\"type\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "type");
                    if (!v.empty()) cur_reg.type = static_cast<DWORD>(std::stoul(v));
                }
                else if (line.find("\"protect\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "protect");
                    if (!v.empty()) cur_reg.protect = static_cast<DWORD>(std::stoul(v));
                }
                else if (line.find("\"content_hash\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "content_hash");
                    if (!v.empty()) cur_reg.content_hash = std::stoull(v, nullptr, 16);
                }
                else if (line.find("\"entropy\":") != std::string::npos)
                {
                    std::string v = extract_json_str_val(line, "entropy");
                    if (!v.empty()) cur_reg.entropy = std::stod(v);
                }
                else if (line.find("\"has_pe\":") != std::string::npos)
                {
                    cur_reg.has_pe = (extract_json_str_val(line, "has_pe") == "true");
                }
                else if (line.find("\"is_rwx\":") != std::string::npos)
                {
                    cur_reg.is_rwx = (extract_json_str_val(line, "is_rwx") == "true");
                }
                else if (line.find("\"is_unbacked\":") != std::string::npos)
                {
                    cur_reg.is_unbacked = (extract_json_str_val(line, "is_unbacked") == "true");
                }
            }
            catch (const std::exception &)
            {
                // Skip or handle corrupt fields without crashing
            }
        }
    }
    return !session.regions.empty();
}

YaraWildcardResult auto_wildcard_bytes(const uint8_t *bytes, size_t len, uintptr_t base_addr, DWORD pid, const std::string &rule_name)
{
    (void)base_addr;
    (void)pid;
    (void)rule_name;

    YaraWildcardResult res;
    res.total_bytes = len;
    res.wildcard_count = 0;

    if (len == 0) return res;

    std::vector<uint8_t> wildcard_mask(len, 0);

    for (size_t i = 0; i < len; )
    {
        // Near CALL (E8) or Near JMP (E9)
        if ((bytes[i] == 0xE8 || bytes[i] == 0xE9) && i + 4 < len)
        {
            res.wildcards_applied.push_back("Offset +0x" + to_hex_string(i) + ": Wildcarded rel32 displacement for " +
                                            (bytes[i] == 0xE8 ? "CALL" : "JMP"));
            for (size_t k = 1; k <= 4; ++k)
            {
                wildcard_mask[i + k] = 1;
                res.wildcard_count++;
            }
            i += 5;
            continue;
        }

        // Conditional Near Jump: 0F 80..8F xx xx xx xx
        if (bytes[i] == 0x0F && i + 5 < len && (bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0x8F))
        {
            res.wildcards_applied.push_back("Offset +0x" + to_hex_string(i) + ": Wildcarded rel32 displacement for conditional Jcc");
            for (size_t k = 2; k <= 5; ++k)
            {
                wildcard_mask[i + k] = 1;
                res.wildcard_count++;
            }
            i += 6;
            continue;
        }

        // x64 REX.W + MOV reg64, imm64: 48 B8..BF (8-byte immediate relocation target)
        if (bytes[i] == 0x48 && i + 9 < len && (bytes[i + 1] >= 0xB8 && bytes[i + 1] <= 0xBF))
        {
            res.wildcards_applied.push_back("Offset +0x" + to_hex_string(i) + ": Wildcarded 64-bit immediate relocation target");
            for (size_t k = 2; k <= 9; ++k)
            {
                wildcard_mask[i + k] = 1;
                res.wildcard_count++;
            }
            i += 10;
            continue;
        }

        // x64 RIP-relative addressing: ModR/M byte where (modrm & 0xC7) == 0x05
        if (i + 1 < len)
        {
            uint8_t op = bytes[i];
            uint8_t modrm = bytes[i + 1];
            bool is_modrm_op = (op == 0x8B || op == 0x89 || op == 0x8D || op == 0x39 || op == 0x3B ||
                                op == 0x80 || op == 0x81 || op == 0x83 || op == 0xFF);
            if (is_modrm_op && (modrm & 0xC7) == 0x05 && i + 5 < len)
            {
                res.wildcards_applied.push_back("Offset +0x" + to_hex_string(i) + ": Wildcarded x64 RIP-relative disp32");
                for (size_t k = 2; k <= 5; ++k)
                {
                    wildcard_mask[i + k] = 1;
                    res.wildcard_count++;
                }
                i += 6;
                continue;
            }
        }

        // REX-prefixed RIP-relative
        if (i + 2 < len && ((bytes[i] & 0xF0) == 0x40))
        {
            uint8_t op = bytes[i + 1];
            uint8_t modrm = bytes[i + 2];
            bool is_modrm_op = (op == 0x8B || op == 0x89 || op == 0x8D || op == 0x39 || op == 0x3B ||
                                op == 0x80 || op == 0x81 || op == 0x83 || op == 0xFF);
            if (is_modrm_op && (modrm & 0xC7) == 0x05 && i + 6 < len)
            {
                res.wildcards_applied.push_back("Offset +0x" + to_hex_string(i) + ": Wildcarded x64 REX RIP-relative disp32");
                for (size_t k = 3; k <= 6; ++k)
                {
                    wildcard_mask[i + k] = 1;
                    res.wildcard_count++;
                }
                i += 7;
                continue;
            }
        }

        i++;
    }

    std::string hex_str;
    for (size_t j = 0; j < len; ++j)
    {
        if (wildcard_mask[j])
        {
            hex_str += "?? ";
        }
        else
        {
            char hx[8];
            std::snprintf(hx, sizeof(hx), "%02X ", bytes[j]);
            hex_str += hx;
        }
    }
    if (!hex_str.empty() && hex_str.back() == ' ')
        hex_str.pop_back();

    res.hex_pattern = hex_str;
    return res;
}

std::string generate_yara_rule_text(const YaraWildcardResult &wildcard_res, uintptr_t base_addr, DWORD pid, const std::string &rule_name)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    char date_buf[64];
    std::snprintf(date_buf, sizeof(date_buf), "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    char base_buf[32];
    std::snprintf(base_buf, sizeof(base_buf), "0x%016llX", static_cast<unsigned long long>(base_addr));

    double wildcard_pct = (wildcard_res.total_bytes > 0)
                              ? (static_cast<double>(wildcard_res.wildcard_count) / wildcard_res.total_bytes * 100.0)
                              : 0.0;
    char pct_buf[48];
    std::snprintf(pct_buf, sizeof(pct_buf), "%.1f%% (%zu/%zu bytes)", wildcard_pct, wildcard_res.wildcard_count, wildcard_res.total_bytes);

    std::ostringstream ss;
    ss << "rule " << (rule_name.empty() ? "deadeye_signature_01" : rule_name) << "\r\n";
    ss << "{\r\n";
    ss << "    meta:\r\n";
    ss << "        description = \"Generated by Deadeye Memory Triage Scanner\"\r\n";
    ss << "        author = \"Deadeye Security Engine\"\r\n";
    ss << "        date = \"" << date_buf << "\"\r\n";
    ss << "        target_pid = " << pid << "\r\n";
    ss << "        source_address = \"" << base_buf << "\"\r\n";
    ss << "        wildcard_ratio = \"" << pct_buf << "\"\r\n";
    ss << "    strings:\r\n";
    ss << "        $sig = { " << wildcard_res.hex_pattern << " }\r\n";
    ss << "    condition:\r\n";
    ss << "        $sig\r\n";
    ss << "}\r\n";
    return ss.str();
}

FalsePositiveReport test_rule_false_positives(const Pattern &pat, DWORD exclude_pid)
{
    FalsePositiveReport report;
    ULONGLONG start_tick = GetTickCount64();

    if (pat.bytes.empty())
    {
        report.elapsed_ms = static_cast<DWORD>(GetTickCount64() - start_tick);
        return report;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        report.elapsed_ms = static_cast<DWORD>(GetTickCount64() - start_tick);
        return report;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    DWORD my_pid = GetCurrentProcessId();
    std::vector<uint8_t> read_buf(128 * 1024);

    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            report.total_processes_checked++;
            DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == exclude_pid || pid == my_pid)
                continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProc) continue;

            report.total_processes_scanned++;

            char name_buf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, sizeof(name_buf), nullptr, nullptr);
            std::string proc_name = name_buf;

            uintptr_t addr = 0;
            MEMORY_BASIC_INFORMATION mbi;

            while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS) &&
                    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                {
                    SIZE_T to_read = std::min<SIZE_T>(mbi.RegionSize, read_buf.size());
                    SIZE_T bytes_read = 0;
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, read_buf.data(), to_read, &bytes_read) && bytes_read >= pat.bytes.size())
                    {
                        report.total_bytes_scanned += bytes_read;
                        std::vector<size_t> hits = find_all(read_buf.data(), bytes_read, pat, 50);
                        for (size_t hit : hits)
                        {
                            FalsePositiveMatch m;
                            m.pid = pid;
                            m.process_name = proc_name;
                            m.match_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + hit;
                            report.matches.push_back(m);
                            if (report.matches.size() >= 50) break;
                        }
                    }
                }
                if (report.matches.size() >= 50) break;

                uintptr_t next_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next_addr <= addr) break;
                addr = next_addr;
            }

            CloseHandle(hProc);
            if (report.matches.size() >= 50) break;

        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    report.elapsed_ms = static_cast<DWORD>(GetTickCount64() - start_tick);
    return report;
}
