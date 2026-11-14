// ============================================================================
// Deadeye Tier 1 Malware Analysis & Detection Engineering Subsystem
// - Process-Wide Memory Diff (Snapshots & Offline JSON Sessions)
// - Memory Behavior Timeline (Unpack & Sleep Obfuscation Detections)
// - Hex Selection to YARA Rule with False-Positive Validator
// ============================================================================


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

// Extracts ASCII and UTF-16LE strings with memory/length capping and baseline comparison
void extract_all_strings_from_source(
    std::shared_ptr<MemorySource> source,
    const std::vector<RegionInfo> &regions,
    int selected_idx,
    size_t min_len)
{
    g_extracted_strings.clear();
    if (!source || regions.empty()) return;

    size_t start_r = (selected_idx >= 0 && selected_idx < static_cast<int>(regions.size())) ? static_cast<size_t>(selected_idx) : 0;
    size_t end_r = (selected_idx >= 0 && selected_idx < static_cast<int>(regions.size())) ? (start_r + 1) : regions.size();

    const size_t MAX_TOTAL_STRINGS = 20000;
    const size_t MAX_STRINGS_PER_REGION = 5000;

    std::vector<uint8_t> read_buf(64 * 1024);

    for (size_t r = start_r; r < end_r && g_extracted_strings.size() < MAX_TOTAL_STRINGS; ++r)
    {
        const auto &reg = regions[r];
        if (reg.size == 0) continue;

        size_t strings_in_reg = 0;
        SIZE_T bytes_scanned = 0;
        SIZE_T total_to_scan = std::min<SIZE_T>(reg.size, 1024 * 1024); // Cap scan to 1 MB per region

        while (bytes_scanned < total_to_scan && strings_in_reg < MAX_STRINGS_PER_REGION && g_extracted_strings.size() < MAX_TOTAL_STRINGS)
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
                        if (g_string_baselines.count(reg.base) > 0)
                        {
                            item.is_new = (g_string_baselines[reg.base].count(item.content_hash) == 0);
                        }
                        item.text = (cur_str.size() > 256) ? (cur_str.substr(0, 256) + "...") : cur_str;
                        g_extracted_strings.push_back(item);
                        strings_in_reg++;
                        if (strings_in_reg >= MAX_STRINGS_PER_REGION || g_extracted_strings.size() >= MAX_TOTAL_STRINGS)
                            break;
                    }
                    cur_str.clear();
                }
            }
            if (cur_str.size() >= min_len && strings_in_reg < MAX_STRINGS_PER_REGION && g_extracted_strings.size() < MAX_TOTAL_STRINGS)
            {
                ExtractedStringItem item;
                item.addr = reg.base + bytes_scanned + cur_start;
                item.encoding = "ASCII";
                item.length = cur_str.size();
                item.tag_hint = classify_string_tag(cur_str);
                item.content_hash = fnv1a64(reinterpret_cast<const uint8_t*>(cur_str.data()), cur_str.size());
                item.region_base = reg.base;
                if (g_string_baselines.count(reg.base) > 0)
                {
                    item.is_new = (g_string_baselines[reg.base].count(item.content_hash) == 0);
                }
                item.text = (cur_str.size() > 256) ? (cur_str.substr(0, 256) + "...") : cur_str;
                g_extracted_strings.push_back(item);
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
                        if (g_string_baselines.count(reg.base) > 0)
                        {
                            item.is_new = (g_string_baselines[reg.base].count(item.content_hash) == 0);
                        }
                        item.text = (cur_wstr.size() > 256) ? (cur_wstr.substr(0, 256) + "...") : cur_wstr;
                        g_extracted_strings.push_back(item);
                        strings_in_reg++;
                        if (strings_in_reg >= MAX_STRINGS_PER_REGION || g_extracted_strings.size() >= MAX_TOTAL_STRINGS)
                            break;
                    }
                    cur_wstr.clear();
                }
            }
            if (cur_wstr.size() >= min_len && strings_in_reg < MAX_STRINGS_PER_REGION && g_extracted_strings.size() < MAX_TOTAL_STRINGS)
            {
                ExtractedStringItem item;
                item.addr = reg.base + bytes_scanned + cur_wstart;
                item.encoding = "UTF-16";
                item.length = cur_wstr.size();
                item.tag_hint = classify_string_tag(cur_wstr);
                item.content_hash = fnv1a64(reinterpret_cast<const uint8_t*>(cur_wstr.data()), cur_wstr.size());
                item.region_base = reg.base;
                if (g_string_baselines.count(reg.base) > 0)
                {
                    item.is_new = (g_string_baselines[reg.base].count(item.content_hash) == 0);
                }
                item.text = (cur_wstr.size() > 256) ? (cur_wstr.substr(0, 256) + "...") : cur_wstr;
                g_extracted_strings.push_back(item);
                strings_in_reg++;
            }

            bytes_scanned += chunk;
        }
    }
}

// Appends sample to ring buffer (capped at 120 samples per region)
inline void add_sample_to_ring(WatchedRegionState &wreg, const RegionSampleRecord &rec)
{
    if (wreg.ring_samples.size() >= RING_BUFFER_CAP)
    {
        wreg.ring_samples.erase(wreg.ring_samples.begin());
    }
    wreg.ring_samples.push_back(rec);
    wreg.total_samples++;
}

// Forward declaration of extract_strings_from_buffer
std::vector<RevealedString> extract_strings_from_buffer(const uint8_t *data, size_t len, uintptr_t base_addr, size_t min_len);

// Evaluates behavioral detections over watched region sample history
void evaluate_watched_region_detections(std::shared_ptr<MemorySource> source, WatchedRegionState &wreg)
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
        size_t L = std::min(s1->sample_bytes.size(), s2->sample_bytes.size());
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
            if (g_string_baselines.count(wreg.key.base) > 0)
            {
                const auto &base_set = g_string_baselines[wreg.key.base];
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
void run_behavior_tracker_tick(std::shared_ptr<MemorySource> source, HWND hwnd)
{
    (void)hwnd;
    if (!source || !source->capabilities().is_live) return;
    DWORD pid = source->get_pid();
    if (pid == 0) return;

    HANDLE proc = get_or_open_target_proc(pid);
    if (!proc)
    {
        g_target_process_exited.store(true);
        return;
    }

    DWORD exit_code = 0;
    if (GetExitCodeProcess(proc, &exit_code) && exit_code != STILL_ACTIVE)
    {
        g_target_process_exited.store(true);
        return;
    }

    // Populate initial watch set if empty
    if (g_watched_regions.empty() && !g_regions.empty())
    {
        for (const auto &reg : g_regions)
        {
            bool is_exec = (reg.protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) != 0;
            bool high_ent = (reg.avg_entropy >= 7.2 || reg.max_entropy >= 7.2);
            bool priv_exec = (reg.type == MEM_PRIVATE && is_exec);

            int sev = 0;
            for (const auto &f : g_triage_report.findings)
            {
                if (f.base == reg.base) { sev = f.severity_score; break; }
            }

            if (sev >= 25 || high_ent || (g_tracker_watch_all_priv_exec.load() && priv_exec))
            {
                WatchedRegionState ws;
                ws.key.base = reg.base;
                ws.key.alloc_base = reg.alloc_base;
                ws.key.generation = g_region_generations[reg.base];
                ws.size = reg.size;
                ws.type = reg.type;
                ws.alloc_protect = reg.alloc_protect;
                ws.is_pinned = false;
                g_watched_regions.push_back(ws);
            }
        }
    }

    size_t N = g_watched_regions.size();
    if (N == 0) return;

    auto tick_start = std::chrono::steady_clock::now();
    g_tracker_total_samples++;
    bool was_partial = false;
    uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());

    size_t start_idx = g_tracker_rotating_idx % N;
    size_t sampled_in_tick = 0;

    for (size_t step = 0; step < N; ++step)
    {
        size_t idx = (start_idx + step) % N;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tick_start).count();
        if (elapsed_ms >= 50 && sampled_in_tick > 0)
        {
            was_partial = true;
            g_tracker_rotating_idx = idx;
            break;
        }

        WatchedRegionState &wreg = g_watched_regions[idx];
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
            g_region_generations[wreg.key.base]++;
            wreg.key.alloc_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            wreg.key.generation = g_region_generations[wreg.key.base];
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
            evaluate_watched_region_detections(source, wreg);
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
                    size_t cmp_len = std::min(rec.sample_bytes.size(), prev->sample_bytes.size());
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
        evaluate_watched_region_detections(source, wreg);
    }

    if (was_partial)
    {
        g_tracker_partial_samples++;
    }
    else
    {
        g_tracker_rotating_idx = (start_idx + sampled_in_tick) % N;
    }
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

std::vector<RevealedString> extract_strings_from_buffer(const uint8_t *data, size_t len, uintptr_t base_addr, size_t min_len = 4)
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

bool capture_process_snapshot_session(DWORD pid, ProcessSnapshotSession &out_session, std::string &out_err)
{
    HANDLE proc = get_or_open_target_proc(pid);
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
    out << "  \"process_name\": \"" << session.process_name << "\",\n";
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
            if (line.find("\"pid\":") != std::string::npos)
            {
                session.pid = static_cast<DWORD>(std::stoul(extract_json_str_val(line, "pid")));
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
                session.total_committed_bytes = std::stoull(extract_json_str_val(line, "total_committed_bytes"));
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
            if (line.find("\"base\":") != std::string::npos)
            {
                std::string v = extract_json_str_val(line, "base");
                cur_reg.base = std::stoull(v, nullptr, 16);
            }
            else if (line.find("\"size\":") != std::string::npos)
            {
                cur_reg.size = std::stoull(extract_json_str_val(line, "size"));
            }
            else if (line.find("\"type\":") != std::string::npos)
            {
                cur_reg.type = static_cast<DWORD>(std::stoul(extract_json_str_val(line, "type")));
            }
            else if (line.find("\"protect\":") != std::string::npos)
            {
                cur_reg.protect = static_cast<DWORD>(std::stoul(extract_json_str_val(line, "protect")));
            }
            else if (line.find("\"content_hash\":") != std::string::npos)
            {
                std::string v = extract_json_str_val(line, "content_hash");
                cur_reg.content_hash = std::stoull(v, nullptr, 16);
            }
            else if (line.find("\"entropy\":") != std::string::npos)
            {
                cur_reg.entropy = std::stod(extract_json_str_val(line, "entropy"));
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
    DWORD start_tick = GetTickCount();

    if (pat.bytes.empty())
    {
        report.elapsed_ms = GetTickCount() - start_tick;
        return report;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        report.elapsed_ms = GetTickCount() - start_tick;
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
                        std::vector<size_t> hits = find_all(read_buf.data(), bytes_read, pat);
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
    report.elapsed_ms = GetTickCount() - start_tick;
    return report;
}

void on_capture_baseline()
{
    if (g_current_pid == 0)
    {
        char pid_buf[64] = {};
        GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
        DWORD parsed_pid = 0;
        if (parse_pid_string(pid_buf, parsed_pid) && parsed_pid != 0)
        {
            g_current_pid = parsed_pid;
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Please enter a valid numeric target PID first before capturing a baseline.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    std::string err;
    set_status("Capturing full process baseline snapshot (PID " + std::to_string(g_current_pid) + ")...");
    UpdateWindow(g_lbl_status);

    if (capture_process_snapshot_session(g_current_pid, g_process_baseline, err))
    {
        g_has_baseline = true;
        char msg[160];
        std::snprintf(msg, sizeof(msg), "Baseline captured: %zu committed regions (%s) for PID %u (%s)",
                      g_process_baseline.regions.size(),
                      fmt_size_short(g_process_baseline.total_committed_bytes).c_str(),
                      static_cast<unsigned int>(g_process_baseline.pid),
                      g_process_baseline.process_name.c_str());
        set_status(msg);
        MessageBoxA(g_hwnd_main, msg, "Deadeye Process Diff", MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        set_status("[ERROR] " + err);
        MessageBoxA(g_hwnd_main, err.c_str(), "Deadeye Process Diff Error", MB_OK | MB_ICONERROR);
    }
}

void on_capture_diff()
{
    if (g_current_pid == 0)
    {
        char pid_buf[64] = {};
        GetWindowTextA(g_edit_pid, pid_buf, sizeof(pid_buf));
        DWORD parsed_pid = 0;
        if (parse_pid_string(pid_buf, parsed_pid) && parsed_pid != 0)
        {
            g_current_pid = parsed_pid;
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Please enter a valid numeric target PID first.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    if (!g_has_baseline)
    {
        on_capture_baseline();
        if (g_has_baseline)
        {
            MessageBoxA(g_hwnd_main,
                        "Baseline snapshot captured successfully!\n\n"
                        "Now run your target malware sample or trigger suspicious activity,\n"
                        "then click 'Diff Proc' again (or press Ctrl+D) to compute the diff.",
                        "Deadeye Baseline Captured", MB_OK | MB_ICONINFORMATION);
        }
        return;
    }

    std::string err;
    set_status("Capturing current process snapshot and computing diff...");
    UpdateWindow(g_lbl_status);

    if (capture_process_snapshot_session(g_current_pid, g_process_target, err))
    {
        g_has_target = true;
        compute_process_diff(g_process_baseline, g_process_target, g_process_diffs);

        // Switch to Process Diff view
        g_view_mode = ViewMode::ProcessDiff;
        SendMessageA(g_combo_view_mode, CB_SETCURSEL, 2, 0);
        populate_region_list();

        size_t new_cnt = 0, prot_cnt = 0, mod_cnt = 0, del_cnt = 0;
        for (const auto &d : g_process_diffs)
        {
            if (d.kind == ProcessDiffKind::Appeared) new_cnt++;
            else if (d.kind == ProcessDiffKind::ProtectionChg) prot_cnt++;
            else if (d.kind == ProcessDiffKind::ContentChg) mod_cnt++;
            else if (d.kind == ProcessDiffKind::Disappeared) del_cnt++;
        }

        char msg[220];
        std::snprintf(msg, sizeof(msg),
                      "Diff complete: %zu changes detected | %zu new regions, %zu protection flips, %zu modified, %zu freed",
                      g_process_diffs.size(), new_cnt, prot_cnt, mod_cnt, del_cnt);
        set_status(msg);
    }
    else
    {
        set_status("[ERROR] " + err);
        MessageBoxA(g_hwnd_main, err.c_str(), "Deadeye Process Diff Error", MB_OK | MB_ICONERROR);
    }
}

void on_save_diff_session()
{
    if (!g_has_baseline && !g_has_target)
    {
        MessageBoxA(g_hwnd_main, "No process session snapshots to save.", "Deadeye Session Export", MB_OK | MB_ICONWARNING);
        return;
    }

    const ProcessSnapshotSession &session_to_save = g_has_target ? g_process_target : g_process_baseline;

    char file_buf[MAX_PATH] = {};
    std::string def_name = "deadeye_session_" + std::to_string(session_to_save.pid) + ".json";
    std::strncpy(file_buf, def_name.c_str(), sizeof(file_buf) - 1);

    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "JSON Session Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "json";

    if (GetSaveFileNameA(&ofn))
    {
        if (save_process_session_to_file(session_to_save, ofn.lpstrFile))
        {
            set_status("Session saved successfully to " + std::string(ofn.lpstrFile));
            MessageBoxA(g_hwnd_main, "Process snapshot session exported successfully.", "Deadeye Session Export", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Failed to write session file.", "Deadeye Session Export Error", MB_OK | MB_ICONERROR);
        }
    }
}

void on_load_diff_session()
{
    char file_buf[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd_main;
    ofn.lpstrFilter = "JSON Session Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = file_buf;
    ofn.nMaxFile = sizeof(file_buf);
    ofn.Flags = OFN_FILEMUSTEXIST;
    ofn.lpstrDefExt = "json";

    if (GetOpenFileNameA(&ofn))
    {
        ProcessSnapshotSession loaded_session;
        if (load_process_session_from_file(ofn.lpstrFile, loaded_session))
        {
            if (!g_has_baseline)
            {
                g_process_baseline = loaded_session;
                g_has_baseline = true;
                set_status("Loaded baseline session: " + loaded_session.process_name + " (" + std::to_string(loaded_session.regions.size()) + " regions)");
                MessageBoxA(g_hwnd_main, ("Loaded baseline snapshot session from:\n" + std::string(ofn.lpstrFile) + "\n\nYou can now capture a live snapshot or load a second session to compare.").c_str(), "Deadeye Session Load", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                g_process_target = loaded_session;
                g_has_target = true;
                compute_process_diff(g_process_baseline, g_process_target, g_process_diffs);
                g_view_mode = ViewMode::ProcessDiff;
                SendMessageA(g_combo_view_mode, CB_SETCURSEL, 2, 0);
                populate_region_list();
                set_status("Loaded target session & computed diff: " + std::to_string(g_process_diffs.size()) + " changes identified.");
                MessageBoxA(g_hwnd_main, ("Compared loaded session with baseline.\nIdentified " + std::to_string(g_process_diffs.size()) + " differences.").c_str(), "Deadeye Session Diff", MB_OK | MB_ICONINFORMATION);
            }
        }
        else
        {
            MessageBoxA(g_hwnd_main, "Failed to parse session JSON file.", "Deadeye Session Load Error", MB_OK | MB_ICONERROR);
        }
    }
}

void evaluate_memory_behavior_heartbeat()
{
    if (g_current_pid == 0) return;
    HANDLE proc = get_or_open_target_proc(g_current_pid);
    if (!proc) return;

    DWORD now = GetTickCount();
    std::vector<uint8_t> read_buf(64 * 1024);
    bool new_detection = false;

    for (auto &reg : g_regions)
    {
        if (reg.type == MEM_IMAGE)
            continue;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(reg.base), &mbi, sizeof(mbi)) != sizeof(mbi))
            continue;

        DWORD cur_protect = mbi.Protect;
        if (reg.last_protect == 0)
        {
            reg.last_protect = reg.protect;
            reg.last_entropy = 0.0;
            reg.last_hash = 0;
        }

        if (cur_protect != reg.last_protect)
        {
            bool was_non_exec = (reg.last_protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY)) != 0;
            bool is_exec = (cur_protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

            reg.flip_count++;
            reg.protect_history.push_back(cur_protect);

            SIZE_T to_read = std::min<SIZE_T>(reg.size, read_buf.size());
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(reg.base), read_buf.data(), to_read, &bytes_read) && bytes_read > 0)
            {
                uint64_t cur_hash = fnv1a64(read_buf.data(), bytes_read);
                double cur_entropy = calculate_shannon_entropy(read_buf.data(), bytes_read);

                MemoryTransition tr;
                tr.timestamp_ms = now;
                tr.old_protect = reg.last_protect;
                tr.new_protect = cur_protect;
                tr.old_entropy = reg.last_entropy;
                tr.new_entropy = cur_entropy;
                tr.old_hash = reg.last_hash;
                tr.new_hash = cur_hash;

                // Unpack detection: non-exec -> exec, bytes mutated or entropy dropped
                if (was_non_exec && is_exec && (cur_hash != reg.last_hash || cur_entropy < reg.last_entropy - 0.4 || reg.last_hash == 0))
                {
                    tr.is_unpack = true;
                    if (!reg.behavior_unpack_detected)
                    {
                        reg.behavior_unpack_detected = true;
                        new_detection = true;
                    }

                    // Extract new strings
                    auto revealed = extract_strings_from_buffer(read_buf.data(), bytes_read, reg.base, 4);
                    for (const auto &rs : revealed)
                    {
                        bool exists = false;
                        for (const auto &prev : g_revealed_strings)
                        {
                            if (prev.addr == rs.addr && prev.text == rs.text)
                            {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            g_revealed_strings.push_back(rs);
                        }
                    }
                }

                // Sleep obfuscation detection: oscillating across ticks
                if (reg.flip_count >= 2)
                {
                    tr.is_sleep_cycle = true;
                    if (!reg.sleep_obfuscation_detected)
                    {
                        reg.sleep_obfuscation_detected = true;
                        new_detection = true;
                    }
                }

                reg.transitions.push_back(tr);
                reg.last_hash = cur_hash;
                reg.last_entropy = cur_entropy;
            }
            reg.last_protect = cur_protect;
        }
    }

    if (new_detection)
    {
        g_triage_report = run_process_triage(proc, g_current_pid, g_regions, nullptr, nullptr, nullptr);
        populate_region_list();
        set_status("[BEHAVIOR DETECTED] Unpack or sleep obfuscation transition identified during heartbeat!");
    }
}

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
            SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        SendMessageA(data->hEditRule, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);
        SendMessageA(data->hEditReport, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

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
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
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
    if (g_view_mode == ViewMode::ProcessDiff)
    {
        if (g_selected_region < g_process_diffs.size())
        {
            target_base = g_process_diffs[g_selected_region].base + g_view_offset;
        }
    }
    else
    {
        if (g_selected_region < g_regions.size())
        {
            target_base = g_regions[g_selected_region].base + g_view_offset;
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
    SendMessageA(g_edit_hex, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start), reinterpret_cast<LPARAM>(&sel_end));
    if (sel_start != sel_end)
    {
        int len = GetWindowTextLengthA(g_edit_hex);
        if (len > 0)
        {
            std::vector<char> full_text(len + 1);
            GetWindowTextA(g_edit_hex, full_text.data(), len + 1);
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
        HANDLE proc = get_or_open_target_proc(g_current_pid);
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

    std::string rule_name = "sig_mem_pid" + std::to_string(g_current_pid) + "_" + to_hex_string(target_base).substr(8);
    YaraWildcardResult wres = auto_wildcard_bytes(target_bytes.data(), target_bytes.size(), target_base, g_current_pid, rule_name);
    std::string rule_text = generate_yara_rule_text(wres, target_base, g_current_pid, rule_name);

    YaraDialogData *data = new YaraDialogData();
    data->rule_text = rule_text;
    data->base_addr = target_base;
    data->pid = g_current_pid;

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

struct StringsDialogData
{
    HWND hFilterEdit = nullptr;
    HWND hListStrings = nullptr;
    HWND hBtnCopy = nullptr;
    HWND hBtnExport = nullptr;
    HWND hBtnClose = nullptr;
};

void populate_strings_view(HWND hEdit, const std::string &filter)
{
    std::string text;
    for (const auto &s : g_revealed_strings)
    {
        if (!filter.empty() && s.text.find(filter) == std::string::npos && s.category.find(filter) == std::string::npos)
            continue;

        char abuf[32];
        std::snprintf(abuf, sizeof(abuf), "0x%016llX", static_cast<unsigned long long>(s.addr));
        text += s.category + "  " + abuf + "  " + s.text + "\r\n";
    }
    if (text.empty())
    {
        if (g_revealed_strings.empty())
            text = "(No strings revealed yet. Enable Heartbeat to monitor payload unpacking/transitions.)\r\n";
        else
            text = "(No strings match current filter.)\r\n";
    }
    SetWindowTextA(hEdit, text.c_str());
}

LRESULT CALLBACK StringsDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<StringsDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<StringsDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));
        HINSTANCE hInst = cs->hInstance;

        HWND lbl1 = CreateWindowA("STATIC", "Newly Revealed Strings (Extracted after Unpack / Protection Transitions):",
                                  WS_CHILD | WS_VISIBLE, 12, 10, 720, 18, hwnd, nullptr, hInst, nullptr);

        HWND lbl_note = CreateWindowA("STATIC", "[Note: Monitored via 1-second heartbeat polling. Sub-second transitions may be missed.]",
                                      WS_CHILD | WS_VISIBLE, 12, 30, 720, 18, hwnd, nullptr, hInst, nullptr);

        HWND lbl_flt = CreateWindowA("STATIC", "Filter:", WS_CHILD | WS_VISIBLE, 12, 54, 42, 20, hwnd, nullptr, hInst, nullptr);

        data->hFilterEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                          58, 52, 240, 24, hwnd, reinterpret_cast<HMENU>(4001), hInst, nullptr);

        data->hBtnCopy = CreateWindowA("BUTTON", "Copy All", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       310, 52, 90, 24, hwnd, reinterpret_cast<HMENU>(4002), hInst, nullptr);

        data->hBtnExport = CreateWindowA("BUTTON", "Export TXT...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         408, 52, 110, 24, hwnd, reinterpret_cast<HMENU>(4003), hInst, nullptr);

        data->hBtnClose = CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        642, 52, 90, 24, hwnd, reinterpret_cast<HMENU>(4004), hInst, nullptr);

        data->hListStrings = CreateWindowA("EDIT", "",
                                           WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
                                               ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                           12, 84, 720, 430, hwnd, reinterpret_cast<HMENU>(4005), hInst, nullptr);

        HWND ui_ctrls[] = { lbl1, lbl_note, lbl_flt, data->hFilterEdit, data->hBtnCopy, data->hBtnExport, data->hBtnClose };
        for (HWND c : ui_ctrls)
            SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);

        SendMessageA(data->hListStrings, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono_font), TRUE);

        make_button_modern(data->hBtnCopy, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnExport, ModernButtonStyle::Accent);
        make_button_modern(data->hBtnClose, ModernButtonStyle::Standard);

        populate_strings_view(data->hListStrings, "");
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
        if (id == 4001 && code == EN_CHANGE)
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hFilterEdit);
            std::vector<char> buf(len + 1);
            GetWindowTextA(data->hFilterEdit, buf.data(), len + 1);
            populate_strings_view(data->hListStrings, buf.data());
        }
        else if (id == 4002) // Copy
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hListStrings);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(data->hListStrings, buf.data(), len + 1);
                copy_text_to_clipboard(hwnd, buf.data());
                MessageBoxA(hwnd, "Revealed strings copied to clipboard.", "Deadeye Strings", MB_OK | MB_ICONINFORMATION);
            }
        }
        else if (id == 4003) // Export
        {
            if (!data) return 0;
            int len = GetWindowTextLengthA(data->hListStrings);
            if (len > 0)
            {
                std::vector<char> buf(len + 1);
                GetWindowTextA(data->hListStrings, buf.data(), len + 1);

                char file_buf[MAX_PATH] = "revealed_strings.txt";
                OPENFILENAMEA ofn = {};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
                ofn.lpstrFile = file_buf;
                ofn.nMaxFile = sizeof(file_buf);
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
                ofn.lpstrDefExt = "txt";

                if (GetSaveFileNameA(&ofn))
                {
                    std::ofstream f(ofn.lpstrFile, std::ios::binary);
                    if (f.is_open())
                    {
                        f.write(buf.data(), len);
                        MessageBoxA(hwnd, "Strings exported successfully.", "Deadeye Strings", MB_OK | MB_ICONINFORMATION);
                    }
                }
            }
        }
        else if (id == 4004) // Close
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
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

void open_revealed_strings_dialog(HWND hParent)
{
    StringsDialogData *data = new StringsDialogData();
    EnableWindow(hParent, FALSE);

    RECT parent_rc;
    GetWindowRect(hParent, &parent_rc);
    int dlg_w = 760, dlg_h = 560;
    int dlg_x = parent_rc.left + (parent_rc.right - parent_rc.left - dlg_w) / 2;
    int dlg_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - dlg_h) / 2;
    if (dlg_x < 10) dlg_x = 10;
    if (dlg_y < 10) dlg_y = 10;

    CreateWindowExA(WS_EX_DLGMODALFRAME, "DeadeyeStringsDlg",
                    "Revealed Strings - Memory Behavior Timeline",
                    WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                    dlg_x, dlg_y, dlg_w, dlg_h, hParent, nullptr, GetModuleHandleA(nullptr), data);
}

// ============================================================================
// Process Attachment Dialog (Debugger-Style Process / Window Picker)
// ============================================================================

#define ID_ATTACH_SEARCH 5001
#define ID_ATTACH_LIST 5002
#define ID_ATTACH_WINDOWS_ONLY 5003
#define ID_ATTACH_BTN_REFRESH 5004
#define ID_ATTACH_BTN_ATTACH 5005
#define ID_ATTACH_BTN_CANCEL 5006
#define ID_ATTACH_STATUS 5007

struct ProcessListEntry
{
    DWORD pid = 0;
    std::string name;
    std::string window_title;
    std::string arch;        // "x64", "x86", or "?"
    std::string path;
    bool has_window = false;
};

struct AttachDialogData
{
    HWND hEditSearch = nullptr;
    HWND hChkWindowsOnly = nullptr;
    HWND hBtnRefresh = nullptr;
    HWND hList = nullptr;
    HWND hLblStatus = nullptr;
    HWND hBtnAttach = nullptr;
    HWND hBtnCancel = nullptr;

    std::vector<ProcessListEntry> all_entries;
    std::vector<ProcessListEntry> filtered_entries;

    int sort_column = -1; // -1 means default: visible windows first, then name alphabetical
    bool sort_asc = true;

    bool confirmed = false;
    DWORD selected_pid = 0;
    std::string selected_name;
};

struct EnumWindowsAttachContext
{
    std::unordered_map<DWORD, std::string> pid_to_title;
};

static BOOL CALLBACK EnumWindowsAttachProc(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;

    if (GetWindow(hwnd, GW_OWNER) != nullptr)
        return TRUE;

    LONG_PTR ex_style = GetWindowLongPtrA(hwnd, GWL_EXSTYLE);
    if (ex_style & WS_EX_TOOLWINDOW)
        return TRUE;

    int len = GetWindowTextLengthA(hwnd);
    if (len <= 0)
        return TRUE;

    std::vector<char> title_buf(static_cast<size_t>(len) + 1);
    GetWindowTextA(hwnd, title_buf.data(), len + 1);
    std::string title = title_buf.data();

    bool non_ws = false;
    for (char c : title)
    {
        if (!std::isspace(static_cast<unsigned char>(c)))
        {
            non_ws = true;
            break;
        }
    }
    if (!non_ws)
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != 0)
    {
        auto *ctx = reinterpret_cast<EnumWindowsAttachContext*>(lParam);
        auto it = ctx->pid_to_title.find(pid);
        if (it == ctx->pid_to_title.end())
        {
            ctx->pid_to_title[pid] = title;
        }
        else if (title.length() > it->second.length())
        {
            ctx->pid_to_title[pid] = title;
        }
    }
    return TRUE;
}

static bool is_host_64bit()
{
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
}

static void sort_process_entries(AttachDialogData *data)
{
    int col = data->sort_column;
    bool asc = data->sort_asc;

    std::sort(data->all_entries.begin(), data->all_entries.end(), [col, asc](const ProcessListEntry &a, const ProcessListEntry &b) {
        if (col == 0) // Process Name
        {
            std::string na = a.name, nb = b.name;
            for (char &c : na) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char &c : nb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (na != nb) return asc ? (na < nb) : (na > nb);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }
        else if (col == 1) // PID
        {
            if (a.pid != b.pid) return asc ? (a.pid < b.pid) : (a.pid > b.pid);
            return false;
        }
        else if (col == 2) // Window Title
        {
            std::string ta = a.window_title, tb = b.window_title;
            for (char &c : ta) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char &c : tb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (ta != tb) return asc ? (ta < tb) : (ta > tb);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }
        else if (col == 3) // Arch
        {
            if (a.arch != b.arch) return asc ? (a.arch < b.arch) : (a.arch > b.arch);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }
        else if (col == 4) // Path
        {
            std::string pa = a.path, pb = b.path;
            for (char &c : pa) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char &c : pb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (pa != pb) return asc ? (pa < pb) : (pa > pb);
            return asc ? (a.pid < b.pid) : (a.pid > b.pid);
        }

        // Default sort: entries with visible windows first, then name alphabetical
        if (a.has_window != b.has_window)
            return a.has_window > b.has_window;
        std::string na = a.name, nb = b.name;
        for (char &c : na) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (char &c : nb) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (na != nb) return na < nb;
        return a.pid < b.pid;
    });
}

static void refresh_process_list(AttachDialogData *data)
{
    data->all_entries.clear();

    EnumWindowsAttachContext wctx;
    EnumWindows(EnumWindowsAttachProc, reinterpret_cast<LPARAM>(&wctx));

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe))
        {
            bool sys_64 = is_host_64bit();
            do
            {
                DWORD pid = pe.th32ProcessID;
                if (pid == 0) // Skip System Idle Process
                    continue;

                ProcessListEntry entry;
                entry.pid = pid;

                char name_buf[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, sizeof(name_buf), nullptr, nullptr);
                entry.name = name_buf;

                auto wit = wctx.pid_to_title.find(pid);
                if (wit != wctx.pid_to_title.end() && !wit->second.empty())
                {
                    entry.window_title = wit->second;
                    entry.has_window = true;
                }

                entry.arch = "?";
                entry.path = "";

                // Query architecture and image path strictly read-only
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!hProc)
                {
                    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                }

                if (hProc)
                {
                    BOOL is_wow64 = FALSE;
                    if (IsWow64Process(hProc, &is_wow64))
                    {
                        if (sys_64)
                            entry.arch = is_wow64 ? "x86" : "x64";
                        else
                            entry.arch = "x86";
                    }

                    char path_buf[MAX_PATH * 2] = {};
                    DWORD path_len = static_cast<DWORD>(sizeof(path_buf));
                    if (QueryFullProcessImageNameA(hProc, 0, path_buf, &path_len) && path_len > 0)
                    {
                        entry.path = path_buf;
                    }
                    CloseHandle(hProc);
                }

                data->all_entries.push_back(std::move(entry));
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    sort_process_entries(data);
}

static void apply_process_filter(AttachDialogData *data)
{
    char filter_buf[256] = {};
    if (data->hEditSearch)
        GetWindowTextA(data->hEditSearch, filter_buf, sizeof(filter_buf));
    std::string query = filter_buf;
    for (char &c : query) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    while (!query.empty() && std::isspace(static_cast<unsigned char>(query.front()))) query.erase(query.begin());
    while (!query.empty() && std::isspace(static_cast<unsigned char>(query.back()))) query.pop_back();

    bool windows_only = false;
    if (data->hChkWindowsOnly)
        windows_only = (SendMessageA(data->hChkWindowsOnly, BM_GETCHECK, 0, 0) == BST_CHECKED);

    data->filtered_entries.clear();
    for (const auto &e : data->all_entries)
    {
        if (windows_only && !e.has_window)
            continue;

        if (query.empty())
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match name
        std::string name_lower = e.name;
        for (char &c : name_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (name_lower.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match window title
        std::string title_lower = e.window_title;
        for (char &c : title_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (title_lower.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match decimal PID
        std::string pid_str = std::to_string(e.pid);
        if (pid_str.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }

        // Match hex PID
        char hex_buf[32];
        snprintf(hex_buf, sizeof(hex_buf), "%lx", static_cast<unsigned long>(e.pid));
        std::string hex_str = hex_buf;
        if (hex_str.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }
        std::string hex_0x = "0x" + hex_str;
        if (hex_0x.find(query) != std::string::npos)
        {
            data->filtered_entries.push_back(e);
            continue;
        }
    }
}

static void populate_attach_listview(AttachDialogData *data)
{
    apply_process_filter(data);

    HWND hList = data->hList;
    SendMessageA(hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hList);

    for (int i = 0; i < static_cast<int>(data->filtered_entries.size()); ++i)
    {
        const auto &e = data->filtered_entries[static_cast<size_t>(i)];
        LVITEMA item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = i;
        item.iSubItem = 0;
        item.pszText = const_cast<char*>(e.name.c_str());
        item.lParam = static_cast<LPARAM>(e.pid);
        ListView_InsertItem(hList, &item);

        char pid_str[64];
        snprintf(pid_str, sizeof(pid_str), "%lu (0x%04lX)", static_cast<unsigned long>(e.pid), static_cast<unsigned long>(e.pid));
        ListView_SetItemText(hList, i, 1, pid_str);

        ListView_SetItemText(hList, i, 2, const_cast<char*>(e.window_title.c_str()));
        ListView_SetItemText(hList, i, 3, const_cast<char*>(e.arch.c_str()));
        ListView_SetItemText(hList, i, 4, const_cast<char*>(e.path.c_str()));
    }

    SendMessageA(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, nullptr, TRUE);

    if (!data->filtered_entries.empty())
    {
        ListView_SetItemState(hList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    size_t win_count = 0;
    for (const auto &e : data->all_entries)
    {
        if (e.has_window) win_count++;
    }
    std::string status_str = "Showing " + std::to_string(data->filtered_entries.size()) +
                             " of " + std::to_string(data->all_entries.size()) +
                             " processes (" + std::to_string(win_count) + " with windows)";
    if (data->hLblStatus)
    {
        SetWindowTextA(data->hLblStatus, status_str.c_str());
    }
}

static void on_attach_confirm(HWND hwnd, AttachDialogData *data)
{
    int sel = ListView_GetNextItem(data->hList, -1, LVNI_SELECTED);
    if (sel < 0 && !data->filtered_entries.empty())
    {
        sel = 0;
    }
    if (sel < 0 || sel >= static_cast<int>(data->filtered_entries.size()))
    {
        MessageBoxA(hwnd, "Please select a target process from the list.", "Deadeye Attach", MB_OK | MB_ICONINFORMATION);
        return;
    }

    data->selected_pid = data->filtered_entries[static_cast<size_t>(sel)].pid;
    data->selected_name = data->filtered_entries[static_cast<size_t>(sel)].name;
    data->confirmed = true;

    DestroyWindow(hwnd);
}

LRESULT CALLBACK AttachDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    auto *data = reinterpret_cast<AttachDialogData*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTA *cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        data = reinterpret_cast<AttachDialogData*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));

        HINSTANCE hInst = cs->hInstance;

        HWND lbl_search = CreateWindowA("STATIC", "Search:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                        12, 14, 50, 20, hwnd, nullptr, hInst, nullptr);

        data->hEditSearch = CreateWindowA("EDIT", "",
                                          WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                          68, 12, 240, 24, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_SEARCH), hInst, nullptr);

        data->hChkWindowsOnly = CreateWindowA("BUTTON", "Processes with visible windows only",
                                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                              320, 12, 250, 24, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_WINDOWS_ONLY), hInst, nullptr);

        data->hBtnRefresh = CreateWindowA("BUTTON", "Refresh",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          760, 12, 80, 24, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_BTN_REFRESH), hInst, nullptr);

        data->hList = CreateWindowExA(
            0, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            12, 44, 830, 460, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_LIST), hInst, nullptr);

        SendMessageA(data->hList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNA col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        col.pszText = const_cast<char*>("Process Name");
        col.cx = 170;
        col.iSubItem = 0;
        ListView_InsertColumn(data->hList, 0, &col);

        col.pszText = const_cast<char*>("PID");
        col.cx = 105;
        col.iSubItem = 1;
        ListView_InsertColumn(data->hList, 1, &col);

        col.pszText = const_cast<char*>("Window Title");
        col.cx = 240;
        col.iSubItem = 2;
        ListView_InsertColumn(data->hList, 2, &col);

        col.pszText = const_cast<char*>("Arch");
        col.cx = 60;
        col.iSubItem = 3;
        ListView_InsertColumn(data->hList, 3, &col);

        col.pszText = const_cast<char*>("Executable Path");
        col.cx = 240;
        col.iSubItem = 4;
        ListView_InsertColumn(data->hList, 4, &col);

        data->hLblStatus = CreateWindowA("STATIC", "Loading processes...",
                                         WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                         12, 516, 620, 22, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_STATUS), hInst, nullptr);

        data->hBtnAttach = CreateWindowA("BUTTON", "Attach",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                         660, 514, 85, 26, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_BTN_ATTACH), hInst, nullptr);

        data->hBtnCancel = CreateWindowA("BUTTON", "Cancel",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                         755, 514, 85, 26, hwnd, reinterpret_cast<HMENU>(ID_ATTACH_BTN_CANCEL), hInst, nullptr);

        HWND ui_ctrls[] = { lbl_search, data->hEditSearch, data->hChkWindowsOnly, data->hBtnRefresh,
                            data->hLblStatus, data->hBtnAttach, data->hBtnCancel };
        for (HWND c : ui_ctrls)
        {
            if (c) SendMessageA(c, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }
        if (data->hList)
        {
            SendMessageA(data->hList, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        }

        make_button_modern(data->hBtnAttach, ModernButtonStyle::Primary);
        make_button_modern(data->hBtnCancel, ModernButtonStyle::Standard);
        make_button_modern(data->hBtnRefresh, ModernButtonStyle::Standard);

        const ThemeColors &tc = get_current_theme();
        if (g_theme == AppTheme::Dark)
        {
            ListView_SetBkColor(data->hList, tc.bg_control);
            ListView_SetTextBkColor(data->hList, tc.bg_control);
            ListView_SetTextColor(data->hList, tc.text_normal);
        }
        else
        {
            ListView_SetBkColor(data->hList, RGB(255, 255, 255));
            ListView_SetTextBkColor(data->hList, RGB(255, 255, 255));
            ListView_SetTextColor(data->hList, RGB(20, 20, 20));
        }

        refresh_process_list(data);
        populate_attach_listview(data);

        SetFocus(data->hEditSearch);
        return 0;
    }

    case WM_SIZE:
    {
        if (data && data->hList)
        {
            int cw = LOWORD(lp);
            int ch = HIWORD(lp);
            if (cw >= 400 && ch >= 250)
            {
                int search_w = cw - 12 - 58 - 250 - 90 - 24;
                if (search_w < 160) search_w = 160;
                MoveWindow(data->hEditSearch, 68, 12, search_w, 24, TRUE);
                MoveWindow(data->hChkWindowsOnly, 68 + search_w + 12, 12, 240, 24, TRUE);
                MoveWindow(data->hBtnRefresh, cw - 12 - 80, 12, 80, 24, TRUE);

                int list_y = 44;
                int list_h = ch - list_y - 44;
                if (list_h < 100) list_h = 100;
                MoveWindow(data->hList, 12, list_y, cw - 24, list_h, TRUE);

                int btm_y = ch - 34;
                MoveWindow(data->hLblStatus, 12, btm_y + 3, cw - 24 - 190, 22, TRUE);
                MoveWindow(data->hBtnAttach, cw - 12 - 180, btm_y, 85, 26, TRUE);
                MoveWindow(data->hBtnCancel, cw - 12 - 85, btm_y, 85, 26, TRUE);
            }
        }
        return 0;
    }

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO *mmi = reinterpret_cast<MINMAXINFO*>(lp);
        mmi->ptMinTrackSize.x = 680;
        mmi->ptMinTrackSize.y = 400;
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
        if (id == ID_ATTACH_SEARCH && code == EN_CHANGE)
        {
            if (data) populate_attach_listview(data);
        }
        else if (id == ID_ATTACH_WINDOWS_ONLY)
        {
            if (data) populate_attach_listview(data);
        }
        else if (id == ID_ATTACH_BTN_REFRESH)
        {
            if (data)
            {
                refresh_process_list(data);
                populate_attach_listview(data);
            }
        }
        else if (id == ID_ATTACH_BTN_ATTACH || id == IDOK)
        {
            if (data) on_attach_confirm(hwnd, data);
        }
        else if (id == ID_ATTACH_BTN_CANCEL || id == IDCANCEL)
        {
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR *nm = reinterpret_cast<NMHDR*>(lp);
        if (nm && nm->idFrom == ID_ATTACH_LIST && data)
        {
            if (nm->code == NM_DBLCLK)
            {
                on_attach_confirm(hwnd, data);
                return 0;
            }
            else if (nm->code == LVN_COLUMNCLICK)
            {
                NMLISTVIEW *nmlv = reinterpret_cast<NMLISTVIEW*>(lp);
                int col = nmlv->iSubItem;
                if (data->sort_column == col)
                {
                    data->sort_asc = !data->sort_asc;
                }
                else
                {
                    data->sort_column = col;
                    data->sort_asc = true;
                }
                sort_process_entries(data);
                populate_attach_listview(data);
                return 0;
            }
        }
        break;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        const ThemeColors &tc = get_current_theme();
        SetTextColor(hdc, tc.text_normal);
        SetBkColor(hdc, tc.bg_control);
        return reinterpret_cast<INT_PTR>(g_br_control);
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_br_window);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

void open_attach_process_dialog(HWND hParent)
{
    AttachDialogData state;

    RECT parent_rc = {};
    GetWindowRect(hParent, &parent_rc);
    int dlg_w = 860, dlg_h = 560;
    int dlg_x = parent_rc.left + (parent_rc.right - parent_rc.left - dlg_w) / 2;
    int dlg_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - dlg_h) / 2;
    if (dlg_x < 10) dlg_x = 10;
    if (dlg_y < 10) dlg_y = 10;

    HWND hwnd_dlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME,
        "DeadeyeAttachDlg",
        "Attach to Process - Deadeye",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_VISIBLE,
        dlg_x, dlg_y, dlg_w, dlg_h,
        hParent, nullptr, GetModuleHandleA(nullptr), &state);

    if (hwnd_dlg == nullptr)
        return;

    EnableWindow(hParent, FALSE);

    MSG msg;
    while (IsWindow(hwnd_dlg) && GetMessageA(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_KEYDOWN)
        {
            if (msg.wParam == VK_ESCAPE)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, IDCANCEL, 0);
                continue;
            }
            if (msg.wParam == VK_RETURN)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, IDOK, 0);
                continue;
            }
            if (msg.wParam == VK_F5)
            {
                SendMessageA(hwnd_dlg, WM_COMMAND, ID_ATTACH_BTN_REFRESH, 0);
                continue;
            }
            if (msg.wParam == VK_DOWN && GetFocus() == state.hEditSearch)
            {
                SetFocus(state.hList);
                continue;
            }
        }
        if (!IsDialogMessageA(hwnd_dlg, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);

    if (state.confirmed && state.selected_pid != 0)
    {
        std::string pid_str = std::to_string(state.selected_pid);
        if (g_edit_pid != nullptr)
        {
            SetWindowTextA(g_edit_pid, pid_str.c_str());
        }

        std::string msg_text = "Attaching to " + state.selected_name + " (PID " + pid_str + ")...";
        set_status(msg_text);

        PostMessageA(hParent, WM_COMMAND, ID_BTN_TRIAGE, 0);
    }
}
