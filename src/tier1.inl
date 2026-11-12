// ============================================================================
// Deadeye Tier 1 Malware Analysis & Detection Engineering Subsystem
// - Process-Wide Memory Diff (Snapshots & Offline JSON Sessions)
// - Memory Behavior Timeline (Unpack & Sleep Obfuscation Detections)
// - Hex Selection to YARA Rule with False-Positive Validator
// ============================================================================

uint64_t fnv1a64(const uint8_t *data, size_t len)
{
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i)
    {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

double calculate_shannon_entropy(const uint8_t *data, size_t len)
{
    if (len == 0) return 0.0;
    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i)
    {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i)
    {
        if (counts[i] > 0)
        {
            double p = static_cast<double>(counts[i]) / static_cast<double>(len);
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
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

std::string extract_json_str_val(const std::string &line, const std::string &key)
{
    size_t kpos = line.find("\"" + key + "\":");
    if (kpos == std::string::npos) return "";
    size_t colon = line.find(':', kpos);
    if (colon == std::string::npos) return "";
    size_t start = line.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return "";
    size_t end = line.find_last_not_of(" \t\r\n,");
    if (end == std::string::npos || end < start) return "";
    std::string val = line.substr(start, end - start + 1);
    if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
    {
        val = val.substr(1, val.size() - 2);
    }
    return val;
}

bool load_process_session_from_file(const std::string &filepath, ProcessSnapshotSession &session)
{
    std::ifstream in(filepath);
    if (!in.is_open()) return false;

    session = ProcessSnapshotSession{};
    ProcessRegionSnapshot cur_reg{};
    bool in_region = false;

    std::string line;
    while (std::getline(in, line))
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
        else if (line.find("    {") != std::string::npos)
        {
            in_region = true;
            cur_reg = ProcessRegionSnapshot{};
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
            else if (line.find("    }") != std::string::npos)
            {
                session.regions.push_back(cur_reg);
                in_region = false;
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
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
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
        MessageBoxA(g_hwnd_main, "Please attach to a process first before capturing a baseline.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
        return;
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
    if (!g_has_baseline)
    {
        MessageBoxA(g_hwnd_main, "No baseline snapshot found. Please capture a baseline snapshot first (Diff -> Capture Baseline).", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
        return;
    }
    if (g_current_pid == 0)
    {
        MessageBoxA(g_hwnd_main, "Please attach to a process first.", "Deadeye Process Diff", MB_OK | MB_ICONWARNING);
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

            size_t b1 = rule_str.find('{');
            size_t b2 = rule_str.rfind('}');
            if (b1 == std::string::npos || b2 == std::string::npos || b2 <= b1)
            {
                SetWindowTextA(data->hEditReport, "[ERROR] Could not find hex signature enclosed in { ... } in the rule editor.");
                return 0;
            }

            std::string hex_str = rule_str.substr(b1 + 1, b2 - b1 - 1);
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
    if (g_selected_region >= g_regions.size())
    {
        MessageBoxA(hParent, "Please select a memory region or bytes in hex view first.", "Deadeye YARA Generator", MB_OK | MB_ICONWARNING);
        return;
    }

    const RegionInfo &reg = g_regions[g_selected_region];
    uintptr_t target_base = reg.base + g_view_offset;
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
