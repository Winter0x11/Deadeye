// src/core/pattern.cpp
// Deadeye Defensive Triage Byte Pattern Engine
#include "core/pattern.hpp"
#include "core/util.hpp"
#include "core/memsource.hpp"
#include "core/snapshot.hpp"

#include <cctype>
#include <cstring>
#include <algorithm>
#include <sstream>

// Parses hex strings like "4D 5A ?? 00 03" into bytes and a match mask.
bool parse_pattern(const std::string &input, Pattern &out, std::string &err)
{
    out.bytes.clear();
    out.mask.clear();
    out.type = PatternType::HexWildcard;
    out.is_case_insensitive = false;
    size_t i = 0;

    while (i < input.size())
    {
        while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i])))
            ++i;
        if (i >= input.size())
            break;

        size_t start = i;
        while (i < input.size() && !std::isspace(static_cast<unsigned char>(input[i])))
            ++i;
        std::string tok = input.substr(start, i - start);

        if (tok == "?")
            tok = "??";

        if (tok.size() % 2 != 0)
        {
            err = "Odd-length token '" + tok + "' in pattern.";
            return false;
        }

        for (size_t k = 0; k < tok.size(); k += 2)
        {
            if (tok[k] == '?' && tok[k + 1] == '?')
            {
                out.bytes.push_back(0);
                out.mask.push_back(0);
            }
            else
            {
                uint8_t hi = 0;
                uint8_t lo = 0;
                if (!hex_nibble(tok[k], hi) || !hex_nibble(tok[k + 1], lo))
                {
                    err = "Invalid hex byte '" + tok.substr(k, 2) + "' in token '" + tok + "'.";
                    return false;
                }
                out.bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
                out.mask.push_back(1);
            }
        }
    }

    if (out.bytes.empty())
    {
        err = "Pattern is empty.";
        return false;
    }

    bool has_literal = false;
    for (size_t k = 0; k < out.mask.size(); ++k)
    {
        if (out.mask[k] != 0)
        {
            has_literal = true;
            break;
        }
    }
    if (!has_literal)
    {
        err = "Pattern cannot consist only of wildcards (must contain at least one literal hex byte).";
        return false;
    }
    return true;
}

bool parse_hex_pattern(const std::string &input, Pattern &out, std::string &err)
{
    return parse_pattern(input, out, err);
}

bool parse_ascii_pattern(const std::string &input, bool match_case, Pattern &out, std::string &err)
{
    out.bytes.clear();
    out.mask.clear();
    out.type = PatternType::AsciiString;
    out.is_case_insensitive = !match_case;

    if (input.empty())
    {
        err = "Search string is empty.";
        return false;
    }

    for (char c : input)
    {
        out.bytes.push_back(static_cast<uint8_t>(c));
        out.mask.push_back(1);
    }
    return true;
}

bool parse_utf16le_pattern(const std::string &input, bool match_case, Pattern &out, std::string &err)
{
    out.bytes.clear();
    out.mask.clear();
    out.type = PatternType::Utf16String;
    out.is_case_insensitive = !match_case;

    if (input.empty())
    {
        err = "Search string is empty.";
        return false;
    }

    for (char c : input)
    {
        out.bytes.push_back(static_cast<uint8_t>(c));
        out.mask.push_back(1);
        out.bytes.push_back(0);
        out.mask.push_back(1);
    }
    return true;
}

static inline bool match_char_case_insensitive(uint8_t a, uint8_t b)
{
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

// Searches buf[0..len) using accelerated matching.
std::vector<size_t> find_all(const uint8_t *buf, size_t len, const Pattern &p, size_t max_hits)
{
    std::vector<size_t> hits;
    const size_t pl = p.bytes.size();
    if (buf == nullptr || pl == 0 || len < pl)
    {
        return hits;
    }

    size_t first_lit = 0;
    bool has_lit = false;
    for (size_t k = 0; k < pl; ++k)
    {
        if (p.mask[k] != 0)
        {
            first_lit = k;
            has_lit = true;
            break;
        }
    }

    if (!has_lit)
    {
        return hits;
    }

    const size_t max_start = len - pl;
    size_t i = 0;

    if (!p.is_case_insensitive)
    {
        const uint8_t target_byte = p.bytes[first_lit];
        while (i <= max_start)
        {
            const void *found = std::memchr(buf + i + first_lit, target_byte, (max_start - i) + 1);
            if (found == nullptr)
            {
                break;
            }

            i = static_cast<size_t>((static_cast<const uint8_t *>(found) - buf) - first_lit);

            bool ok = true;
            for (size_t j = 0; j < pl; ++j)
            {
                if (p.mask[j] != 0 && buf[i + j] != p.bytes[j])
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
            {
                hits.push_back(i);
                if (max_hits > 0 && hits.size() >= max_hits)
                {
                    break;
                }
            }
            ++i;
        }
    }
    else
    {
        const uint8_t lo = static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(p.bytes[first_lit])));
        const uint8_t hi = static_cast<uint8_t>(std::toupper(static_cast<unsigned char>(p.bytes[first_lit])));
        const bool is_alpha = (lo != hi);

        while (i <= max_start)
        {
            uint8_t b = buf[i + first_lit];
            if (is_alpha)
            {
                if (b != lo && b != hi)
                {
                    ++i;
                    continue;
                }
            }
            else
            {
                if (b != lo)
                {
                    const void *found = std::memchr(buf + i + first_lit, lo, (max_start - i) + 1);
                    if (found == nullptr) break;
                    i = static_cast<size_t>((static_cast<const uint8_t *>(found) - buf) - first_lit);
                }
            }

            bool ok = true;
            if (p.type == PatternType::Utf16String)
            {
                for (size_t j = 0; j < pl; ++j)
                {
                    if (p.mask[j] != 0)
                    {
                        if ((j % 2) == 0)
                        {
                            if (!match_char_case_insensitive(buf[i + j], p.bytes[j]))
                            {
                                ok = false;
                                break;
                            }
                        }
                        else
                        {
                            if (buf[i + j] != p.bytes[j])
                            {
                                ok = false;
                                break;
                            }
                        }
                    }
                }
            }
            else
            {
                for (size_t j = 0; j < pl; ++j)
                {
                    if (p.mask[j] != 0)
                    {
                        if (!match_char_case_insensitive(buf[i + j], p.bytes[j]))
                        {
                            ok = false;
                            break;
                        }
                    }
                }
            }

            if (ok)
            {
                hits.push_back(i);
                if (max_hits > 0 && hits.size() >= max_hits)
                {
                    break;
                }
            }
            ++i;
        }
    }

    return hits;
}

static void build_previews(const uint8_t *data, size_t data_len, size_t hit_offset, std::string &out_hex, std::string &out_ascii)
{
    size_t preview_len = std::min<size_t>(16, data_len - hit_offset);
    char hx[4];
    out_hex.clear();
    out_ascii.clear();
    for (size_t b = 0; b < preview_len; ++b)
    {
        uint8_t val = data[hit_offset + b];
        std::snprintf(hx, sizeof(hx), "%02X ", val);
        out_hex += hx;
        out_ascii += (val >= 0x20 && val < 0x7F) ? static_cast<char>(val) : '.';
    }
    if (!out_hex.empty() && out_hex.back() == ' ')
    {
        out_hex.pop_back();
    }
}

std::vector<PatternMatchResult> search_memory_pattern(
    std::shared_ptr<MemorySource> source,
    const std::vector<RegionInfo> &regions,
    const SearchOptions &options,
    std::atomic<bool> *abort_flag,
    SearchProgressCallback progress_cb)
{
    std::vector<PatternMatchResult> results;
    if (!source || regions.empty() || options.pattern.bytes.empty())
    {
        return results;
    }

    const size_t pat_len = options.pattern.bytes.size();
    const size_t overlap = (pat_len > 1) ? (pat_len - 1) : 0;
    const SIZE_T chunk_size = 1024 * 1024; // 1 MB chunk

    std::vector<size_t> target_reg_indices;
    SIZE_T total_scope_bytes = 0;

    for (size_t i = 0; i < regions.size(); ++i)
    {
        const auto &reg = regions[i];
        if (options.scope == SearchScope::SelectedRegion)
        {
            if (i != options.selected_region_idx) continue;
        }
        else if (options.scope == SearchScope::AddressRange)
        {
            uintptr_t reg_end = reg.base + reg.size;
            if (reg_end <= options.range_start || reg.base >= options.range_end)
            {
                continue;
            }
        }
        else // AllReadable
        {
            DWORD p = reg.protect & 0xFF;
            if (p == PAGE_NOACCESS || p == 0) continue;
        }

        target_reg_indices.push_back(i);
        total_scope_bytes += reg.size;
    }

    SIZE_T bytes_scanned = 0;
    std::vector<uint8_t> chunk_buf(chunk_size);

    for (size_t reg_idx : target_reg_indices)
    {
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
        {
            break;
        }

        const auto &reg = regions[reg_idx];
        SIZE_T offset = 0;
        SIZE_T prev_overlap = 0;

        while (offset < reg.size)
        {
            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
            {
                break;
            }

            SIZE_T to_read = std::min<SIZE_T>(chunk_size, reg.size - offset);
            SIZE_T bytes_read = source->read(reg.base + offset, to_read, chunk_buf.data());
            if (bytes_read == 0)
            {
                offset += std::min<SIZE_T>(4096, reg.size - offset);
                prev_overlap = 0;
                continue;
            }

            std::vector<size_t> chunk_hits = find_all(chunk_buf.data(), bytes_read, options.pattern,
                                                      (options.max_results > results.size()) ? (options.max_results - results.size()) : 1);

            for (size_t h : chunk_hits)
            {
                if (h < prev_overlap)
                {
                    continue;
                }

                uintptr_t match_addr = reg.base + offset + h;

                if (options.scope == SearchScope::AddressRange)
                {
                    if (match_addr < options.range_start || match_addr >= options.range_end)
                    {
                        continue;
                    }
                }

                PatternMatchResult res;
                res.match_address = match_addr;
                res.region_base = reg.base;
                res.region_size = reg.size;
                res.protect = reg.protect;
                res.type = reg.type;
                build_previews(chunk_buf.data(), bytes_read, h, res.preview_hex, res.preview_ascii);

                results.push_back(std::move(res));
                if (results.size() >= options.max_results)
                {
                    break;
                }
            }

            if (results.size() >= options.max_results)
            {
                break;
            }

            if (offset + to_read >= reg.size)
            {
                bytes_scanned += (bytes_read > prev_overlap) ? (bytes_read - prev_overlap) : 0;
                break;
            }

            if (bytes_read <= overlap)
            {
                offset += to_read;
                bytes_scanned += to_read;
                prev_overlap = 0;
            }
            else
            {
                SIZE_T step = bytes_read - overlap;
                offset += step;
                bytes_scanned += step;
                prev_overlap = overlap;
            }

            if (progress_cb != nullptr)
            {
                progress_cb(bytes_scanned, total_scope_bytes, results.size());
            }
        }

        if (results.size() >= options.max_results)
        {
            break;
        }
    }

    if (progress_cb != nullptr)
    {
        progress_cb(bytes_scanned, total_scope_bytes, results.size());
    }

    return results;
}

std::vector<PatternMatchResult> search_snapshot_pattern(
    const core::ProcessSnapshot &snapshot,
    const SearchOptions &options,
    std::atomic<bool> *abort_flag,
    SearchProgressCallback progress_cb)
{
    std::vector<PatternMatchResult> results;
    if (snapshot.regions.empty() || options.pattern.bytes.empty())
    {
        return results;
    }

    SIZE_T total_bytes = 0;
    for (const auto &reg : snapshot.regions)
    {
        total_bytes += reg.data.size();
    }

    SIZE_T scanned_bytes = 0;

    for (const auto &reg : snapshot.regions)
    {
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
        {
            break;
        }

        if (reg.data.empty())
        {
            continue;
        }

        if (options.scope == SearchScope::AddressRange)
        {
            uintptr_t reg_end = reg.base_address + reg.region_size;
            if (reg_end <= options.range_start || reg.base_address >= options.range_end)
            {
                scanned_bytes += reg.data.size();
                continue;
            }
        }

        std::vector<size_t> hits = find_all(reg.data.data(), reg.data.size(), options.pattern,
                                            (options.max_results > results.size()) ? (options.max_results - results.size()) : 1);

        for (size_t h : hits)
        {
            uintptr_t match_addr = reg.base_address + h;
            if (options.scope == SearchScope::AddressRange)
            {
                if (match_addr < options.range_start || match_addr >= options.range_end)
                {
                    continue;
                }
            }

            PatternMatchResult res;
            res.match_address = match_addr;
            res.region_base = reg.base_address;
            res.region_size = reg.region_size;
            res.protect = reg.protect;
            res.type = reg.type;
            build_previews(reg.data.data(), reg.data.size(), h, res.preview_hex, res.preview_ascii);

            results.push_back(std::move(res));
            if (results.size() >= options.max_results)
            {
                break;
            }
        }

        scanned_bytes += reg.data.size();
        if (progress_cb != nullptr)
        {
            progress_cb(scanned_bytes, total_bytes, results.size());
        }

        if (results.size() >= options.max_results)
        {
            break;
        }
    }

    return results;
}
