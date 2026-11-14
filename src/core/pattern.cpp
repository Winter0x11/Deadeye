// src/core/pattern.cpp
// Deadeye Defensive Triage Byte Pattern Engine
#include "core/pattern.hpp"
#include "core/util.hpp"
#include <cctype>
#include <cstring>

// Parses hex strings like "4D 5A ?? 00 03" into bytes and a match mask.
bool parse_pattern(const std::string &input, Pattern &out, std::string &err)
{
    out.bytes.clear();
    out.mask.clear();
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

// Searches buf[0..len) using SIMD-accelerated memchr anchored on the first literal byte.
std::vector<size_t> find_all(const uint8_t *buf, size_t len, const Pattern &p)
{
    std::vector<size_t> hits;
    size_t pl = p.bytes.size();
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

    uint8_t target_byte = p.bytes[first_lit];
    size_t max_start = len - pl;
    size_t i = 0;

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
        }
        ++i;
    }
    return hits;
}
