// src/core/pattern.hpp
// Deadeye Defensive Triage Byte Pattern Engine
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

inline constexpr size_t MAX_HITS_PER_REGION = 10000;

// Compiled byte pattern: mask[i] == 1 means exact byte match, 0 means wildcard (??).
struct Pattern
{
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

// Parses hex strings like "4D 5A ?? 00 03" into bytes and a match mask.
bool parse_pattern(const std::string &input, Pattern &out, std::string &err);

// Searches buf[0..len) using SIMD-accelerated memchr anchored on the first literal byte.
// If max_hits > 0, stops searching once max_hits matches are accumulated.
std::vector<size_t> find_all(const uint8_t *buf, size_t len, const Pattern &p, size_t max_hits = 0);
