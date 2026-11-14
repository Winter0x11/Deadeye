// src/core/util.hpp
// Deadeye Defensive Triage Utility & Conversion Functions
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cmath>

// Win32 error formatting
std::string format_win32_error(DWORD err);

// Address & Number Formatting
std::string fmt_addr(uintptr_t v);
std::string to_hex_string(uintptr_t value);
std::string fmt_size_short(SIZE_T sz);
bool hex_nibble(char c, uint8_t &out);

// Memory Protection & Type String Representations
std::string prot_short(DWORD protect);
std::string prot_full(DWORD protect);
std::string type_short(DWORD t);
std::string type_full(DWORD t);

// Memory Heuristic Predicates
bool is_private_rwx(DWORD type, DWORD protect);
bool is_executable_protect(DWORD protect);
bool is_unbacked_exec(DWORD type, DWORD protect);
bool has_pe_header(const uint8_t *buf, size_t len);
bool is_write_then_flip(DWORD alloc_protect, DWORD current_protect);

// Security & Privilege
bool enable_debug_privilege();
bool parse_pid_string(const std::string &arg, DWORD &out_pid);

// JSON Formatting & Extraction
std::string escape_json(const std::string &s);
std::string extract_json_str_val(const std::string &line, const std::string &key);

// Hashing & Information Entropy
uint64_t fnv1a64(const uint8_t *data, size_t len);
double calculate_shannon_entropy(const uint8_t *data, size_t len);

inline double calculate_buffer_entropy(const uint8_t *data, size_t len)
{
    return calculate_shannon_entropy(data, len);
}
