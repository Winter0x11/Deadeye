// tests/test_pattern.cpp
// Unit tests for Deadeye Advanced Pattern Search Engine

#include "core/pattern.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

void test_hex_wildcard_patterns()
{
    std::cout << "[*] Testing hex wildcard patterns..." << std::endl;
    Pattern pat;
    std::string err;

    // Valid wildcard pattern
    assert(parse_hex_pattern("48 8B ?? ?? 48 85 C0", pat, err));
    assert(pat.bytes.size() == 7);
    assert(pat.mask.size() == 7);
    assert(pat.mask[0] == 1 && pat.mask[1] == 1 && pat.mask[2] == 0 && pat.mask[3] == 0);
    assert(pat.mask[4] == 1 && pat.mask[5] == 1 && pat.mask[6] == 1);

    // Invalid hex
    Pattern bad_pat;
    assert(!parse_hex_pattern("48 8B ZZ", bad_pat, err));
    assert(!err.empty());

    // All wildcards
    assert(!parse_hex_pattern("?? ?? ??", bad_pat, err));

    // Match in buffer
    std::vector<uint8_t> buf = {
        0x90, 0x90, 0x48, 0x8B, 0x05, 0x12, 0x48, 0x85, 0xC0, 0xCC,
        0x48, 0x8B, 0xAA, 0xBB, 0x48, 0x85, 0xC0, 0x90
    };

    auto hits = find_all(buf.data(), buf.size(), pat);
    assert(hits.size() == 2);
    assert(hits[0] == 2);
    assert(hits[1] == 10);

    // Test max_hits capping
    auto capped = find_all(buf.data(), buf.size(), pat, 1);
    assert(capped.size() == 1);
    assert(capped[0] == 2);

    std::cout << "  [+] Hex wildcards parsing and SIMD matching passed." << std::endl;
}

void test_ascii_string_patterns()
{
    std::cout << "[*] Testing ASCII string patterns (case sensitive & insensitive)..." << std::endl;
    Pattern pat_ci;
    std::string err;

    // Case-insensitive ASCII search for "Secret"
    assert(parse_ascii_pattern("Secret", false, pat_ci, err));
    assert(pat_ci.is_case_insensitive);
    assert(pat_ci.bytes.size() == 6);

    std::string text = "No match here. secret found! Also SECRET and SeCrEt here.";
    const uint8_t *buf = reinterpret_cast<const uint8_t*>(text.data());
    size_t len = text.size();

    auto hits_ci = find_all(buf, len, pat_ci);
    assert(hits_ci.size() == 3);
    assert(hits_ci[0] == 15); // "secret"
    assert(hits_ci[1] == 34); // "SECRET"
    assert(hits_ci[2] == 45); // "SeCrEt"

    // Case-sensitive ASCII search for "SECRET"
    Pattern pat_cs;
    assert(parse_ascii_pattern("SECRET", true, pat_cs, err));
    assert(!pat_cs.is_case_insensitive);

    auto hits_cs = find_all(buf, len, pat_cs);
    assert(hits_cs.size() == 1);
    assert(hits_cs[0] == 34);

    std::cout << "  [+] ASCII string case-sensitive and case-insensitive matching passed." << std::endl;
}

void test_utf16le_string_patterns()
{
    std::cout << "[*] Testing UTF-16LE string patterns..." << std::endl;
    Pattern pat_utf16;
    std::string err;

    // Case-insensitive UTF-16LE search for "Admin"
    assert(parse_utf16le_pattern("Admin", false, pat_utf16, err));
    assert(pat_utf16.bytes.size() == 10); // 5 chars * 2 bytes

    // Construct buffer with UTF-16LE strings: "ADMIN" and "admin"
    std::vector<uint8_t> buf;
    // Prefix padding
    buf.push_back(0x00);
    buf.push_back(0x00);

    // "ADMIN" in UTF-16LE
    std::string s1 = "ADMIN";
    for (char c : s1) { buf.push_back(static_cast<uint8_t>(c)); buf.push_back(0x00); }

    // Middle padding
    buf.push_back(0xAA);
    buf.push_back(0xBB);

    // "admin" in UTF-16LE
    std::string s2 = "admin";
    for (char c : s2) { buf.push_back(static_cast<uint8_t>(c)); buf.push_back(0x00); }

    auto hits = find_all(buf.data(), buf.size(), pat_utf16);
    assert(hits.size() == 2);
    assert(hits[0] == 2);
    assert(hits[1] == 14);

    std::cout << "  [+] UTF-16LE case-insensitive matching passed." << std::endl;
}

void test_chunk_boundary_overlap()
{
    std::cout << "[*] Testing chunk boundary overlap handling..." << std::endl;
    Pattern pat;
    std::string err;
    assert(parse_hex_pattern("DE AD BE EF 00 11 22 33", pat, err));
    const size_t pat_len = pat.bytes.size();
    const size_t overlap = pat_len - 1;

    // Suppose chunk 1 ends with: DE AD BE EF
    // And chunk 2 starts with:   00 11 22 33
    // In memory, they form contiguous bytes at offset 96..103
    std::vector<uint8_t> full_mem(200, 0x00);
    for (size_t i = 0; i < pat_len; ++i)
    {
        full_mem[96 + i] = pat.bytes[i];
    }

    // Simulate chunked reading with chunk_size = 100
    const size_t chunk_size = 100;

    // Chunk 1: [0..100) -> bytes 96..99 are DE AD BE EF (first 4 bytes of pattern)
    // Chunk 2 with overlap: starts at offset (100 - overlap) = 93..193
    // In Chunk 2, pattern starts at offset (96 - 93) = 3!
    size_t chunk1_start = 0;
    size_t chunk1_len = chunk_size;

    auto hits1 = find_all(full_mem.data() + chunk1_start, chunk1_len, pat);
    assert(hits1.empty()); // Straddles boundary, cannot complete inside Chunk 1

    size_t chunk2_start = chunk1_len - overlap; // 100 - 7 = 93
    size_t chunk2_len = chunk_size;

    auto hits2 = find_all(full_mem.data() + chunk2_start, chunk2_len, pat);
    assert(hits2.size() == 1);
    assert(chunk2_start + hits2[0] == 96); // Exactly reconstructed target address!

    std::cout << "  [+] Chunk-boundary overlap correctly captures cross-boundary matches." << std::endl;
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << " Running Deadeye Pattern Search Tests   " << std::endl;
    std::cout << "========================================" << std::endl;

    test_hex_wildcard_patterns();
    test_ascii_string_patterns();
    test_utf16le_string_patterns();
    test_chunk_boundary_overlap();

    std::cout << "[SUCCESS] All Advanced Pattern Search tests passed!" << std::endl;
    return 0;
}
