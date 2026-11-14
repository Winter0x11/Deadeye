// src/core/json_export.cpp
// Deadeye Defensive Triage JSON Serialization

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "core/json_export.hpp"
#include "core/util.hpp"
#include <cstdio>

std::string export_triage_json(
    const TriageReport &report,
    const std::vector<WatchedRegionState> *watched_regions,
    uint64_t partial_sample_count,
    uint32_t interval_ms)
{
    std::string json;
    json.reserve(report.findings.size() * 512 + 512);
    json += "{\n";
    json += "  \"source\": {\n";
    std::string kind_str = "Live";
    if (report.source_kind == MemorySourceKind::MappedPe) kind_str = "MappedPe";
    else if (report.source_kind == MemorySourceKind::RawFile) kind_str = "RawFile";
    json += "    \"kind\": \"" + kind_str + "\",\n";
    json += "    \"name\": \"" + escape_json(report.source_description) + "\",\n";
    json += "    \"base\": \"" + to_hex_string(report.source_base) + "\",\n";
    json += "    \"synthetic_protection\": " + std::string(report.protection_is_synthetic ? "true" : "false") + "\n";
    json += "  },\n";
    json += "  \"pid\": " + std::to_string(report.pid) + ",\n";
    json += "  \"wow64_unsupported\": " + std::string(report.wow64_unsupported ? "true" : "false") + ",\n";
    json += "  \"rules_not_evaluated\": [";
    for (size_t k = 0; k < report.rules_not_evaluated.size(); ++k)
    {
        json += "\"" + report.rules_not_evaluated[k] + "\"" + (k + 1 < report.rules_not_evaluated.size() ? ", " : "");
    }
    json += "],\n";

    // 1. Per-region Entropy Profiles
    json += "  \"entropy\": [\n";
    for (size_t i = 0; i < report.entropy_profiles.size(); ++i)
    {
        const auto &e = report.entropy_profiles[i];
        json += "    {\n";
        json += "      \"base\": \"" + to_hex_string(e.base) + "\",\n";
        json += "      \"avg_entropy\": " + ((e.avg_entropy >= 0.0) ? std::to_string(e.avg_entropy) : "-1.0") + ",\n";
        json += "      \"max_entropy\": " + ((e.max_entropy >= 0.0) ? std::to_string(e.max_entropy) : "-1.0") + ",\n";
        json += "      \"ascii_profile\": \"" + escape_json(e.ascii_profile) + "\"\n";
        json += "    }" + std::string(i + 1 < report.entropy_profiles.size() ? ",\n" : "\n");
    }
    json += "  ],\n";

    // 2. Behavioral Tracking Array (Live Sources Only)
    json += "  \"behavior\": [\n";
    if (report.source_kind == MemorySourceKind::Live && watched_regions != nullptr)
    {
        for (size_t i = 0; i < watched_regions->size(); ++i)
        {
            const auto &w = (*watched_regions)[i];
            json += "    {\n";
            json += "      \"base\": \"" + to_hex_string(w.key.base) + "\",\n";
            json += "      \"alloc_base\": \"" + to_hex_string(w.key.alloc_base) + "\",\n";
            json += "      \"generation\": " + std::to_string(w.key.generation) + ",\n";
            json += "      \"size\": " + std::to_string(w.size) + ",\n";
            json += "      \"pinned\": " + std::string(w.is_pinned ? "true" : "false") + ",\n";
            json += "      \"sample_count\": " + std::to_string(w.ring_samples.size()) + ",\n";
            json += "      \"partial_sample_count\": " + std::to_string(partial_sample_count) + ",\n";
            json += "      \"interval_ms\": " + std::to_string(interval_ms) + ",\n";
            json += "      \"score\": " + std::to_string(w.behavior_score) + ",\n";
            json += "      \"flags\": [";
            for (size_t k = 0; k < w.behavior_flags.size(); ++k)
            {
                json += "\"" + w.behavior_flags[k] + "\"" + (k + 1 < w.behavior_flags.size() ? ", " : "");
            }
            json += "],\n";
            json += "      \"evidence\": {\n";
            json += "        \"summary\": \"" + escape_json(w.evidence_summary) + "\",\n";
            json += "        \"sleep_mask\": {\n";
            json += "          \"cycle_count\": " + std::to_string(w.sleep_evidence.cycles) + ",\n";
            json += "          \"period_ms\": " + std::to_string(w.sleep_evidence.period_ms) + ",\n";
            json += "          \"min_entropy\": " + std::to_string(w.sleep_evidence.min_entropy) + ",\n";
            json += "          \"max_entropy\": " + std::to_string(w.sleep_evidence.max_entropy) + ",\n";
            json += "          \"protection_sequence\": \"" + escape_json(w.sleep_evidence.protect_seq) + "\"\n";
            json += "        },\n";
            json += "        \"key_rotation\": {\n";
            json += "          \"xor_period\": " + std::to_string(w.key_evidence.xor_period) + ",\n";
            std::string dkey_hex;
            for (uint8_t kb : w.key_evidence.candidate_delta_key)
            {
                char h[4]; std::snprintf(h, sizeof(h), "%02X ", kb); dkey_hex += h;
            }
            json += "          \"candidate_delta_key_hex\": \"" + escape_json(dkey_hex) + "\",\n";
            json += "          \"note\": \"" + escape_json(w.key_evidence.note) + "\"\n";
            json += "        },\n";
            json += "        \"decrypt_on_wake\": {\n";
            json += "          \"entropy_before\": " + std::to_string(w.decrypt_evidence.entropy_before) + ",\n";
            json += "          \"entropy_after\": " + std::to_string(w.decrypt_evidence.entropy_after) + ",\n";
            json += "          \"new_strings_count\": " + std::to_string(w.decrypt_evidence.new_strings_count) + ",\n";
            json += "          \"sample_strings\": [";
            for (size_t s = 0; s < w.decrypt_evidence.sample_strings.size(); ++s)
            {
                json += "\"" + escape_json(w.decrypt_evidence.sample_strings[s]) + "\"" + (s + 1 < w.decrypt_evidence.sample_strings.size() ? ", " : "");
            }
            json += "]\n";
            json += "        }\n";
            json += "      }\n";
            json += "    }" + std::string(i + 1 < watched_regions->size() ? ",\n" : "\n");
        }
    }
    json += "  ],\n";

    json += "  \"findings_count\": " + std::to_string(report.findings.size()) + ",\n";
    json += "  \"findings\": [\n";

    for (size_t i = 0; i < report.findings.size(); ++i)
    {
        const TriageFinding &f = report.findings[i];
        json += "    {\n";
        json += "      \"base\": \"" + to_hex_string(f.base) + "\",\n";
        json += "      \"size\": " + std::to_string(f.size) + ",\n";
        json += "      \"alloc_base\": \"" + to_hex_string(f.alloc_base) + "\",\n";
        json += "      \"type\": \"" + type_full(f.type) + "\",\n";
        json += "      \"protect\": \"" + prot_full(f.protect) + "\",\n";
        json += "      \"alloc_protect\": \"" + prot_full(f.alloc_protect) + "\",\n";
        json += "      \"severity_score\": " + std::to_string(f.severity_score) + ",\n";
        json += "      \"severity_label\": \"" + f.severity_label + "\",\n";

        json += "      \"flags\": [";
        for (size_t k = 0; k < f.flags.size(); ++k)
        {
            json += "\"" + f.flags[k] + "\"" + (k + 1 < f.flags.size() ? ", " : "");
        }
        json += "],\n";

        json += "      \"reasons\": [\n";
        for (size_t k = 0; k < f.reasons.size(); ++k)
        {
            json += "        \"" + escape_json(f.reasons[k]) + "\"" + (k + 1 < f.reasons.size() ? ",\n" : "\n");
        }
        json += "      ]\n";
        json += "    }" + std::string(i + 1 < report.findings.size() ? ",\n" : "\n");
    }

    json += "  ]\n";
    json += "}\n";
    return json;
}
