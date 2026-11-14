// src/core/triage.cpp
// Deadeye Defensive Triage Threat Engine
#include "core/triage.hpp"
#include "core/util.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>

PageEntropyProfile compute_region_entropy_profile(MemorySource &source, uintptr_t base, SIZE_T size)
{
    PageEntropyProfile prof;
    if (size == 0)
    {
        prof.ascii_profile = "n/a";
        return prof;
    }

    size_t num_pages = (size + 4095) / 4096;
    prof.total_pages = num_pages;

    // Hardening: Sample up to 64 pages evenly distributed across large regions
    size_t pages_to_check = num_pages;
    if (pages_to_check > 64)
    {
        pages_to_check = 64;
        prof.is_sampled = true;
    }

    std::vector<uint8_t> page_buf(4096);
    double sum_entropy = 0.0;
    size_t valid_count = 0;
    double max_ent = -1.0;

    prof.ascii_profile.reserve(pages_to_check);

    for (size_t k = 0; k < pages_to_check; ++k)
    {
        size_t page_idx = (pages_to_check == num_pages) ? k : (k * (num_pages - 1) / (pages_to_check - 1));
        uintptr_t page_addr = base + page_idx * 4096;
        SIZE_T bytes_left = (page_idx * 4096 < size) ? (size - page_idx * 4096) : 0;
        SIZE_T to_read = (bytes_left < 4096) ? bytes_left : 4096;

        if (to_read < 512)
        {
            prof.ascii_profile.push_back('?');
            continue;
        }

        SIZE_T read_len = source.read(page_addr, to_read, page_buf.data());
        if (read_len < 512)
        {
            prof.ascii_profile.push_back('?');
            continue;
        }

        double h = calculate_shannon_entropy(page_buf.data(), read_len);
        sum_entropy += h;
        valid_count++;
        if (h > max_ent)
        {
            max_ent = h;
        }

        // Compact ASCII profile mapping: ._-=#
        if (h < 2.0)
            prof.ascii_profile.push_back('.');
        else if (h < 4.0)
            prof.ascii_profile.push_back('_');
        else if (h < 6.0)
            prof.ascii_profile.push_back('-');
        else if (h < 7.2)
            prof.ascii_profile.push_back('=');
        else
            prof.ascii_profile.push_back('#');
    }

    prof.valid_pages = valid_count;
    if (valid_count > 0)
    {
        prof.avg_entropy = sum_entropy / static_cast<double>(valid_count);
        prof.max_entropy = max_ent;
    }
    else
    {
        prof.avg_entropy = -1.0;
        prof.max_entropy = -1.0;
        prof.ascii_profile = "n/a";
    }

    return prof;
}

TriageReport run_source_triage(std::shared_ptr<MemorySource> source,
                               std::vector<RegionInfo> &regions,
                               std::atomic<bool> *abort_flag,
                               void (*progress_cb)(SIZE_T current, SIZE_T total, void *user_data),
                               void *user_data)
{
    TriageReport report;
    if (!source)
        return report;

    report.source_description = source->describe();
    report.source_kind = source->kind();
    report.source_base = source->get_base_address();
    MemorySourceCapabilities caps = source->capabilities();
    report.protection_is_synthetic = caps.protection_is_synthetic;
    report.pid = (caps.is_live) ? source->get_pid() : 0;

    SIZE_T total_regions = regions.size();

    if (caps.is_live)
    {
        // Dynamic live process heuristics
        report.rules_not_evaluated = {
            "STATIC_WX_SECTION",
            "STATIC_EP_OUTSIDE_EXEC",
            "STATIC_NONTRIVIAL_OVERLAY"
        };

        std::vector<LoadedModuleRange> peb_modules;
        bool peb_ok = source->query_peb_modules(peb_modules, report.wow64_unsupported);

        std::vector<uint8_t> header_buf(4096);

        for (size_t i = 0; i < regions.size(); ++i)
        {
            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
                break;

            RegionInfo &reg = regions[i];

            // 1. Calculate Shannon entropy profile (page-wise & region aggregation)
            PageEntropyProfile ent_prof = compute_region_entropy_profile(*source, reg.base, reg.size);
            reg.avg_entropy = ent_prof.avg_entropy;
            reg.max_entropy = ent_prof.max_entropy;
            reg.entropy_ascii_profile = ent_prof.ascii_profile;
            reg.entropy_sampled = ent_prof.is_sampled;
            reg.entropy = (ent_prof.avg_entropy > 0.0) ? ent_prof.avg_entropy : 0.0;

            RegionEntropyJson rej;
            rej.base = reg.base;
            rej.avg_entropy = ent_prof.avg_entropy;
            rej.max_entropy = ent_prof.max_entropy;
            rej.ascii_profile = ent_prof.ascii_profile;
            report.entropy_profiles.push_back(rej);

            // Check for injected PE header in MEM_PRIVATE regions
            if (reg.type == MEM_PRIVATE)
            {
                SIZE_T to_read = (reg.size < 4096) ? reg.size : 4096;
                SIZE_T bytes_read = source->read(reg.base, to_read, header_buf.data());
                if (bytes_read > 0 && has_pe_header(header_buf.data(), bytes_read))
                {
                    reg.is_pe_in_private = true;
                }
            }

            // Check for unlinked MEM_IMAGE allocations (missing from PEB loader list)
            if (!report.wow64_unsupported && peb_ok && reg.type == MEM_IMAGE && reg.base == reg.alloc_base)
            {
                bool in_peb = false;
                for (const auto &mod : peb_modules)
                {
                    if (mod.base == reg.base)
                    {
                        in_peb = true;
                        break;
                    }
                }
                if (!in_peb)
                {
                    reg.is_unlinked_image = true;
                }
            }

            // Calculate additive triage severity score
            TriageFinding finding;
            finding.region_index = i;
            finding.base = reg.base;
            finding.size = reg.size;
            finding.alloc_base = reg.alloc_base;
            finding.type = reg.type;
            finding.protect = reg.protect;
            finding.alloc_protect = reg.alloc_protect;
            finding.severity_score = 0;

            bool is_exec = (reg.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            if (reg.is_pe_in_private)
            {
                finding.severity_score += WEIGHT_INJECTED_PE;
                finding.flags.push_back("INJECTED_PE");
                finding.reasons.push_back("Injected PE/Reflective DLL header in private memory (+" +
                                          std::to_string(WEIGHT_INJECTED_PE) + ")");
            }
            if (reg.is_unlinked_image)
            {
                finding.severity_score += WEIGHT_UNLINKED_MODULE;
                finding.flags.push_back("UNLINKED_MODULE");
                finding.reasons.push_back("Image allocation unlinked from PEB loader list (+" +
                                          std::to_string(WEIGHT_UNLINKED_MODULE) + ")");
            }
            if (reg.private_rwx)
            {
                finding.severity_score += WEIGHT_PRIVATE_RWX;
                finding.flags.push_back("PRIVATE_RWX");
                finding.reasons.push_back("Private memory with RWX/RXC protection (+" +
                                          std::to_string(WEIGHT_PRIVATE_RWX) + ")");
            }
            if (reg.write_then_flip)
            {
                finding.severity_score += WEIGHT_WRITE_THEN_FLIP;
                finding.flags.push_back("WRITE_THEN_FLIP");
                finding.reasons.push_back("Write-then-flip: allocated writable, currently executable (+" +
                                          std::to_string(WEIGHT_WRITE_THEN_FLIP) + ")");
            }
            if (reg.is_unbacked_exec)
            {
                finding.severity_score += WEIGHT_UNBACKED_EXEC;
                finding.flags.push_back("UNBACKED_EXEC");
                finding.reasons.push_back("Executable memory not backed by a disk image (+" +
                                          std::to_string(WEIGHT_UNBACKED_EXEC) + ")");
            }
            if (reg.behavior_unpack_detected)
            {
                finding.severity_score += WEIGHT_BEHAVIOR_UNPACK;
                finding.flags.push_back("BEHAVIOR_UNPACK");
                finding.reasons.push_back("Unpack detected: memory flipped to executable with byte changes / entropy shift (+" +
                                          std::to_string(WEIGHT_BEHAVIOR_UNPACK) + ")");
            }
            if (reg.sleep_obfuscation_detected)
            {
                finding.severity_score += WEIGHT_SLEEP_OBFUSCATION;
                finding.flags.push_back("SLEEP_OBFUSCATION");
                finding.reasons.push_back("Sleep obfuscation detected: oscillating between dormant encrypted and active executable (+" +
                                          std::to_string(WEIGHT_SLEEP_OBFUSCATION) + ")");
            }

            // New Static Triage Rule: HIGH_ENTROPY_EXEC (executable region/page with entropy >= 7.2)
            if (is_exec && (ent_prof.max_entropy >= 7.2 || ent_prof.avg_entropy >= 7.2))
            {
                finding.severity_score += WEIGHT_HIGH_ENTROPY_EXEC;
                finding.flags.push_back("HIGH_ENTROPY_EXEC");
                char ent_buf[64];
                std::snprintf(ent_buf, sizeof(ent_buf), "avg %.2f, max %.2f", ent_prof.avg_entropy, ent_prof.max_entropy);
                finding.reasons.push_back(std::string("Executable region with high Shannon entropy (") + ent_buf +
                                          " >= 7.20, possible packed/encrypted code) (+" +
                                          std::to_string(WEIGHT_HIGH_ENTROPY_EXEC) + ")");
            }

            // New Static Triage Rule: HIGH_ENTROPY_PRIVATE (MEM_PRIVATE non-exec region >= 7.4 over at least 16 KB)
            // Note: Does NOT flag MEM_IMAGE data sections by entropy alone (compressed resources are normal)
            if (reg.type == MEM_PRIVATE && !is_exec && reg.size >= 16384 && ent_prof.avg_entropy >= 7.4)
            {
                finding.severity_score += WEIGHT_HIGH_ENTROPY_PRIVATE;
                finding.flags.push_back("HIGH_ENTROPY_PRIVATE");
                char ent_buf[32];
                std::snprintf(ent_buf, sizeof(ent_buf), "avg %.2f", ent_prof.avg_entropy);
                finding.reasons.push_back(std::string("Private non-executable buffer >= 16KB with high Shannon entropy (") +
                                          ent_buf + " >= 7.40, possible encrypted payload or blob) (+" +
                                          std::to_string(WEIGHT_HIGH_ENTROPY_PRIVATE) + ")");
            }

            if (finding.severity_score >= SEV_MIN_CRITICAL) finding.severity_label = "CRIT";
            else if (finding.severity_score >= SEV_MIN_HIGH) finding.severity_label = "HIGH";
            else if (finding.severity_score >= SEV_MIN_MEDIUM) finding.severity_label = "MED";
            else if (finding.severity_score >= SEV_MIN_LOW) finding.severity_label = "LOW";
            else finding.severity_label = "CLEAN";

            report.findings.push_back(finding);

            if (progress_cb != nullptr && (i % 20 == 0 || i + 1 == total_regions))
            {
                progress_cb(i + 1, total_regions, user_data);
            }
        }
    }
    else if (source->kind() == MemorySourceKind::MappedPe)
    {
        // Mapped PE static heuristics
        report.rules_not_evaluated = {
            "INJECTED_PE",
            "UNLINKED_MODULE",
            "PRIVATE_RWX",
            "WRITE_THEN_FLIP",
            "UNBACKED_EXEC",
            "BEHAVIOR_UNPACK",
            "SLEEP_OBFUSCATION",
            "SLEEP_MASK_SUSPECT (requires live process)",
            "KEY_ROTATION_SUSPECT (requires live process)",
            "DECRYPT_ON_WAKE (requires live process)",
            "BEHAVIOR_TRACKER (requires live process)"
        };

        PeSummaryInfo pe_info;
        bool has_pe = source->get_pe_summary(pe_info);

        for (size_t i = 0; i < regions.size(); ++i)
        {
            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
                break;

            RegionInfo &reg = regions[i];

            // 1. Calculate Shannon entropy profile (page-wise & region aggregation)
            PageEntropyProfile ent_prof = compute_region_entropy_profile(*source, reg.base, reg.size);
            reg.avg_entropy = ent_prof.avg_entropy;
            reg.max_entropy = ent_prof.max_entropy;
            reg.entropy_ascii_profile = ent_prof.ascii_profile;
            reg.entropy_sampled = ent_prof.is_sampled;
            reg.entropy = (ent_prof.avg_entropy > 0.0) ? ent_prof.avg_entropy : 0.0;

            RegionEntropyJson rej;
            rej.base = reg.base;
            rej.avg_entropy = ent_prof.avg_entropy;
            rej.max_entropy = ent_prof.max_entropy;
            rej.ascii_profile = ent_prof.ascii_profile;
            report.entropy_profiles.push_back(rej);

            TriageFinding finding;
            finding.region_index = i;
            finding.base = reg.base;
            finding.size = reg.size;
            finding.alloc_base = reg.alloc_base;
            finding.type = reg.type;
            finding.protect = reg.protect;
            finding.alloc_protect = reg.alloc_protect;
            finding.severity_score = 0;

            // 1. Static Heuristic: W+X section
            bool is_exec = (reg.protect == PAGE_EXECUTE || reg.protect == PAGE_EXECUTE_READ ||
                            reg.protect == PAGE_EXECUTE_READWRITE || reg.protect == PAGE_EXECUTE_WRITECOPY);
            bool is_write = (reg.protect == PAGE_READWRITE || reg.protect == PAGE_WRITECOPY ||
                             reg.protect == PAGE_EXECUTE_READWRITE || reg.protect == PAGE_EXECUTE_WRITECOPY);

            if (is_exec && is_write)
            {
                finding.severity_score += WEIGHT_STATIC_WX_SECTION;
                finding.flags.push_back("STATIC_WX_SECTION");
                finding.reasons.push_back("Static: Section has both Writable and Executable rights (W+X) (+" +
                                          std::to_string(WEIGHT_STATIC_WX_SECTION) + ")");
            }

            // 2. Static Heuristic: Entry point outside executable sections
            if (has_pe && pe_info.ep_outside_exec_sections)
            {
                uintptr_t ep_va = pe_info.effective_base + pe_info.entry_point_rva;
                if (ep_va >= reg.base && ep_va < reg.base + reg.size)
                {
                    finding.severity_score += WEIGHT_STATIC_EP_OUTSIDE_EXEC;
                    finding.flags.push_back("STATIC_EP_OUTSIDE_EXEC");
                    finding.reasons.push_back("Static: Entry point is outside all executable sections (+" +
                                              std::to_string(WEIGHT_STATIC_EP_OUTSIDE_EXEC) + ")");
                }
            }

            // 3. Static Heuristic: Section with executable rights and high Shannon entropy (>=7.2)
            double ent = (ent_prof.max_entropy >= 7.2) ? ent_prof.max_entropy : ((reg.entropy > 0.0) ? reg.entropy : reg.last_entropy);
            if (is_exec && ent >= 7.2)
            {
                finding.severity_score += WEIGHT_STATIC_EXEC_HIGH_ENTROPY;
                finding.flags.push_back("STATIC_EXEC_HIGH_ENTROPY");
                char ent_buf[32];
                std::snprintf(ent_buf, sizeof(ent_buf), "%.2f", ent);
                finding.reasons.push_back(std::string("Static: Executable section with high entropy (") + ent_buf +
                                          " >= 7.20, possible packed/encrypted payload) (+" +
                                          std::to_string(WEIGHT_STATIC_EXEC_HIGH_ENTROPY) + ")");
            }

            // 4. Static Heuristic: Non-trivial overlay (> 512 bytes) (assigned to final section)
            if (has_pe && pe_info.overlay_size > 512 && (i + 1 == regions.size()))
            {
                finding.severity_score += WEIGHT_STATIC_NONTRIVIAL_OVERLAY;
                finding.flags.push_back("STATIC_NONTRIVIAL_OVERLAY");
                finding.reasons.push_back("Static: Non-trivial overlay detected after raw sections (" +
                                          std::to_string(pe_info.overlay_size) + " bytes) (+" +
                                          std::to_string(WEIGHT_STATIC_NONTRIVIAL_OVERLAY) + ")");
            }

            if (finding.severity_score >= SEV_MIN_CRITICAL) finding.severity_label = "CRIT";
            else if (finding.severity_score >= SEV_MIN_HIGH) finding.severity_label = "HIGH";
            else if (finding.severity_score >= SEV_MIN_MEDIUM) finding.severity_label = "MED";
            else if (finding.severity_score >= SEV_MIN_LOW) finding.severity_label = "LOW";
            else finding.severity_label = "CLEAN";

            report.findings.push_back(finding);

            if (progress_cb != nullptr && (i % 20 == 0 || i + 1 == total_regions))
            {
                progress_cb(i + 1, total_regions, user_data);
            }
        }
    }
    else // RawFileSource
    {
        report.rules_not_evaluated = {
            "INJECTED_PE",
            "UNLINKED_MODULE",
            "PRIVATE_RWX",
            "WRITE_THEN_FLIP",
            "UNBACKED_EXEC",
            "BEHAVIOR_UNPACK",
            "SLEEP_OBFUSCATION",
            "STATIC_WX_SECTION",
            "STATIC_EP_OUTSIDE_EXEC",
            "STATIC_EXEC_HIGH_ENTROPY",
            "STATIC_NONTRIVIAL_OVERLAY",
            "SLEEP_MASK_SUSPECT (requires live process)",
            "KEY_ROTATION_SUSPECT (requires live process)",
            "DECRYPT_ON_WAKE (requires live process)",
            "BEHAVIOR_TRACKER (requires live process)"
        };

        for (size_t i = 0; i < regions.size(); ++i)
        {
            RegionInfo &reg = regions[i];

            // Calculate Shannon entropy profile
            PageEntropyProfile ent_prof = compute_region_entropy_profile(*source, reg.base, reg.size);
            reg.avg_entropy = ent_prof.avg_entropy;
            reg.max_entropy = ent_prof.max_entropy;
            reg.entropy_ascii_profile = ent_prof.ascii_profile;
            reg.entropy_sampled = ent_prof.is_sampled;
            reg.entropy = (ent_prof.avg_entropy > 0.0) ? ent_prof.avg_entropy : 0.0;

            RegionEntropyJson rej;
            rej.base = reg.base;
            rej.avg_entropy = ent_prof.avg_entropy;
            rej.max_entropy = ent_prof.max_entropy;
            rej.ascii_profile = ent_prof.ascii_profile;
            report.entropy_profiles.push_back(rej);

            TriageFinding finding;
            finding.region_index = i;
            finding.base = reg.base;
            finding.size = reg.size;
            finding.alloc_base = reg.alloc_base;
            finding.type = reg.type;
            finding.protect = reg.protect;
            finding.alloc_protect = reg.alloc_protect;
            finding.severity_score = 0;
            finding.severity_label = "CLEAN";
            report.findings.push_back(finding);
        }
    }

    // Sort findings by severity score descending (highest threat first)
    std::stable_sort(report.findings.begin(), report.findings.end(),
                     [](const TriageFinding &a, const TriageFinding &b)
                     {
                         return a.severity_score > b.severity_score;
                     });

    return report;
}
