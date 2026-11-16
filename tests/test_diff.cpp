// tests/test_diff.cpp
// Unit tests for Deadeye Byte-Level Memory Diff Engine & Snapshot Storage

#include "core/snapshot.hpp"
#include "core/util.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>

static core::ProcessSnapshot make_test_snapshot(const std::string &name, DWORD pid)
{
    core::ProcessSnapshot snap;
    snap.metadata.id = "snap_" + name;
    snap.metadata.name = name;
    snap.metadata.pid = pid;
    snap.metadata.timestamp_unix_sec = 1700000000;
    snap.metadata.timestamp_str = "12:00:00.000";
    snap.metadata.process_name = "target.exe";
    snap.metadata.architecture = "x64";
    return snap;
}

static core::SnapshotRegion make_test_region(uintptr_t base, SIZE_T size, DWORD protect, DWORD type, const std::vector<uint8_t> &data)
{
    core::SnapshotRegion reg;
    reg.base_address = base;
    reg.region_size = size;
    reg.protect = protect;
    reg.alloc_protect = protect;
    reg.alloc_base = base;
    reg.type = type;
    reg.state = MEM_COMMIT;
    reg.bytes_captured = data.size();
    reg.data = data;
    reg.status = core::SnapshotCaptureStatus::Complete;
    reg.checksum = fnv1a64(data.data(), data.size());
    return reg;
}

void test_identical_snapshots()
{
    std::cout << "[*] Testing identical snapshots comparison..." << std::endl;
    auto snap_a = make_test_snapshot("Baseline", 1000);
    auto snap_b = make_test_snapshot("Current", 1000);

    std::vector<uint8_t> page_data(4096, 0x90); // 4 KB of NOPs
    snap_a.regions.push_back(make_test_region(0x10000, 4096, PAGE_EXECUTE_READ, MEM_PRIVATE, page_data));
    snap_b.regions.push_back(make_test_region(0x10000, 4096, PAGE_EXECUTE_READ, MEM_PRIVATE, page_data));

    core::SnapshotCompareReport report;
    std::string err;
    assert(core::compare_snapshots(snap_a, snap_b, report, err));

    assert(report.pid_match);
    assert(report.count_unchanged_regions == 1);
    assert(report.count_modified_regions == 0);
    assert(report.count_added_regions == 0);
    assert(report.count_removed_regions == 0);
    assert(report.total_changed_bytes == 0);
    assert(report.region_diffs.size() == 1);
    assert(report.region_diffs[0].overall_status == core::DiffByteStatus::Unchanged);

    std::cout << "  [+] Identical snapshots comparison passed." << std::endl;
}

void test_single_byte_and_multi_range_diff()
{
    std::cout << "[*] Testing byte-level changed ranges detection..." << std::endl;
    auto snap_a = make_test_snapshot("A", 2000);
    auto snap_b = make_test_snapshot("B", 2000);

    std::vector<uint8_t> data_a(100, 0x00);
    std::vector<uint8_t> data_b = data_a;

    // Single byte change at offset 10
    data_b[10] = 0xFF;

    // Second changed range at offset 50..54 (5 bytes)
    for (size_t i = 50; i < 55; ++i) data_b[i] = 0xAA;

    snap_a.regions.push_back(make_test_region(0x20000, 100, PAGE_READWRITE, MEM_PRIVATE, data_a));
    snap_b.regions.push_back(make_test_region(0x20000, 100, PAGE_READWRITE, MEM_PRIVATE, data_b));

    core::SnapshotCompareReport report;
    std::string err;
    assert(core::compare_snapshots(snap_a, snap_b, report, err));

    assert(report.count_modified_regions == 1);
    assert(report.total_changed_bytes == 6); // 1 + 5
    [[maybe_unused]] const auto &rd = report.region_diffs[0];
    assert(rd.overall_status == core::DiffByteStatus::Modified);
    assert(rd.changed_ranges.size() == 2);

    // Range 1
    assert(rd.changed_ranges[0].offset_in_region == 10);
    assert(rd.changed_ranges[0].length == 1);
    assert(rd.changed_ranges[0].old_bytes[0] == 0x00);
    assert(rd.changed_ranges[0].new_bytes[0] == 0xFF);

    // Range 2
    assert(rd.changed_ranges[1].offset_in_region == 50);
    assert(rd.changed_ranges[1].length == 5);
    assert(rd.changed_ranges[1].new_bytes[0] == 0xAA);

    std::cout << "  [+] Changed byte ranges calculated with exact offsets and lengths." << std::endl;
}

void test_added_removed_and_protect_diff()
{
    std::cout << "[*] Testing added/removed regions and protection change..." << std::endl;
    auto snap_a = make_test_snapshot("A", 3000);
    auto snap_b = make_test_snapshot("B", 3000);

    std::vector<uint8_t> dummy(64, 0xCC);

    // Region 1: In A, removed in B
    snap_a.regions.push_back(make_test_region(0x10000, 64, PAGE_READONLY, MEM_IMAGE, dummy));

    // Region 2: In B, added (was absent in A)
    snap_b.regions.push_back(make_test_region(0x20000, 64, PAGE_READWRITE, MEM_PRIVATE, dummy));

    // Region 3: Present in both, but protection changed RW -> RX
    snap_a.regions.push_back(make_test_region(0x30000, 64, PAGE_READWRITE, MEM_PRIVATE, dummy));
    snap_b.regions.push_back(make_test_region(0x30000, 64, PAGE_EXECUTE_READ, MEM_PRIVATE, dummy));

    core::SnapshotCompareReport report;
    std::string err;
    assert(core::compare_snapshots(snap_a, snap_b, report, err));

    assert(report.count_removed_regions == 1);
    assert(report.count_added_regions == 1);
    assert(report.count_modified_regions == 1); // due to protect change

    bool found_removed = false, found_added = false, found_prot = false;
    for (const auto &rd : report.region_diffs)
    {
        if (rd.base_address == 0x10000)
        {
            assert(rd.overall_status == core::DiffByteStatus::Removed);
            found_removed = true;
        }
        else if (rd.base_address == 0x20000)
        {
            assert(rd.overall_status == core::DiffByteStatus::Added);
            found_added = true;
        }
        else if (rd.base_address == 0x30000)
        {
            assert(rd.protection_changed);
            assert(rd.old_protect == PAGE_READWRITE);
            assert(rd.new_protect == PAGE_EXECUTE_READ);
            found_prot = true;
        }
    }
    assert(found_removed && found_added && found_prot);

    std::cout << "  [+] Added, removed, and protection transition diffs passed." << std::endl;
}

void test_file_diff_and_json_export()
{
    std::cout << "[*] Testing file serialization and offline snapshot diffing..." << std::endl;
    auto snap_a = make_test_snapshot("Disk_A", 4000);
    auto snap_b = make_test_snapshot("Disk_B", 4000);

    std::vector<uint8_t> data_a = { 0x41, 0x42, 0x43, 0x44 };
    std::vector<uint8_t> data_b = { 0x41, 0x90, 0x90, 0x44 };

    snap_a.regions.push_back(make_test_region(0x50000, 4, PAGE_READWRITE, MEM_PRIVATE, data_a));
    snap_b.regions.push_back(make_test_region(0x50000, 4, PAGE_READWRITE, MEM_PRIVATE, data_b));

    const std::string file_a = "temp_snap_a.desnap";
    const std::string file_b = "temp_snap_b.desnap";

    std::string err;
    assert(core::save_snapshot_to_file(snap_a, file_a, err));
    assert(core::save_snapshot_to_file(snap_b, file_b, err));

    core::SnapshotCompareReport report;
    assert(core::compare_snapshot_files(file_a, file_b, report, err));
    assert(report.count_modified_regions == 1);
    assert(report.total_changed_bytes == 2);

    // Test JSON export
    std::string json = core::export_diff_json(report, true);
    assert(!json.empty());
    assert(json.find("\"snapshot_a\"") != std::string::npos);
    assert(json.find("\"total_changed_bytes\": 2") != std::string::npos);
    assert(json.find("\"new_hex\": \"9090\"") != std::string::npos);

    // Clean up temporary files
    std::remove(file_a.c_str());
    std::remove(file_b.c_str());

    std::cout << "  [+] Offline .desnap comparison and JSON export passed." << std::endl;
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << " Running Deadeye Memory Diff Tests      " << std::endl;
    std::cout << "========================================" << std::endl;

    test_identical_snapshots();
    test_single_byte_and_multi_range_diff();
    test_added_removed_and_protect_diff();
    test_file_diff_and_json_export();

    std::cout << "[SUCCESS] All Memory Diff tests passed!" << std::endl;
    return 0;
}
