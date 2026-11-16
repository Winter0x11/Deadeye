// tests/test_timeline.cpp
// Unit tests for Deadeye Memory Investigation Timeline Engine

#include "core/timeline.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

void test_timeline_recording_and_counts()
{
    std::cout << "[*] Testing timeline recording and event counts..." << std::endl;
    core::TimelineManager tm(100);
    assert(tm.count() == 0);

    // Record observed region
    uint64_t id1 = tm.record_region_observed(1234, 0x7FFE0000, 0x10000, PAGE_READWRITE, MEM_PRIVATE, 4.5);
    assert(id1 == 1);
    assert(tm.count() == 1);

    // Record protection change: RW -> RX (ExecPermGained)
    uint64_t id2 = tm.record_protection_changed(1234, 0x7FFE0000, 0x10000, PAGE_READWRITE, PAGE_EXECUTE_READ, MEM_PRIVATE);
    assert(id2 == 2);
    assert(tm.count() == 2);

    // Record protection change: RX -> RW (ExecPermLost)
    uint64_t id3 = tm.record_protection_changed(1234, 0x7FFE0000, 0x10000, PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_PRIVATE);
    assert(id3 == 3);

    // Record content changed
    uint64_t id4 = tm.record_content_changed(1234, 0x7FFE0000, 0x10000, PAGE_READWRITE, MEM_PRIVATE, 512, "Decryption detected");
    assert(id4 == 4);

    // Record entropy shift
    uint64_t id5 = tm.record_entropy_shift(1234, 0x7FFE0000, 0x10000, PAGE_READWRITE, MEM_PRIVATE, 3.2, 7.8, "Encrypted / Packed");
    assert(id5 == 5);

    // Record region disappeared
    uint64_t id6 = tm.record_region_disappeared(1234, 0x7FFE0000, 0x10000, PAGE_READWRITE, MEM_PRIVATE);
    assert(id6 == 6);

    // Record snapshot and diff
    uint64_t id7 = tm.record_snapshot_captured(1234, "snap_01", "Snapshot 1", 10, 409600);
    uint64_t id8 = tm.record_diff_generated(1234, "Snap 1 vs Snap 2", 2, 1024);
    assert(id7 == 7 && id8 == 8);
    assert(tm.count() == 8);

    core::TimelineEvent ev2;
    assert(tm.get_event_by_id(2, ev2));
    assert(ev2.event_type == core::TimelineEventType::ExecPermGained);
    assert(ev2.category == core::TimelineCategory::Protection);

    core::TimelineEvent ev3;
    assert(tm.get_event_by_id(3, ev3));
    assert(ev3.event_type == core::TimelineEventType::ExecPermLost);

    core::TimelineEvent ev6;
    assert(tm.get_event_by_id(6, ev6));
    assert(ev6.event_type == core::TimelineEventType::RegionDisappeared);
    assert(ev6.category == core::TimelineCategory::Lifecycle);

    std::cout << "  [+] Recording and event type categorization passed." << std::endl;
}

void test_timeline_filtering()
{
    std::cout << "[*] Testing timeline querying and filters..." << std::endl;
    core::TimelineManager tm(100);

    tm.record_region_observed(100, 0x10000, 0x1000, PAGE_READONLY, MEM_IMAGE);
    tm.record_protection_changed(100, 0x10000, 0x1000, PAGE_READONLY, PAGE_EXECUTE_READ, MEM_IMAGE);
    tm.record_content_changed(100, 0x20000, 0x2000, PAGE_READWRITE, MEM_PRIVATE, 64);
    tm.record_entropy_shift(100, 0x30000, 0x3000, PAGE_READWRITE, MEM_PRIVATE, 4.0, 7.5);
    tm.record_snapshot_captured(100, "snap_a", "Baseline", 5, 20480);

    // Filter by Category: Protection only
    core::TimelineFilter f_prot;
    f_prot.category_mask = core::TimelineCategory::Protection;
    auto res_prot = tm.query(f_prot);
    assert(res_prot.size() == 1);
    assert(res_prot[0].event_type == core::TimelineEventType::ExecPermGained);

    // Filter by Category: SnapshotDiff only
    core::TimelineFilter f_snap;
    f_snap.category_mask = core::TimelineCategory::SnapshotDiff;
    auto res_snap = tm.query(f_snap);
    assert(res_snap.size() == 1);
    assert(res_snap[0].summary.find("Baseline") != std::string::npos);

    // Filter by Address range: [0x10000, 0x15000)
    core::TimelineFilter f_addr;
    f_addr.min_address = 0x10000;
    f_addr.max_address = 0x15000;
    auto res_addr = tm.query(f_addr);
    assert(res_addr.size() == 2);

    // Filter by Text search: "Entropy"
    core::TimelineFilter f_txt;
    f_txt.text_query = "entropy";
    auto res_txt = tm.query(f_txt);
    assert(res_txt.size() >= 1);

    // Sort order: Descending
    core::TimelineFilter f_desc;
    f_desc.sort_ascending = false;
    auto res_desc = tm.query(f_desc);
    assert(res_desc.size() == 5);
    assert(res_desc[0].id == 5);
    assert(res_desc.back().id == 1);

    std::cout << "  [+] Category, address range, text query, and sorting passed." << std::endl;
}

void test_timeline_capacity_and_json()
{
    std::cout << "[*] Testing timeline ring capacity capping and JSON serialization..." << std::endl;
    core::TimelineManager tm(5); // Cap to 5 events

    for (int i = 1; i <= 10; ++i)
    {
        tm.record_region_observed(100, 0x10000 * i, 0x1000, PAGE_READWRITE, MEM_PRIVATE);
    }
    assert(tm.count() == 5);

    core::TimelineFilter f_all;
    auto res = tm.query(f_all);
    assert(res.size() == 5);
    // Oldest surviving event should be 6
    assert(res[0].id == 6);
    assert(res.back().id == 10);

    // Test JSON export
    std::string json = tm.export_json(f_all);
    assert(!json.empty());
    assert(json.find("\"events\"") != std::string::npos);
    assert(json.find("\"total_events\": 5") != std::string::npos);
    assert(json.find("0x00000000000A0000") != std::string::npos || json.find("A0000") != std::string::npos);

    std::cout << "  [+] Ring capacity capping and JSON export passed." << std::endl;
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << " Running Deadeye Memory Timeline Tests  " << std::endl;
    std::cout << "========================================" << std::endl;

    test_timeline_recording_and_counts();
    test_timeline_filtering();
    test_timeline_capacity_and_json();

    std::cout << "[SUCCESS] All Memory Timeline tests passed!" << std::endl;
    return 0;
}
