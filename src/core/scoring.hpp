// src/core/scoring.hpp
// Deadeye Defensive Triage & Detection Engineering Scoring Constants
#pragma once

#include <cstdint>

// ----------------------------------------------------------------------------
// Heuristic Severity Weights & Thresholds
// ----------------------------------------------------------------------------
inline constexpr int WEIGHT_INJECTED_PE = 50;     // MZ/PE header detected in MEM_PRIVATE
inline constexpr int WEIGHT_UNLINKED_MODULE = 45; // Image region unlinked from PEB loader list
inline constexpr int WEIGHT_PRIVATE_RWX = 40;     // Private memory with RWX/RXC protection
inline constexpr int WEIGHT_WRITE_THEN_FLIP = 35; // AllocationProtect writable, Protect executable
inline constexpr int WEIGHT_UNBACKED_EXEC = 25;   // Executable unbacked by MEM_IMAGE
inline constexpr int WEIGHT_BEHAVIOR_UNPACK = 50; // Memory flipped to executable with byte changes / entropy shift
inline constexpr int WEIGHT_SLEEP_OBFUSCATION = 65; // Protection/entropy oscillating across heartbeat ticks

// Memory Behavior Analysis: Phase 2 Weights
inline constexpr int WEIGHT_HIGH_ENTROPY_EXEC = 35;     // Executable region (or page) with entropy >= 7.2
inline constexpr int WEIGHT_HIGH_ENTROPY_PRIVATE = 20;  // MEM_PRIVATE non-executable region >= 7.4 over at least 16 KB

// Behavior Tracker Detections
inline constexpr int WEIGHT_SLEEP_MASK_SUSPECT = 40;    // Oscillates between low/high entropy and/or exec <-> non-exec/NOACCESS >= 3 cycles
inline constexpr int WEIGHT_KEY_ROTATION_SUSPECT = 35;  // High entropy with changing content hash & repeating XOR delta
inline constexpr int WEIGHT_DECRYPT_ON_WAKE = 35;       // Sharp entropy drop + new strings appearing vs baseline

// Static Mapped PE Heuristic Weights
inline constexpr int WEIGHT_STATIC_WX_SECTION = 50;        // Section marked writable and executable (W+X)
inline constexpr int WEIGHT_STATIC_EP_OUTSIDE_EXEC = 45;   // Entry point outside executable sections
inline constexpr int WEIGHT_STATIC_EXEC_HIGH_ENTROPY = 40; // Executable section with high Shannon entropy (>7.2)
inline constexpr int WEIGHT_STATIC_NONTRIVIAL_OVERLAY = 25;// Non-trivial overlay after last section (> 512 bytes)

// Severity Thresholds
inline constexpr int SEV_MIN_CRITICAL = 80;
inline constexpr int SEV_MIN_HIGH = 50;
inline constexpr int SEV_MIN_MEDIUM = 25;
inline constexpr int SEV_MIN_LOW = 10;
