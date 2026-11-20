# ==============================================================================
# Deadeye Makefile for GNU Make / MinGW-w64
# ==============================================================================

CXX ?= g++
WINDRES ?= windres

CXXFLAGS ?= -std=c++17 -m64 -Wall -Wextra -pedantic -Wno-unused-parameter -O2
LDFLAGS ?= -static -static-libgcc -static-libstdc++
INCLUDES = -Isrc -Isrc/resources

# Win32 Libraries
LIBS_DEADEYE = -ladvapi32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32 -ldwmapi
LIBS_BASE = -ladvapi32 -luser32

BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin

SRC_CORE = src/core/behavior.cpp \
           src/core/json_export.cpp \
           src/core/live_source.cpp \
           src/core/memsource.cpp \
           src/core/pattern.cpp \
           src/core/pe_integrity.cpp \
           src/core/pe_source.cpp \
           src/core/snapshot.cpp \
           src/core/timeline.cpp \
           src/core/triage.cpp \
           src/core/util.cpp

SRC_GUI = src/gui/app.cpp \
          src/gui/attach_dialog.cpp \
          src/gui/controls.cpp \
          src/gui/hexview.cpp \
          src/gui/menu.cpp \
          src/gui/pe_integrity_dialog.cpp \
          src/gui/pe_options_dialog.cpp \
          src/gui/search_dialog.cpp \
          src/gui/strings_dialog.cpp \
          src/gui/views.cpp

SRC_DEADEYE = src/main.cpp $(SRC_CORE) $(SRC_GUI)
RC_DEADEYE = src/resources/deadeye.rc
RES_OBJ = $(BUILD_DIR)/deadeye_res.o

TARGET_DEADEYE = $(BIN_DIR)/deadeye.exe
TARGET_TEST_TARGET = $(BIN_DIR)/test_target.exe
TARGET_TEST_TIMELINE = $(BIN_DIR)/test_timeline.exe
TARGET_TEST_DIFF = $(BIN_DIR)/test_diff.exe
TARGET_TEST_PATTERN = $(BIN_DIR)/test_pattern.exe
TARGET_TEST_PE_INTEGRITY = $(BIN_DIR)/test_pe_integrity.exe

# Platform directory management
ifeq ($(OS),Windows_NT)
    MKDIR = if not exist $(subst /,\,$(1)) mkdir $(subst /,\,$(1))
    RMDIR = if exist $(subst /,\,$(1)) rmdir /s /q $(subst /,\,$(1))
else
    MKDIR = mkdir -p $(1)
    RMDIR = rm -rf $(1)
endif

.PHONY: all clean tests check dirs

all: dirs $(TARGET_DEADEYE) $(TARGET_TEST_TARGET)

dirs:
	@$(call MKDIR,$(BUILD_DIR))
	@$(call MKDIR,$(BIN_DIR))

$(RES_OBJ): $(RC_DEADEYE) src/resources/deadeye.manifest src/resources/newdeadeyeicon.ico | dirs
	$(WINDRES) -Isrc/resources -i $(RC_DEADEYE) -O coff -o $(RES_OBJ)

$(TARGET_DEADEYE): $(SRC_DEADEYE) $(RES_OBJ) | dirs
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC_DEADEYE) $(RES_OBJ) -o $@ -mwindows $(LDFLAGS) $(LIBS_DEADEYE)

$(TARGET_TEST_TARGET): tests/test_target.cpp | dirs
	$(CXX) $(CXXFLAGS) $(INCLUDES) tests/test_target.cpp -o $@ $(LDFLAGS) $(LIBS_BASE)

tests: dirs $(TARGET_TEST_TIMELINE) $(TARGET_TEST_DIFF) $(TARGET_TEST_PATTERN) $(TARGET_TEST_PE_INTEGRITY)

$(TARGET_TEST_TIMELINE): tests/test_timeline.cpp src/core/timeline.cpp src/core/util.cpp | dirs
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LIBS_BASE)

$(TARGET_TEST_DIFF): tests/test_diff.cpp src/core/snapshot.cpp src/core/util.cpp src/core/memsource.cpp src/core/pattern.cpp | dirs
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LIBS_BASE)

$(TARGET_TEST_PATTERN): tests/test_pattern.cpp src/core/pattern.cpp src/core/util.cpp src/core/memsource.cpp src/core/snapshot.cpp | dirs
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LIBS_BASE)

$(TARGET_TEST_PE_INTEGRITY): tests/test_pe_integrity.cpp src/core/pe_integrity.cpp src/core/live_source.cpp src/core/util.cpp src/core/timeline.cpp | dirs
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LIBS_BASE)

check: tests
	@echo [RUN] Running test_timeline...
	@$(TARGET_TEST_TIMELINE)
	@echo [RUN] Running test_diff...
	@$(TARGET_TEST_DIFF)
	@echo [RUN] Running test_pattern...
	@$(TARGET_TEST_PATTERN)
	@echo [RUN] Running test_pe_integrity...
	@$(TARGET_TEST_PE_INTEGRITY)
	@echo [SUCCESS] All unit tests passed!

clean:
	@$(call RMDIR,$(BUILD_DIR))
