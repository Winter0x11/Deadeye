// src/core/pe_integrity.cpp
// Deadeye Defensive Triage PE Integrity & Memory Comparison Engine Implementation

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "core/pe_integrity.hpp"
#include "core/live_source.hpp"
#include "core/util.hpp"
#include <Windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>

namespace core {

// Computes SHA-256 hash using native Windows Crypto API (advapi32)
std::string compute_sha256_hex(const uint8_t *data, size_t len)
{
    if (!data || len == 0)
    {
        return "";
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        {
            if (CryptHashData(hHash, data, static_cast<DWORD>(len), 0))
            {
                BYTE hash_bytes[32] = {};
                DWORD hash_len = sizeof(hash_bytes);
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash_bytes, &hash_len, 0))
                {
                    char hex_buf[65] = {};
                    for (DWORD i = 0; i < hash_len; ++i)
                    {
                        std::snprintf(hex_buf + (i * 2), 3, "%02x", hash_bytes[i]);
                    }
                    result = hex_buf;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

std::string format_integrity_category(PeIntegrityCategory cat)
{
    switch (cat)
    {
        case PeIntegrityCategory::ModifiedExecutableCode:    return "Modified Executable Code";
        case PeIntegrityCategory::ModifiedNonExecutableData: return "Modified Non-Executable Data";
        case PeIntegrityCategory::InlineHookCandidate:       return "Inline Hook Candidate";
        case PeIntegrityCategory::ImportAddressTable:        return "Import Address Table (IAT)";
        case PeIntegrityCategory::RelocationResolved:        return "Relocation Resolved (Expected)";
        case PeIntegrityCategory::UnexpectedSection:         return "Unexpected Section";
        case PeIntegrityCategory::MissingSection:            return "Missing Section";
        case PeIntegrityCategory::UnreadableMemory:          return "Unreadable Memory Range";
        case PeIntegrityCategory::ExpectedLoaderModification:return "Expected Loader Modification";
        case PeIntegrityCategory::Unclassified:              return "Unclassified Difference";
        default:                                             return "Unknown";
    }
}

std::string format_integrity_severity(PeIntegritySeverity sev)
{
    switch (sev)
    {
        case PeIntegritySeverity::Critical:      return "Critical";
        case PeIntegritySeverity::Warning:       return "Warning";
        case PeIntegritySeverity::Informational: return "Informational";
        default:                                 return "Unknown";
    }
}

bool enumerate_process_modules(DWORD pid, HANDLE proc, std::vector<LoadedModuleInfo> &out_modules, std::string &out_err)
{
    out_modules.clear();
    out_err.clear();

    if (pid == 0)
    {
        out_err = "Invalid process ID (0).";
        return false;
    }

    // Method 1: Toolhelp32 module snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W me = {};
        me.dwSize = sizeof(me);

        if (Module32FirstW(hSnap, &me))
        {
            bool first = true;
            do
            {
                LoadedModuleInfo mod;
                // Convert WCHAR strings to UTF-8
                char narrow_name[MAX_MODULE_NAME32 + 1] = {};
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, narrow_name, sizeof(narrow_name), nullptr, nullptr);
                mod.module_name = narrow_name;

                char narrow_path[MAX_PATH + 1] = {};
                WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, narrow_path, sizeof(narrow_path), nullptr, nullptr);
                mod.module_path = narrow_path;

                mod.base_address = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                mod.image_size = me.modBaseSize;
                mod.is_main_executable = first;
                first = false;

                out_modules.push_back(mod);
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
    }

    // Method 2: Fallback to PEB traversal if Toolhelp returned empty
    if (out_modules.empty() && proc != nullptr)
    {
        std::vector<LoadedModuleRange> peb_mods;
        bool wow64_unsupported = false;
        if (query_peb_modules_x64(proc, peb_mods, wow64_unsupported) && !peb_mods.empty())
        {
            for (size_t i = 0; i < peb_mods.size(); ++i)
            {
                LoadedModuleInfo mod;
                char narrow_name[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, peb_mods[i].name.c_str(), -1, narrow_name, sizeof(narrow_name), nullptr, nullptr);
                mod.module_name = narrow_name;
                mod.base_address = peb_mods[i].base;
                mod.image_size = static_cast<uint32_t>(peb_mods[i].size);
                mod.is_main_executable = (i == 0);
                resolve_disk_module_path(mod, mod.module_path);
                out_modules.push_back(mod);
            }
        }
    }

    if (out_modules.empty())
    {
        out_err = "Unable to enumerate process modules (access denied or incompatible architecture).";
        return false;
    }

    return true;
}

bool resolve_disk_module_path(const LoadedModuleInfo &mod, std::string &out_disk_path)
{
    out_disk_path.clear();

    // 1. Direct path check
    if (!mod.module_path.empty())
    {
        DWORD attrs = GetFileAttributesA(mod.module_path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            out_disk_path = mod.module_path;
            return true;
        }
    }

    if (mod.module_name.empty())
    {
        return false;
    }

    // 2. Search System32, SysWOW64, and Windows root
    char sys_dir[MAX_PATH] = {};
    if (GetSystemDirectoryA(sys_dir, MAX_PATH))
    {
        std::string test_path = std::string(sys_dir) + "\\" + mod.module_name;
        if (GetFileAttributesA(test_path.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            out_disk_path = test_path;
            return true;
        }
    }

    char win_dir[MAX_PATH] = {};
    if (GetWindowsDirectoryA(win_dir, MAX_PATH))
    {
        std::string test_path = std::string(win_dir) + "\\SysWOW64\\" + mod.module_name;
        if (GetFileAttributesA(test_path.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            out_disk_path = test_path;
            return true;
        }

        test_path = std::string(win_dir) + "\\" + mod.module_name;
        if (GetFileAttributesA(test_path.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            out_disk_path = test_path;
            return true;
        }
    }

    // 3. SearchPath API
    char found_buf[MAX_PATH] = {};
    if (SearchPathA(nullptr, mod.module_name.c_str(), nullptr, MAX_PATH, found_buf, nullptr) > 0)
    {
        out_disk_path = found_buf;
        return true;
    }

    return false;
}

// Internal representation of parsed PE structures
struct InternalPeMetadata
{
    bool is_valid = false;
    bool is_64 = false;
    uint16_t machine = 0;
    uint32_t timedatestamp = 0;
    uintptr_t preferred_image_base = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t entry_point_rva = 0;
    uint16_t number_of_sections = 0;

    std::vector<IMAGE_SECTION_HEADER> sections;
    IMAGE_DATA_DIRECTORY data_dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {};

    std::vector<PeExportSymbol> exports;
    std::vector<PeImportEntry> imports;

    // Relocation fixup RVAs mapped to fixup length (4 for HIGHLOW, 8 for DIR64)
    struct RelocFixup
    {
        uint32_t rva = 0;
        uint8_t size = 0;
    };
    std::vector<RelocFixup> relocations;

    // Raw file bytes
    std::vector<uint8_t> raw_bytes;
};

static bool parse_pe_image_buffer(
    const uint8_t *data,
    size_t size,
    InternalPeMetadata &out_meta,
    std::string &out_err)
{
    out_err.clear();
    out_meta = InternalPeMetadata{};

    if (!data || size < sizeof(IMAGE_DOS_HEADER))
    {
        out_err = "Buffer too small for DOS header.";
        return false;
    }

    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        out_err = "Invalid DOS header signature (not MZ).";
        return false;
    }

    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > size)
    {
        out_err = "Invalid e_lfanew offset in DOS header.";
        return false;
    }

    size_t nt_offset = static_cast<size_t>(dos->e_lfanew);
    DWORD nt_sig = 0;
    std::memcpy(&nt_sig, data + nt_offset, sizeof(DWORD));
    if (nt_sig != IMAGE_NT_SIGNATURE)
    {
        out_err = "Invalid NT header signature (not PE\\0\\0).";
        return false;
    }

    const auto *file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(data + nt_offset + sizeof(DWORD));
    out_meta.machine = file_hdr->Machine;
    out_meta.timedatestamp = file_hdr->TimeDateStamp;
    out_meta.number_of_sections = file_hdr->NumberOfSections;

    size_t opt_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (opt_offset + file_hdr->SizeOfOptionalHeader > size || file_hdr->SizeOfOptionalHeader < sizeof(WORD))
    {
        out_err = "Optional header extends past end of file.";
        return false;
    }

    uint16_t opt_magic = 0;
    std::memcpy(&opt_magic, data + opt_offset, sizeof(WORD));

    if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        out_meta.is_64 = true;
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
        {
            out_err = "SizeOfOptionalHeader too small for 64-bit PE.";
            return false;
        }
        const auto *opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_offset);
        out_meta.preferred_image_base = static_cast<uintptr_t>(opt64->ImageBase);
        out_meta.section_alignment = opt64->SectionAlignment;
        out_meta.file_alignment = opt64->FileAlignment;
        out_meta.size_of_image = opt64->SizeOfImage;
        out_meta.size_of_headers = opt64->SizeOfHeaders;
        out_meta.entry_point_rva = opt64->AddressOfEntryPoint;

        DWORD dirs_to_copy = std::min<DWORD>(opt64->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (DWORD i = 0; i < dirs_to_copy; ++i)
        {
            out_meta.data_dirs[i] = opt64->DataDirectory[i];
        }
    }
    else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        out_meta.is_64 = false;
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
        {
            out_err = "SizeOfOptionalHeader too small for 32-bit PE.";
            return false;
        }
        const auto *opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_offset);
        out_meta.preferred_image_base = static_cast<uintptr_t>(opt32->ImageBase);
        out_meta.section_alignment = opt32->SectionAlignment;
        out_meta.file_alignment = opt32->FileAlignment;
        out_meta.size_of_image = opt32->SizeOfImage;
        out_meta.size_of_headers = opt32->SizeOfHeaders;
        out_meta.entry_point_rva = opt32->AddressOfEntryPoint;

        DWORD dirs_to_copy = std::min<DWORD>(opt32->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (DWORD i = 0; i < dirs_to_copy; ++i)
        {
            out_meta.data_dirs[i] = opt32->DataDirectory[i];
        }
    }
    else
    {
        out_err = "Unsupported optional header magic.";
        return false;
    }

    if (out_meta.section_alignment == 0)
    {
        out_meta.section_alignment = 0x1000;
    }

    // Parse section headers
    size_t sec_offset = opt_offset + file_hdr->SizeOfOptionalHeader;
    for (WORD i = 0; i < file_hdr->NumberOfSections; ++i)
    {
        if (sec_offset + sizeof(IMAGE_SECTION_HEADER) > size)
        {
            break;
        }
        IMAGE_SECTION_HEADER sec = {};
        std::memcpy(&sec, data + sec_offset, sizeof(IMAGE_SECTION_HEADER));
        out_meta.sections.push_back(sec);
        sec_offset += sizeof(IMAGE_SECTION_HEADER);
    }

    // Helper lambda to map RVA to raw file pointer
    auto rva_to_file_offset = [&](uint32_t rva) -> size_t {
        for (const auto &sec : out_meta.sections)
        {
            uint32_t vsize = (sec.Misc.VirtualSize != 0) ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + vsize)
            {
                uint32_t off = rva - sec.VirtualAddress;
                if (off < sec.SizeOfRawData && static_cast<size_t>(sec.PointerToRawData) + off < size)
                {
                    return static_cast<size_t>(sec.PointerToRawData) + off;
                }
            }
        }
        if (rva < out_meta.size_of_headers && rva < size)
        {
            return rva;
        }
        return SIZE_MAX;
    };

    // Parse Exports
    const auto &exp_dir = out_meta.data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress != 0 && exp_dir.Size >= sizeof(IMAGE_EXPORT_DIRECTORY))
    {
        size_t exp_file_off = rva_to_file_offset(exp_dir.VirtualAddress);
        if (exp_file_off != SIZE_MAX && exp_file_off + sizeof(IMAGE_EXPORT_DIRECTORY) <= size)
        {
            const auto *ied = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(data + exp_file_off);
            size_t func_off = rva_to_file_offset(ied->AddressOfFunctions);
            size_t name_off = rva_to_file_offset(ied->AddressOfNames);
            size_t ord_off = rva_to_file_offset(ied->AddressOfNameOrdinals);

            if (func_off != SIZE_MAX && name_off != SIZE_MAX && ord_off != SIZE_MAX &&
                ied->NumberOfNames > 0 && ied->NumberOfNames < 65536)
            {
                const auto *funcs = reinterpret_cast<const uint32_t*>(data + func_off);
                const auto *names = reinterpret_cast<const uint32_t*>(data + name_off);
                const auto *ordinals = reinterpret_cast<const uint16_t*>(data + ord_off);

                for (DWORD i = 0; i < ied->NumberOfNames; ++i)
                {
                    if (func_off + (ordinals[i] * sizeof(uint32_t)) > size ||
                        name_off + (i * sizeof(uint32_t)) > size)
                    {
                        break;
                    }
                    size_t str_off = rva_to_file_offset(names[i]);
                    if (str_off != SIZE_MAX && str_off < size)
                    {
                        const char *s = reinterpret_cast<const char*>(data + str_off);
                        // Safe bound-checked strlen
                        size_t max_s = std::min<size_t>(256, size - str_off);
                        size_t s_len = 0;
                        while (s_len < max_s && s[s_len] != '\0') s_len++;

                        if (s_len > 0 && ordinals[i] < ied->NumberOfFunctions)
                        {
                            PeExportSymbol sym;
                            sym.name = std::string(s, s_len);
                            sym.ordinal = static_cast<uint16_t>(ied->Base + ordinals[i]);
                            sym.rva = funcs[ordinals[i]];
                            sym.is_forwarder = (sym.rva >= exp_dir.VirtualAddress &&
                                                sym.rva < exp_dir.VirtualAddress + exp_dir.Size);
                            out_meta.exports.push_back(sym);
                        }
                    }
                }
            }
        }
    }

    // Parse Relocations
    const auto &reloc_dir = out_meta.data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size >= sizeof(IMAGE_BASE_RELOCATION))
    {
        size_t reloc_file_off = rva_to_file_offset(reloc_dir.VirtualAddress);
        if (reloc_file_off != SIZE_MAX && reloc_file_off + reloc_dir.Size <= size)
        {
            size_t cursor = 0;
            while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= reloc_dir.Size)
            {
                const auto *block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(data + reloc_file_off + cursor);
                if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block->SizeOfBlock > (reloc_dir.Size - cursor))
                {
                    break;
                }

                uint32_t page_rva = block->VirtualAddress;
                size_t entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                const auto *entries = reinterpret_cast<const uint16_t*>(data + reloc_file_off + cursor + sizeof(IMAGE_BASE_RELOCATION));

                for (size_t k = 0; k < entry_count; ++k)
                {
                    uint16_t entry = entries[k];
                    uint16_t type = (entry >> 12);
                    uint16_t offset = (entry & 0x0FFF);

                    if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        out_meta.relocations.push_back({page_rva + offset, 4});
                    }
                    else if (type == IMAGE_REL_BASED_DIR64)
                    {
                        out_meta.relocations.push_back({page_rva + offset, 8});
                    }
                }

                cursor += block->SizeOfBlock;
            }
        }
    }

    // Parse Imports
    const auto &imp_dir = out_meta.data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress != 0 && imp_dir.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
        size_t imp_file_off = rva_to_file_offset(imp_dir.VirtualAddress);
        if (imp_file_off != SIZE_MAX && imp_file_off + imp_dir.Size <= size)
        {
            size_t desc_idx = 0;
            while (imp_file_off + (desc_idx + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) <= size)
            {
                const auto *desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(data + imp_file_off + (desc_idx * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
                if (desc->Characteristics == 0 && desc->FirstThunk == 0)
                {
                    break;
                }

                std::string dll_name;
                size_t dll_name_off = rva_to_file_offset(desc->Name);
                if (dll_name_off != SIZE_MAX && dll_name_off < size)
                {
                    const char *p = reinterpret_cast<const char*>(data + dll_name_off);
                    size_t max_l = std::min<size_t>(256, size - dll_name_off);
                    size_t l = 0;
                    while (l < max_l && p[l] != '\0') l++;
                    dll_name = std::string(p, l);
                }

                uint32_t thunk_rva = desc->FirstThunk;
                uint32_t ilt_rva = (desc->OriginalFirstThunk != 0) ? desc->OriginalFirstThunk : desc->FirstThunk;
                size_t thunk_off = rva_to_file_offset(thunk_rva);
                size_t ilt_off = rva_to_file_offset(ilt_rva);

                if (thunk_off != SIZE_MAX && ilt_off != SIZE_MAX)
                {
                    size_t ptr_size = out_meta.is_64 ? 8 : 4;
                    size_t entry_idx = 0;

                    while (thunk_off + ((entry_idx + 1) * ptr_size) <= size &&
                           ilt_off + ((entry_idx + 1) * ptr_size) <= size)
                    {
                        uint64_t ilt_val = 0;
                        uint64_t thunk_val = 0;
                        if (out_meta.is_64)
                        {
                            std::memcpy(&ilt_val, data + ilt_off + (entry_idx * 8), 8);
                            std::memcpy(&thunk_val, data + thunk_off + (entry_idx * 8), 8);
                        }
                        else
                        {
                            uint32_t v32_ilt = 0, v32_thk = 0;
                            std::memcpy(&v32_ilt, data + ilt_off + (entry_idx * 4), 4);
                            std::memcpy(&v32_thk, data + thunk_off + (entry_idx * 4), 4);
                            ilt_val = v32_ilt;
                            thunk_val = v32_thk;
                        }

                        if (ilt_val == 0)
                        {
                            break;
                        }

                        PeImportEntry imp;
                        imp.dll_name = dll_name;
                        imp.iat_rva = thunk_rva + static_cast<uint32_t>(entry_idx * ptr_size);
                        imp.ilt_rva = ilt_rva + static_cast<uint32_t>(entry_idx * ptr_size);
                        imp.disk_value = static_cast<uintptr_t>(thunk_val);

                        uint64_t ord_flag = out_meta.is_64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
                        if (ilt_val & ord_flag)
                        {
                            imp.ordinal = static_cast<uint16_t>(ilt_val & 0xFFFF);
                            imp.function_name = "Ordinal#" + std::to_string(imp.ordinal);
                        }
                        else
                        {
                            uint32_t ibn_rva = static_cast<uint32_t>(ilt_val & 0x7FFFFFFF);
                            size_t ibn_off = rva_to_file_offset(ibn_rva);
                            if (ibn_off != SIZE_MAX && ibn_off + sizeof(WORD) < size)
                            {
                                const char *fn = reinterpret_cast<const char*>(data + ibn_off + sizeof(WORD));
                                size_t max_f = std::min<size_t>(256, size - (ibn_off + sizeof(WORD)));
                                size_t flen = 0;
                                while (flen < max_f && fn[flen] != '\0') flen++;
                                imp.function_name = std::string(fn, flen);
                            }
                        }

                        out_meta.imports.push_back(imp);
                        entry_idx++;
                    }
                }
                desc_idx++;
            }
        }
    }

    out_meta.is_valid = true;
    return true;
}

bool verify_pe_module_match(const std::string &disk_path, HANDLE proc, uintptr_t live_base, std::string &out_err)
{
    out_err.clear();

    std::ifstream file(disk_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        out_err = "Cannot open on-disk PE image: " + disk_path;
        return false;
    }

    size_t fsize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (fsize < sizeof(IMAGE_DOS_HEADER) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
    {
        out_err = "On-disk file is too small to be a valid PE executable.";
        return false;
    }

    std::vector<uint8_t> header_bytes(std::min<size_t>(fsize, 4096));
    file.read(reinterpret_cast<char*>(header_bytes.data()), header_bytes.size());

    InternalPeMetadata disk_meta;
    if (!parse_pe_image_buffer(header_bytes.data(), header_bytes.size(), disk_meta, out_err))
    {
        return false;
    }

    if (proc == nullptr || live_base == 0)
    {
        return true;
    }

    // Read live memory headers
    std::vector<uint8_t> live_hdr(4096, 0);
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(live_base), live_hdr.data(), live_hdr.size(), &bytes_read) ||
        bytes_read < sizeof(IMAGE_DOS_HEADER) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
    {
        out_err = "Target process module at 0x" + to_hex_string(live_base) + " is unreadable (access denied or uncommitted).";
        return false;
    }

    InternalPeMetadata live_meta;
    std::string live_err;
    if (!parse_pe_image_buffer(live_hdr.data(), bytes_read, live_meta, live_err))
    {
        // Live headers might be zeroed (header stomping). That is a suspicious finding rather than fatal rejection.
        return true;
    }

    if (disk_meta.machine != live_meta.machine)
    {
        out_err = "Architecture mismatch: On-disk machine type (0x" + to_hex_string(disk_meta.machine) +
                  ") does not match live module machine type (0x" + to_hex_string(live_meta.machine) + ").";
        return false;
    }

    return true;
}

// Disassembles common x86/x64 redirect instructions
static bool inspect_inline_hook_instruction(
    const uint8_t *code,
    size_t code_len,
    uintptr_t cur_vaddr,
    uintptr_t module_base,
    uint32_t module_size,
    HANDLE proc,
    uintptr_t &out_target_addr,
    std::string &out_desc)
{
    out_target_addr = 0;
    out_desc.clear();

    if (!code || code_len < 2)
    {
        return false;
    }

    // 1. E9 [rel32]: JMP rel32 (5 bytes)
    if (code[0] == 0xE9 && code_len >= 5)
    {
        int32_t rel = 0;
        std::memcpy(&rel, code + 1, sizeof(int32_t));
        uintptr_t target = cur_vaddr + 5 + rel;
        if (target < module_base || target >= module_base + module_size)
        {
            out_target_addr = target;
            out_desc = "JMP rel32 (0xE9) -> 0x" + to_hex_string(target);
            return true;
        }
    }

    // 2. FF 25 [disp32]: JMP [rip + disp32] on x64, or JMP [imm32] on x86
    if (code[0] == 0xFF && code[1] == 0x25 && code_len >= 6)
    {
        int32_t disp = 0;
        std::memcpy(&disp, code + 2, sizeof(int32_t));
        uintptr_t ptr_addr = cur_vaddr + 6 + disp;

        uintptr_t deref_target = 0;
        SIZE_T read_len = 0;
        if (proc != nullptr && ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(ptr_addr), &deref_target, sizeof(uintptr_t), &read_len) &&
            read_len == sizeof(uintptr_t))
        {
            if (deref_target < module_base || deref_target >= module_base + module_size)
            {
                out_target_addr = deref_target;
                out_desc = "JMP QWORD PTR [rip+" + std::to_string(disp) + "] (0xFF 0x25) -> 0x" + to_hex_string(deref_target);
                return true;
            }
        }
        else
        {
            // Even if unresolvable deref, target is an external pointer table
            out_target_addr = ptr_addr;
            out_desc = "JMP QWORD PTR [0x" + to_hex_string(ptr_addr) + "] (0xFF 0x25)";
            return true;
        }
    }

    // 3. 48 B8 [imm64]; FF E0: MOV RAX, imm64; JMP RAX (12 bytes)
    if (code_len >= 12 && code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0)
    {
        uint64_t target = 0;
        std::memcpy(&target, code + 2, sizeof(uint64_t));
        if (target < module_base || target >= module_base + module_size)
        {
            out_target_addr = static_cast<uintptr_t>(target);
            out_desc = "MOV RAX, imm64; JMP RAX -> 0x" + to_hex_string(out_target_addr);
            return true;
        }
    }

    // 4. 49 BA [imm64]; 41 FF E2: MOV R10, imm64; JMP R10 (13 bytes)
    if (code_len >= 13 && code[0] == 0x49 && code[1] == 0xBA && code[10] == 0x41 && code[11] == 0xFF && code[12] == 0xE2)
    {
        uint64_t target = 0;
        std::memcpy(&target, code + 2, sizeof(uint64_t));
        if (target < module_base || target >= module_base + module_size)
        {
            out_target_addr = static_cast<uintptr_t>(target);
            out_desc = "MOV R10, imm64; JMP R10 -> 0x" + to_hex_string(out_target_addr);
            return true;
        }
    }

    // 5. 68 [imm32]; C3: PUSH imm32; RET (6 bytes on x86)
    if (code_len >= 6 && code[0] == 0x68 && code[5] == 0xC3)
    {
        uint32_t target32 = 0;
        std::memcpy(&target32, code + 1, sizeof(uint32_t));
        uintptr_t target = target32;
        if (target < module_base || target >= module_base + module_size)
        {
            out_target_addr = target;
            out_desc = "PUSH imm32; RET (0x68 ... 0xC3) -> 0x" + to_hex_string(target);
            return true;
        }
    }

    // 6. 48 B8 [imm64]; 50; C3: MOV RAX, imm64; PUSH RAX; RET (12 bytes)
    if (code_len >= 12 && code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0x50 && code[11] == 0xC3)
    {
        uint64_t target = 0;
        std::memcpy(&target, code + 2, sizeof(uint64_t));
        if (target < module_base || target >= module_base + module_size)
        {
            out_target_addr = static_cast<uintptr_t>(target);
            out_desc = "MOV RAX, imm64; PUSH RAX; RET -> 0x" + to_hex_string(out_target_addr);
            return true;
        }
    }

    // 7. E8 [rel32]: CALL rel32 (5 bytes)
    if (code[0] == 0xE8 && code_len >= 5)
    {
        int32_t rel = 0;
        std::memcpy(&rel, code + 1, sizeof(int32_t));
        uintptr_t target = cur_vaddr + 5 + rel;
        if (target < module_base || target >= module_base + module_size)
        {
            out_target_addr = target;
            out_desc = "CALL rel32 (0xE8) -> 0x" + to_hex_string(target);
            return true;
        }
    }

    return false;
}

static std::string resolve_address_module_name(uintptr_t addr, const std::vector<LoadedModuleInfo> *modules)
{
    if (!modules || addr == 0)
    {
        return "[Unbacked / Unknown Memory]";
    }

    for (const auto &m : *modules)
    {
        if (addr >= m.base_address && addr < m.base_address + m.image_size)
        {
            return m.module_name;
        }
    }
    return "[Unbacked / Private Memory]";
}

// Core unified PE integrity comparison algorithm
static bool execute_pe_integrity_compare_core(
    const uint8_t *disk_bytes,
    size_t disk_size,
    const std::string &disk_file_path,
    uintptr_t live_base,
    DWORD target_pid,
    HANDLE proc,
    std::shared_ptr<MemorySource> memory_source,
    const PeIntegrityOptions &options,
    PeIntegrityReport &out_report,
    std::string &out_err,
    std::atomic<bool> *abort_flag,
    std::function<void(float progress, const std::string &status)> progress_cb,
    const std::vector<LoadedModuleInfo> *all_modules)
{
    out_err.clear();
    out_report = PeIntegrityReport{};
    out_report.target_pid = target_pid;
    out_report.comparison_timestamp = static_cast<uint64_t>(GetTickCount64());

    InternalPeMetadata pe;
    if (!parse_pe_image_buffer(disk_bytes, disk_size, pe, out_err))
    {
        return false;
    }

    // Populate metadata
    out_report.metadata.disk_file_path = disk_file_path;
    size_t last_slash = disk_file_path.find_last_of("\\/");
    out_report.metadata.module_name = (last_slash != std::string::npos) ? disk_file_path.substr(last_slash + 1) : disk_file_path;
    out_report.metadata.live_base_address = live_base;
    out_report.metadata.preferred_base_address = (options.preferred_base_override != 0) ? options.preferred_base_override : pe.preferred_image_base;
    out_report.metadata.image_size = pe.size_of_image;
    out_report.metadata.architecture = pe.is_64 ? "x64" : "x86";
    out_report.metadata.machine = pe.machine;
    out_report.metadata.timedatestamp = pe.timedatestamp;
    out_report.metadata.section_count = pe.sections.size();
    out_report.metadata.exports_count = pe.exports.size();
    out_report.metadata.imports_count = pe.imports.size();
    out_report.metadata.disk_sha256 = compute_sha256_hex(disk_bytes, disk_size);

    int64_t reloc_delta = static_cast<int64_t>(live_base) - static_cast<int64_t>(out_report.metadata.preferred_base_address);

    // Fast lookup for relocation sites
    std::vector<InternalPeMetadata::RelocFixup> relocs = pe.relocations;
    std::sort(relocs.begin(), relocs.end(), [](const InternalPeMetadata::RelocFixup &a, const InternalPeMetadata::RelocFixup &b) {
        return a.rva < b.rva;
    });

    // Fast lookup for IAT entries
    std::vector<PeImportEntry> imports = pe.imports;
    std::sort(imports.begin(), imports.end(), [](const PeImportEntry &a, const PeImportEntry &b) {
        return a.iat_rva < b.iat_rva;
    });

    // Fast lookup for nearest exports
    std::vector<PeExportSymbol> exports = pe.exports;
    std::sort(exports.begin(), exports.end(), [](const PeExportSymbol &a, const PeExportSymbol &b) {
        return a.rva < b.rva;
    });

    auto find_nearest_export = [&](uint32_t rva) -> std::pair<std::string, int32_t> {
        if (exports.empty()) return {"", 0};
        auto it = std::upper_bound(exports.begin(), exports.end(), rva, [](uint32_t val, const PeExportSymbol &sym) {
            return val < sym.rva;
        });
        if (it != exports.begin())
        {
            --it;
            int32_t dist = static_cast<int32_t>(rva - it->rva);
            if (dist >= 0 && dist < 128)
            {
                return {it->name, dist};
            }
        }
        return {"", 0};
    };

    // Helper to read memory safely
    auto read_live_memory = [&](uintptr_t addr, uint8_t *dest, size_t len) -> size_t {
        if (proc != nullptr)
        {
            SIZE_T br = 0;
            if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), dest, len, &br))
            {
                return br;
            }
            return 0;
        }
        else if (memory_source != nullptr)
        {
            return memory_source->read(addr, len, dest);
        }
        return 0;
    };

    std::vector<RegionInfo> cached_source_regions;
    bool has_cached_source_regions = false;
    if (memory_source != nullptr)
    {
        std::string reg_err;
        if (memory_source->query_regions(cached_source_regions, reg_err))
        {
            has_cached_source_regions = true;
        }
    }

    auto is_address_mapped = [&](uintptr_t addr) -> bool {
        if (proc != nullptr)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != 0)
            {
                return (mbi.State != MEM_FREE);
            }
            return false;
        }
        else if (has_cached_source_regions)
        {
            for (const auto &reg : cached_source_regions)
            {
                if (addr >= reg.base && addr < reg.base + reg.size)
                {
                    return true;
                }
            }
            return false;
        }
        return true;
    };

    size_t total_sections = pe.sections.size() + 1; // +1 for Headers
    size_t section_idx = 0;

    // 1. Compare Headers Segment
    {
        uint32_t hdr_size = std::min<uint32_t>(pe.size_of_headers, static_cast<uint32_t>(disk_size));
        if (hdr_size > 0)
        {
            std::vector<uint8_t> live_hdr(hdr_size, 0);
            size_t br = read_live_memory(live_base, live_hdr.data(), hdr_size);
            out_report.total_compared_bytes += hdr_size;

            if (br < hdr_size)
            {
                out_report.total_unreadable_bytes += (hdr_size - br);
                PeIntegrityDifference diff;
                diff.category = PeIntegrityCategory::UnreadableMemory;
                diff.severity = PeIntegritySeverity::Warning;
                diff.section_name = "Headers";
                diff.virtual_address = live_base + br;
                diff.rva = static_cast<uint32_t>(br);
                diff.file_offset = br;
                diff.length = hdr_size - br;
                diff.explanation = "PE Headers in live memory were partially unreadable.";
                out_report.differences.push_back(diff);
            }

            // Compare readable header portion
            size_t comp_len = br;
            size_t chg_start = SIZE_MAX;
            for (size_t i = 0; i < comp_len; ++i)
            {
                if (disk_bytes[i] != live_hdr[i])
                {
                    if (chg_start == SIZE_MAX) chg_start = i;
                }
                else
                {
                    if (chg_start != SIZE_MAX)
                    {
                        size_t diff_len = i - chg_start;
                        out_report.total_changed_bytes += diff_len;
                        PeIntegrityDifference diff;
                        diff.category = PeIntegrityCategory::ExpectedLoaderModification;
                        diff.severity = PeIntegritySeverity::Informational;
                        diff.is_expected = true;
                        diff.section_name = "Headers";
                        diff.virtual_address = live_base + chg_start;
                        diff.rva = static_cast<uint32_t>(chg_start);
                        diff.file_offset = chg_start;
                        diff.length = diff_len;
                        diff.disk_bytes.assign(disk_bytes + chg_start, disk_bytes + chg_start + std::min<size_t>(diff_len, 64));
                        diff.live_bytes.assign(live_hdr.data() + chg_start, live_hdr.data() + chg_start + std::min<size_t>(diff_len, 64));
                        diff.explanation = "Header modification (typical for loader metadata or timestamp updates).";
                        out_report.differences.push_back(diff);
                        chg_start = SIZE_MAX;
                    }
                }
            }
            if (chg_start != SIZE_MAX)
            {
                size_t diff_len = comp_len - chg_start;
                out_report.total_changed_bytes += diff_len;
                PeIntegrityDifference diff;
                diff.category = PeIntegrityCategory::ExpectedLoaderModification;
                diff.severity = PeIntegritySeverity::Informational;
                diff.is_expected = true;
                diff.section_name = "Headers";
                diff.virtual_address = live_base + chg_start;
                diff.rva = static_cast<uint32_t>(chg_start);
                diff.file_offset = chg_start;
                diff.length = diff_len;
                diff.disk_bytes.assign(disk_bytes + chg_start, disk_bytes + chg_start + std::min<size_t>(diff_len, 64));
                diff.live_bytes.assign(live_hdr.data() + chg_start, live_hdr.data() + chg_start + std::min<size_t>(diff_len, 64));
                diff.explanation = "Header modification at end of header segment.";
                out_report.differences.push_back(diff);
            }

            // Check for unexpected sections in memory header
            if (br >= sizeof(IMAGE_DOS_HEADER))
            {
                const auto *live_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(live_hdr.data());
                if (live_dos->e_magic == IMAGE_DOS_SIGNATURE && live_dos->e_lfanew > 0 &&
                    static_cast<size_t>(live_dos->e_lfanew) + 0x18 < br)
                {
                    size_t l_nt = static_cast<size_t>(live_dos->e_lfanew);
                    DWORD l_sig = *reinterpret_cast<const DWORD*>(live_hdr.data() + l_nt);
                    if (l_sig == IMAGE_NT_SIGNATURE)
                    {
                        const auto *l_file = reinterpret_cast<const IMAGE_FILE_HEADER*>(live_hdr.data() + l_nt + 4);
                        size_t l_opt = l_nt + 4 + sizeof(IMAGE_FILE_HEADER);
                        size_t l_sec_off = l_opt + l_file->SizeOfOptionalHeader;
                        for (WORD si = 0; si < l_file->NumberOfSections; ++si)
                        {
                            if (l_sec_off + sizeof(IMAGE_SECTION_HEADER) <= br)
                            {
                                const auto *l_sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(live_hdr.data() + l_sec_off);
                                char l_name[9] = {};
                                std::memcpy(l_name, l_sec->Name, 8);
                                bool found_on_disk = false;
                                for (const auto &d_sec : pe.sections)
                                {
                                    char d_name[9] = {};
                                    std::memcpy(d_name, d_sec.Name, 8);
                                    if (std::strcmp(l_name, d_name) == 0 && l_sec->VirtualAddress == d_sec.VirtualAddress)
                                    {
                                        found_on_disk = true;
                                        break;
                                    }
                                }
                                if (!found_on_disk)
                                {
                                    PeIntegrityDifference diff;
                                    diff.category = PeIntegrityCategory::UnexpectedSection;
                                    diff.severity = PeIntegritySeverity::Warning;
                                    diff.section_name = l_name;
                                    diff.virtual_address = live_base + l_sec->VirtualAddress;
                                    diff.rva = l_sec->VirtualAddress;
                                    diff.length = l_sec->Misc.VirtualSize;
                                    diff.explanation = "Section present in live memory PE header but not found in on-disk image headers.";
                                    out_report.differences.push_back(diff);
                                }
                                l_sec_off += sizeof(IMAGE_SECTION_HEADER);
                            }
                        }
                    }
                }
            }
        }
    }
    section_idx++;

    // 2. Compare Each Section
    for (const auto &sec : pe.sections)
    {
        if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
        {
            out_report.is_incomplete = true;
            out_report.warnings.push_back("Comparison aborted by user request.");
            break;
        }

        char sec_name[9] = {};
        std::memcpy(sec_name, sec.Name, 8);
        std::string sname = sec_name;

        if (progress_cb != nullptr)
        {
            float pct = static_cast<float>(section_idx) / static_cast<float>(total_sections);
            progress_cb(pct, "Comparing section " + sname + "...");
        }

        uintptr_t sec_vaddr = live_base + sec.VirtualAddress;
        uint32_t virt_size = (sec.Misc.VirtualSize != 0) ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        uint32_t raw_size = sec.SizeOfRawData;
        uint32_t file_ptr = sec.PointerToRawData;
        bool is_executable = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        uint32_t compare_bytes = std::min<uint32_t>(raw_size, virt_size);
        if (file_ptr + compare_bytes > disk_size)
        {
            compare_bytes = (file_ptr < disk_size) ? static_cast<uint32_t>(disk_size - file_ptr) : 0;
        }

        // Compare raw section content chunk by chunk
        const size_t CHUNK_SIZE = options.chunk_size ? options.chunk_size : (64 * 1024);
        size_t processed_in_sec = 0;

        while (processed_in_sec < compare_bytes)
        {
            if (abort_flag != nullptr && abort_flag->load(std::memory_order_relaxed))
            {
                out_report.is_incomplete = true;
                break;
            }

            size_t to_read = std::min<size_t>(CHUNK_SIZE, compare_bytes - processed_in_sec);
            uintptr_t chunk_vaddr = sec_vaddr + processed_in_sec;
            size_t chunk_file_off = file_ptr + processed_in_sec;
            uint32_t chunk_rva = sec.VirtualAddress + static_cast<uint32_t>(processed_in_sec);

            std::vector<uint8_t> live_chunk(to_read, 0);
            size_t br = read_live_memory(chunk_vaddr, live_chunk.data(), to_read);
            out_report.total_compared_bytes += to_read;

            if (br < to_read)
            {
                out_report.is_incomplete = true;
                bool mapped = is_address_mapped(chunk_vaddr);
                if (!mapped)
                {
                    // Section is unmapped or missing from virtual memory
                    out_report.total_unreadable_bytes += (compare_bytes - processed_in_sec);
                    PeIntegrityDifference diff;
                    diff.category = PeIntegrityCategory::MissingSection;
                    diff.severity = PeIntegritySeverity::Warning;
                    diff.section_name = sname;
                    diff.virtual_address = sec_vaddr;
                    diff.rva = sec.VirtualAddress;
                    diff.file_offset = file_ptr;
                    diff.length = virt_size;
                    diff.explanation = "Section present in on-disk PE headers is missing or unmapped in process virtual memory.";
                    out_report.differences.push_back(diff);
                    break;
                }
                else
                {
                    // Unreadable page range
                    size_t unreadable_len = to_read - br;
                    out_report.total_unreadable_bytes += unreadable_len;
                    PeIntegrityDifference diff;
                    diff.category = PeIntegrityCategory::UnreadableMemory;
                    diff.severity = PeIntegritySeverity::Warning;
                    diff.section_name = sname;
                    diff.virtual_address = chunk_vaddr + br;
                    diff.rva = chunk_rva + static_cast<uint32_t>(br);
                    diff.file_offset = chunk_file_off + br;
                    diff.length = unreadable_len;
                    diff.explanation = "Page memory unreadable via ReadProcessMemory (PAGE_NOACCESS or uncommitted).";
                    out_report.differences.push_back(diff);
                }
            }

            // Byte by byte diff scan within the readable chunk
            size_t k = 0;
            while (k < br)
            {
                uint32_t cur_rva = chunk_rva + static_cast<uint32_t>(k);
                uintptr_t cur_vaddr = chunk_vaddr + k;
                size_t cur_file_off = chunk_file_off + k;

                // A. Check if current location is a base relocation site
                auto rel_it = std::lower_bound(relocs.begin(), relocs.end(), cur_rva, [](const InternalPeMetadata::RelocFixup &fix, uint32_t rva) {
                    return fix.rva < rva;
                });

                if (rel_it != relocs.end() && rel_it->rva == cur_rva)
                {
                    uint8_t fix_size = rel_it->size;
                    if (k + fix_size <= br && cur_file_off + fix_size <= disk_size)
                    {
                        bool is_match = true;
                        if (fix_size == 8 && pe.is_64)
                        {
                            uint64_t disk_val = 0;
                            uint64_t live_val = 0;
                            std::memcpy(&disk_val, disk_bytes + cur_file_off, 8);
                            std::memcpy(&live_val, live_chunk.data() + k, 8);
                            uint64_t expected_val = static_cast<uint64_t>(static_cast<int64_t>(disk_val) + reloc_delta);

                            if (live_val == expected_val)
                            {
                                out_report.total_ignored_expected_bytes += 8;
                                out_report.count_reloc_diffs++;
                                if (options.include_expected_differences)
                                {
                                    PeIntegrityDifference diff;
                                    diff.category = PeIntegrityCategory::RelocationResolved;
                                    diff.severity = PeIntegritySeverity::Informational;
                                    diff.is_expected = true;
                                    diff.section_name = sname;
                                    diff.virtual_address = cur_vaddr;
                                    diff.rva = cur_rva;
                                    diff.file_offset = cur_file_off;
                                    diff.length = 8;
                                    diff.disk_bytes.assign(disk_bytes + cur_file_off, disk_bytes + cur_file_off + 8);
                                    diff.live_bytes.assign(live_chunk.data() + k, live_chunk.data() + k + 8);
                                    diff.explanation = "Legitimate loader base relocation (DIR64). Disk: 0x" + to_hex_string(disk_val) +
                                                      " + Delta 0x" + to_hex_string(static_cast<uintptr_t>(reloc_delta)) +
                                                      " = 0x" + to_hex_string(live_val);
                                    out_report.differences.push_back(diff);
                                }
                            }
                            else
                            {
                                is_match = false;
                            }
                        }
                        else if (fix_size == 4)
                        {
                            uint32_t disk_val = 0;
                            uint32_t live_val = 0;
                            std::memcpy(&disk_val, disk_bytes + cur_file_off, 4);
                            std::memcpy(&live_val, live_chunk.data() + k, 4);
                            uint32_t expected_val = static_cast<uint32_t>(static_cast<int32_t>(disk_val) + static_cast<int32_t>(reloc_delta));

                            if (live_val == expected_val)
                            {
                                out_report.total_ignored_expected_bytes += 4;
                                out_report.count_reloc_diffs++;
                                if (options.include_expected_differences)
                                {
                                    PeIntegrityDifference diff;
                                    diff.category = PeIntegrityCategory::RelocationResolved;
                                    diff.severity = PeIntegritySeverity::Informational;
                                    diff.is_expected = true;
                                    diff.section_name = sname;
                                    diff.virtual_address = cur_vaddr;
                                    diff.rva = cur_rva;
                                    diff.file_offset = cur_file_off;
                                    diff.length = 4;
                                    diff.disk_bytes.assign(disk_bytes + cur_file_off, disk_bytes + cur_file_off + 4);
                                    diff.live_bytes.assign(live_chunk.data() + k, live_chunk.data() + k + 4);
                                    diff.explanation = "Legitimate loader base relocation (HIGHLOW).";
                                    out_report.differences.push_back(diff);
                                }
                            }
                            else
                            {
                                is_match = false;
                            }
                        }

                        if (is_match)
                        {
                            k += fix_size;
                            continue;
                        }
                    }
                }

                // B. Check if current location is an IAT entry site
                auto imp_it = std::lower_bound(imports.begin(), imports.end(), cur_rva, [](const PeImportEntry &imp, uint32_t rva) {
                    return imp.iat_rva < rva;
                });

                if (imp_it != imports.end() && imp_it->iat_rva == cur_rva)
                {
                    size_t ptr_size = pe.is_64 ? 8 : 4;
                    if (k + ptr_size <= br)
                    {
                        uintptr_t bound_addr = 0;
                        if (pe.is_64)
                        {
                            uint64_t v64 = 0;
                            std::memcpy(&v64, live_chunk.data() + k, 8);
                            bound_addr = static_cast<uintptr_t>(v64);
                        }
                        else
                        {
                            uint32_t v32 = 0;
                            std::memcpy(&v32, live_chunk.data() + k, 4);
                            bound_addr = v32;
                        }

                        out_report.count_iat_diffs++;
                        out_report.total_changed_bytes += ptr_size;

                        std::string target_module = resolve_address_module_name(bound_addr, all_modules);
                        bool is_suspicious_iat = (target_module == "[Unbacked / Private Memory]");

                        PeIntegrityDifference diff;
                        diff.category = PeIntegrityCategory::ImportAddressTable;
                        diff.severity = is_suspicious_iat ? PeIntegritySeverity::Critical : PeIntegritySeverity::Informational;
                        diff.is_expected = !is_suspicious_iat;
                        diff.section_name = sname;
                        diff.virtual_address = cur_vaddr;
                        diff.rva = cur_rva;
                        diff.file_offset = cur_file_off;
                        diff.length = ptr_size;
                        diff.disk_bytes.assign(disk_bytes + cur_file_off, disk_bytes + cur_file_off + ptr_size);
                        diff.live_bytes.assign(live_chunk.data() + k, live_chunk.data() + k + ptr_size);
                        diff.nearest_export_name = imp_it->function_name;

                        if (is_suspicious_iat)
                        {
                            diff.explanation = "SUSPICIOUS IAT HOOK: " + imp_it->dll_name + "!" + imp_it->function_name +
                                              " bound to unbacked memory 0x" + to_hex_string(bound_addr);
                        }
                        else
                        {
                            diff.explanation = "Resolved IAT pointer: " + imp_it->dll_name + "!" + imp_it->function_name +
                                              " -> 0x" + to_hex_string(bound_addr) + " (" + target_module + ")";
                        }

                        out_report.differences.push_back(diff);
                        k += ptr_size;
                        continue;
                    }
                }

                // C. Standard Byte Comparison
                if (disk_bytes[cur_file_off] == live_chunk[k])
                {
                    k++;
                    continue;
                }

                // Changed byte sequence found: find contiguous run
                size_t span_start = k;
                while (k < br && disk_bytes[chunk_file_off + k] != live_chunk[k])
                {
                    // Don't swallow relocation or IAT entries inside raw diff spans
                    uint32_t next_rva = chunk_rva + static_cast<uint32_t>(k);
                    auto n_rel = std::lower_bound(relocs.begin(), relocs.end(), next_rva, [](const InternalPeMetadata::RelocFixup &fix, uint32_t rva) {
                        return fix.rva < rva;
                    });
                    if (n_rel != relocs.end() && n_rel->rva == next_rva && k > span_start)
                    {
                        break;
                    }
                    auto n_imp = std::lower_bound(imports.begin(), imports.end(), next_rva, [](const PeImportEntry &imp, uint32_t rva) {
                        return imp.iat_rva < rva;
                    });
                    if (n_imp != imports.end() && n_imp->iat_rva == next_rva && k > span_start)
                    {
                        break;
                    }
                    k++;
                }

                size_t diff_len = k - span_start;
                out_report.total_changed_bytes += diff_len;

                uintptr_t diff_vaddr = chunk_vaddr + span_start;
                uint32_t diff_rva = chunk_rva + static_cast<uint32_t>(span_start);
                size_t diff_file_off = chunk_file_off + span_start;

                PeIntegrityDifference diff;
                diff.section_name = sname;
                diff.virtual_address = diff_vaddr;
                diff.rva = diff_rva;
                diff.file_offset = diff_file_off;
                diff.length = diff_len;

                size_t copy_sample = std::min<size_t>(diff_len, 64);
                diff.disk_bytes.assign(disk_bytes + diff_file_off, disk_bytes + diff_file_off + copy_sample);
                diff.live_bytes.assign(live_chunk.data() + span_start, live_chunk.data() + span_start + copy_sample);

                auto near_exp = find_nearest_export(diff_rva);
                diff.nearest_export_name = near_exp.first;
                diff.export_offset = near_exp.second;

                if (is_executable)
                {
                    out_report.count_executable_diffs++;

                    // Inline hook analysis
                    uintptr_t hook_target = 0;
                    std::string hook_desc;
                    if (options.perform_hook_analysis &&
                        inspect_inline_hook_instruction(live_chunk.data() + span_start, br - span_start,
                                                       diff_vaddr, live_base, pe.size_of_image,
                                                       proc, hook_target, hook_desc))
                    {
                        out_report.count_hook_candidates++;
                        diff.category = PeIntegrityCategory::InlineHookCandidate;
                        diff.severity = PeIntegritySeverity::Critical;
                        diff.is_hook_candidate = true;
                        diff.hook_target_address = hook_target;
                        diff.hook_instruction_desc = hook_desc;
                        diff.hook_target_module = resolve_address_module_name(hook_target, all_modules);

                        std::string target_desc = (diff.hook_target_module != "[Unbacked / Private Memory]") ?
                                                   diff.hook_target_module : "unbacked memory";

                        diff.explanation = "Inline Hook Candidate: " + hook_desc + " (target in " + target_desc + ")";
                        if (!diff.nearest_export_name.empty())
                        {
                            diff.explanation += " near exported API " + diff.nearest_export_name;
                        }
                    }
                    else
                    {
                        diff.category = PeIntegrityCategory::ModifiedExecutableCode;
                        diff.severity = PeIntegritySeverity::Critical;
                        diff.explanation = "Executable code modification in section " + sname;
                        if (!diff.nearest_export_name.empty())
                        {
                            diff.explanation += " (within function " + diff.nearest_export_name + " +" + std::to_string(diff.export_offset) + ")";
                        }
                    }
                }
                else
                {
                    out_report.count_data_diffs++;
                    diff.category = PeIntegrityCategory::ModifiedNonExecutableData;
                    diff.severity = PeIntegritySeverity::Warning;
                    diff.explanation = "Non-executable data modified in section " + sname;
                }

                out_report.differences.push_back(diff);
            }

            processed_in_sec += br;
            if (br == 0)
            {
                // Unreadable remainder of section
                break;
            }
        }

        // 3. Inspect Virtual Section Tail (Zero-fill validation)
        if (virt_size > raw_size)
        {
            uint32_t tail_start_rva = sec.VirtualAddress + raw_size;
            uint32_t tail_len = virt_size - raw_size;
            uintptr_t tail_vaddr = live_base + tail_start_rva;

            // Sample virtual tail for unexpected cave injections
            size_t tail_read_sz = std::min<size_t>(tail_len, 4096);
            std::vector<uint8_t> tail_buf(tail_read_sz, 0);
            size_t tail_br = read_live_memory(tail_vaddr, tail_buf.data(), tail_read_sz);

            if (tail_br > 0)
            {
                bool has_nonzero = false;
                size_t first_nonzero = 0;
                for (size_t t = 0; t < tail_br; ++t)
                {
                    if (tail_buf[t] != 0)
                    {
                        has_nonzero = true;
                        first_nonzero = t;
                        break;
                    }
                }

                if (has_nonzero)
                {
                    PeIntegrityDifference diff;
                    if (is_executable)
                    {
                        out_report.count_executable_diffs++;
                        diff.category = PeIntegrityCategory::ModifiedExecutableCode;
                        diff.severity = PeIntegritySeverity::Critical;
                    }
                    else
                    {
                        out_report.count_data_diffs++;
                        diff.category = PeIntegrityCategory::ModifiedNonExecutableData;
                        diff.severity = PeIntegritySeverity::Warning;
                    }
                    diff.section_name = sname + " [Virtual Tail]";
                    diff.virtual_address = tail_vaddr + first_nonzero;
                    diff.rva = tail_start_rva + static_cast<uint32_t>(first_nonzero);
                    diff.file_offset = 0; // Virtual tail has no raw file offset
                    diff.length = tail_br - first_nonzero;
                    diff.live_bytes.assign(tail_buf.data() + first_nonzero, tail_buf.data() + std::min<size_t>(tail_br, first_nonzero + 32));
                    diff.explanation = "Non-zero bytes found in virtual section tail (expected zero-initialized BSS / slack space). Potential cave injection.";
                    out_report.differences.push_back(diff);
                }
            }
        }

        section_idx++;
    }

    if (progress_cb != nullptr)
    {
        progress_cb(1.0f, "Comparison completed.");
    }

    return true;
}

bool compare_pe_integrity(
    HANDLE proc,
    uintptr_t live_base,
    const std::string &disk_path,
    const PeIntegrityOptions &options,
    PeIntegrityReport &out_report,
    std::string &out_err,
    std::atomic<bool> *abort_flag,
    std::function<void(float progress, const std::string &status)> progress_cb,
    const std::vector<LoadedModuleInfo> *all_modules)
{
    out_err.clear();

    if (proc == nullptr || live_base == 0)
    {
        out_err = "Invalid process handle or live base address.";
        return false;
    }

    std::ifstream file(disk_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        out_err = "Cannot open on-disk PE image file: " + disk_path;
        return false;
    }

    size_t fsize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    static const size_t MAX_PE_SIZE = 256 * 1024 * 1024;
    if (fsize == 0 || fsize > MAX_PE_SIZE)
    {
        out_err = "PE image file size exceeds safety cap or is empty.";
        return false;
    }

    std::vector<uint8_t> raw_bytes(fsize);
    file.read(reinterpret_cast<char*>(raw_bytes.data()), static_cast<std::streamsize>(fsize));

    DWORD target_pid = GetProcessId(proc);

    return execute_pe_integrity_compare_core(
        raw_bytes.data(),
        raw_bytes.size(),
        disk_path,
        live_base,
        target_pid,
        proc,
        nullptr,
        options,
        out_report,
        out_err,
        abort_flag,
        progress_cb,
        all_modules);
}

bool compare_pe_memory_integrity(
    std::shared_ptr<MemorySource> live_source,
    uintptr_t live_base,
    const std::vector<uint8_t> &disk_pe_bytes,
    const PeIntegrityOptions &options,
    PeIntegrityReport &out_report,
    std::string &out_err,
    std::atomic<bool> *abort_flag,
    std::function<void(float progress, const std::string &status)> progress_cb,
    const std::vector<LoadedModuleInfo> *all_modules)
{
    out_err.clear();

    if (disk_pe_bytes.empty())
    {
        out_err = "Empty on-disk PE byte buffer.";
        return false;
    }

    DWORD target_pid = live_source ? live_source->get_pid() : 0;

    return execute_pe_integrity_compare_core(
        disk_pe_bytes.data(),
        disk_pe_bytes.size(),
        live_source ? live_source->get_file_path() : "memory_test_module.dll",
        live_base,
        target_pid,
        nullptr,
        live_source,
        options,
        out_report,
        out_err,
        abort_flag,
        progress_cb,
        all_modules);
}

std::string export_pe_integrity_json(const PeIntegrityReport &report, bool include_byte_arrays, size_t max_bytes_cap)
{
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"target_pid\": " << report.target_pid << ",\n";
    ss << "  \"timestamp_ms\": " << report.comparison_timestamp << ",\n";
    ss << "  \"metadata\": {\n";
    ss << "    \"module_name\": \"" << escape_json(report.metadata.module_name) << "\",\n";
    ss << "    \"disk_file_path\": \"" << escape_json(report.metadata.disk_file_path) << "\",\n";
    ss << "    \"live_base_address\": \"0x" << to_hex_string(report.metadata.live_base_address) << "\",\n";
    ss << "    \"preferred_base_address\": \"0x" << to_hex_string(report.metadata.preferred_base_address) << "\",\n";
    ss << "    \"image_size\": " << report.metadata.image_size << ",\n";
    ss << "    \"architecture\": \"" << report.metadata.architecture << "\",\n";
    ss << "    \"machine\": \"0x" << to_hex_string(report.metadata.machine) << "\",\n";
    ss << "    \"timedatestamp\": " << report.metadata.timedatestamp << ",\n";
    ss << "    \"disk_sha256\": \"" << report.metadata.disk_sha256 << "\",\n";
    ss << "    \"section_count\": " << report.metadata.section_count << ",\n";
    ss << "    \"exports_count\": " << report.metadata.exports_count << ",\n";
    ss << "    \"imports_count\": " << report.metadata.imports_count << "\n";
    ss << "  },\n";

    ss << "  \"summary\": {\n";
    ss << "    \"total_compared_bytes\": " << report.total_compared_bytes << ",\n";
    ss << "    \"total_changed_bytes\": " << report.total_changed_bytes << ",\n";
    ss << "    \"total_ignored_expected_bytes\": " << report.total_ignored_expected_bytes << ",\n";
    ss << "    \"total_unreadable_bytes\": " << report.total_unreadable_bytes << ",\n";
    ss << "    \"count_executable_diffs\": " << report.count_executable_diffs << ",\n";
    ss << "    \"count_data_diffs\": " << report.count_data_diffs << ",\n";
    ss << "    \"count_hook_candidates\": " << report.count_hook_candidates << ",\n";
    ss << "    \"count_iat_diffs\": " << report.count_iat_diffs << ",\n";
    ss << "    \"count_reloc_diffs\": " << report.count_reloc_diffs << ",\n";
    ss << "    \"is_incomplete\": " << (report.is_incomplete ? "true" : "false") << "\n";
    ss << "  },\n";

    ss << "  \"differences\": [\n";
    for (size_t i = 0; i < report.differences.size(); ++i)
    {
        const auto &d = report.differences[i];
        ss << "    {\n";
        ss << "      \"index\": " << i << ",\n";
        ss << "      \"category\": \"" << format_integrity_category(d.category) << "\",\n";
        ss << "      \"severity\": \"" << format_integrity_severity(d.severity) << "\",\n";
        ss << "      \"is_expected\": " << (d.is_expected ? "true" : "false") << ",\n";
        ss << "      \"section\": \"" << escape_json(d.section_name) << "\",\n";
        ss << "      \"virtual_address\": \"0x" << to_hex_string(d.virtual_address) << "\",\n";
        ss << "      \"rva\": \"0x" << to_hex_string(d.rva) << "\",\n";
        ss << "      \"file_offset\": \"0x" << to_hex_string(static_cast<uintptr_t>(d.file_offset)) << "\",\n";
        ss << "      \"length\": " << d.length << ",\n";
        ss << "      \"is_hook_candidate\": " << (d.is_hook_candidate ? "true" : "false") << ",\n";

        if (d.is_hook_candidate)
        {
            ss << "      \"hook_target_address\": \"0x" << to_hex_string(d.hook_target_address) << "\",\n";
            ss << "      \"hook_target_module\": \"" << escape_json(d.hook_target_module) << "\",\n";
            ss << "      \"hook_instruction\": \"" << escape_json(d.hook_instruction_desc) << "\",\n";
        }

        if (!d.nearest_export_name.empty())
        {
            ss << "      \"nearest_export\": \"" << escape_json(d.nearest_export_name) << "\",\n";
            ss << "      \"export_offset\": " << d.export_offset << ",\n";
        }

        ss << "      \"explanation\": \"" << escape_json(d.explanation) << "\"";

        if (include_byte_arrays && (!d.disk_bytes.empty() || !d.live_bytes.empty()))
        {
            ss << ",\n      \"disk_bytes_hex\": \"";
            size_t disk_cap = std::min<size_t>(d.disk_bytes.size(), max_bytes_cap);
            for (size_t b = 0; b < disk_cap; ++b)
            {
                char hx[4];
                std::snprintf(hx, sizeof(hx), "%02X", d.disk_bytes[b]);
                ss << hx;
            }
            ss << "\",\n      \"live_bytes_hex\": \"";
            size_t live_cap = std::min<size_t>(d.live_bytes.size(), max_bytes_cap);
            for (size_t b = 0; b < live_cap; ++b)
            {
                char hx[4];
                std::snprintf(hx, sizeof(hx), "%02X", d.live_bytes[b]);
                ss << hx;
            }
            ss << "\"";
        }

        ss << "\n    }" << (i + 1 < report.differences.size() ? "," : "") << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";

    return ss.str();
}

void record_integrity_report_to_timeline(TimelineManager &timeline, DWORD pid, const PeIntegrityReport &report)
{
    std::string summary = "PE Integrity check for " + report.metadata.module_name + ": " +
                          std::to_string(report.count_hook_candidates) + " hook candidate(s), " +
                          std::to_string(report.count_executable_diffs) + " code modification(s), " +
                          std::to_string(report.total_changed_bytes) + " changed bytes.";

    std::string details = "Base: 0x" + to_hex_string(report.metadata.live_base_address) +
                          ", Size: " + fmt_size_short(report.metadata.image_size) +
                          ", SHA256: " + (report.metadata.disk_sha256.empty() ? "N/A" : report.metadata.disk_sha256.substr(0, 16) + "...");

    timeline.record_diff_generated(
        pid,
        summary,
        report.count_hook_candidates + report.count_executable_diffs + report.count_data_diffs,
        report.total_changed_bytes);

    // If critical hook candidates found, record explicit content change events
    for (const auto &d : report.differences)
    {
        if (d.is_hook_candidate)
        {
            timeline.record_content_changed(
                pid,
                d.virtual_address,
                d.length,
                PAGE_EXECUTE_READ,
                MEM_IMAGE,
                d.length,
                "Inline Hook: " + d.hook_instruction_desc + " in " + report.metadata.module_name);
        }
    }
}

} // namespace core
