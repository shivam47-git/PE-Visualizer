#include "pe_parser.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <unordered_map>
#include <regex>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace pe {

// ─── Constructor ─────────────────────────────────────────────────────────────
PEParser::PEParser(const std::string& path) : m_path(path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    auto sz = f.tellg();
    m_data.resize(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(m_data.data()), sz);
}

PEParser::PEParser(const std::vector<uint8_t>& data, const std::string& name)
    : m_data(data), m_path(name) {}

std::string PEParser::read_string(uint64_t offset, uint32_t max_len) const {
    std::string s;
    for (uint32_t i = 0; i < max_len && valid_offset(offset + i); i++) {
        char c = static_cast<char>(m_data[offset + i]);
        if (!c) break;
        s += c;
    }
    return s;
}

uint64_t PEParser::rva_to_offset(uint64_t rva) const {
    for (const auto& s : m_sections) {
        if (rva >= s.va && rva < s.va + std::max(s.vsize, s.raw_size)) {
            uint64_t off = s.raw_off + (rva - s.va);
            if (off < m_data.size()) return off;
        }
    }
    // Headers
    // Header region: RVA is before first section
    uint64_t first_va = m_sections.empty() ? 0x1000 : m_sections.front().va;
    if (rva < first_va)
        return rva;
    return UINT64_MAX;
}

uint64_t PEParser::offset_to_rva(uint64_t offset) const {
    for (const auto& s : m_sections) {
        if (offset >= s.raw_off && offset < s.raw_off + s.raw_size)
            return s.va + (offset - s.raw_off);
    }
    return offset; // header region
}

// ─── Main Parse ──────────────────────────────────────────────────────────────
PEInfo PEParser::parse() {
    PEInfo info;
    info.file_path = m_path;
    info.file_size = m_data.size();

    // DOS
    if (m_data.size() < sizeof(IMAGE_DOS_HEADER)) {
        info.error = "File too small for DOS header";
        return info;
    }
    auto* dos = ptr_at<IMAGE_DOS_HEADER>(0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        info.error = "Invalid DOS signature";
        return info;
    }

    info.dos_header = parse_dos_header();
    m_nt_offset = dos->e_lfanew;

    // NT Signature
    if (!valid_offset(m_nt_offset, 4)) {
        info.error = "NT header offset out of bounds";
        return info;
    }
    uint32_t sig = read_at<uint32_t>(m_nt_offset);
    if (sig != IMAGE_NT_SIGNATURE) {
        info.error = "Invalid PE signature";
        return info;
    }

    // File Header
    uint64_t fh_offset = m_nt_offset + 4;
    auto* fh = ptr_at<IMAGE_FILE_HEADER>(fh_offset);
    if (!fh) { info.error = "Cannot read file header"; return info; }
    info.file_header = parse_file_header(fh);

    // Optional Header
    uint64_t opt_offset = fh_offset + sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = read_at<uint16_t>(opt_offset);
    m_is_64bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    info.optional_header = parse_optional_header(opt_offset);

    // Data directories
    if (m_is_64bit) {
        auto* opt64 = ptr_at<IMAGE_OPTIONAL_HEADER64>(opt_offset);
        if (opt64) {
            for (int i = 0; i < std::min((int)opt64->NumberOfRvaAndSizes,
                                          IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++)
                m_data_dirs[i] = opt64->DataDirectory[i];
            m_image_base = opt64->ImageBase;
        }
    } else {
        auto* opt32 = ptr_at<IMAGE_OPTIONAL_HEADER32>(opt_offset);
        if (opt32) {
            for (int i = 0; i < std::min((int)opt32->NumberOfRvaAndSizes,
                                          IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++)
                m_data_dirs[i] = opt32->DataDirectory[i];
            m_image_base = opt32->ImageBase;
        }
    }

    // Sections
    uint64_t sect_offset = opt_offset + fh->SizeOfOptionalHeader;
    info.sections = parse_sections(sect_offset, fh->NumberOfSections);
    // Populate m_sections for RVA translation
    for (auto& s : info.sections)
        m_sections.push_back({s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size});

    // All directories
    info.rich_header    = parse_rich_header();
    info.imports        = parse_imports();
    info.delay_imports  = parse_delay_imports();
    info.exports        = parse_exports();
    info.resources      = parse_resources();
    info.debug_entries  = parse_debug();
    info.tls            = parse_tls();
    info.load_config    = parse_load_config();
    info.exceptions     = parse_exceptions();
    info.relocations    = parse_relocations();
    info.clr            = parse_clr();
    info.overlay        = detect_overlay();
    info.strings        = extract_strings();
    info.hashes         = compute_hashes();
    info.signature      = parse_signature();
    info.anomalies      = detect_anomalies(info);

    // Stats
    info.file_entropy  = compute_entropy(base(), m_data.size());
    info.import_count  = 0;
    for (auto& d : info.imports) info.import_count += d.functions.size();
    info.export_count  = info.exports.functions.size();
    info.string_count  = info.strings.size();
    info.timestamp_epoch = fh->TimeDateStamp;

    // PE type
    uint16_t chars = fh->Characteristics;
    if (chars & IMAGE_FILE_DLL) info.pe_type = "DLL";
    else if (chars & IMAGE_FILE_SYSTEM) info.pe_type = "SYS";
    else if (chars & IMAGE_FILE_EXECUTABLE_IMAGE) info.pe_type = "EXE";
    else info.pe_type = "UNKNOWN";

    info.valid = true;
    return info;
}

// ─── DOS Header ──────────────────────────────────────────────────────────────
DosHeader PEParser::parse_dos_header() {
    DosHeader h{};
    auto* dos = ptr_at<IMAGE_DOS_HEADER>(0);
    if (!dos) return h;
    h.e_magic    = dos->e_magic;
    h.e_cblp     = dos->e_cblp;
    h.e_cp       = dos->e_cp;
    h.e_crlc     = dos->e_crlc;
    h.e_cparhdr  = dos->e_cparhdr;
    h.e_minalloc = dos->e_minalloc;
    h.e_maxalloc = dos->e_maxalloc;
    h.e_ss       = dos->e_ss;
    h.e_sp       = dos->e_sp;
    h.e_csum     = dos->e_csum;
    h.e_ip       = dos->e_ip;
    h.e_cs       = dos->e_cs;
    h.e_lfarlc   = dos->e_lfarlc;
    h.e_ovno     = dos->e_ovno;
    h.e_oemid    = dos->e_oemid;
    h.e_oeminfo  = dos->e_oeminfo;
    h.e_lfanew   = dos->e_lfanew;
    // DOS stub: from 0x40 to e_lfanew
    uint32_t stub_start = 0x40;
    uint32_t stub_end   = std::min((uint32_t)dos->e_lfanew, (uint32_t)m_data.size());
    if (stub_end > stub_start)
        h.stub = std::vector<uint8_t>(m_data.begin() + stub_start, m_data.begin() + stub_end);
    return h;
}

// ─── Rich Header ─────────────────────────────────────────────────────────────
RichHeader PEParser::parse_rich_header() {
    RichHeader rh{};
    // Search for "Rich" marker between DOS stub and NT headers
    auto* dos = ptr_at<IMAGE_DOS_HEADER>(0);
    if (!dos) return rh;
    uint32_t search_end = std::min((uint32_t)dos->e_lfanew, (uint32_t)m_data.size());
    // Find "Rich" (0x52696368) signature
    for (uint32_t i = 0x40; i + 8 < search_end; i += 4) {
        uint32_t val = read_at<uint32_t>(i);
        if (val == 0x68636952) { // "Rich"
            rh.present = true;
            rh.xor_key = read_at<uint32_t>(i + 4);
            // Find "DanS" XOR'd with key = 0x536e6144 ^ key
            uint32_t dans_val = 0x536e6144 ^ rh.xor_key;
            // Scan backwards for DanS
            for (int32_t j = (int32_t)i - 4; j >= 0x40; j -= 4) {
                if (read_at<uint32_t>(j) == dans_val) {
                    // Entries between j+16 and i
                    uint32_t start = j + 16; // skip DanS + 3 padding dwords
                    for (uint32_t k = start; k + 8 <= i; k += 8) {
                        uint32_t id_count = read_at<uint32_t>(k) ^ rh.xor_key;
                        uint32_t use_cnt  = read_at<uint32_t>(k + 4) ^ rh.xor_key;
                        RichEntry e;
                        e.build_id   = (uint16_t)(id_count & 0xFFFF);
                        e.product_id = (uint16_t)(id_count >> 16);
                        e.use_count  = use_cnt;
                        e.product_name = resolve_rich_product(e.product_id);
                        rh.entries.push_back(e);
                    }
                    // Checksum
                    uint32_t calc_cs = j; // simplified; real impl sums DanS region
                    rh.checksum = rh.xor_key;
                    break;
                }
            }
            // Raw hex
            std::ostringstream oss;
            for (uint32_t k = 0x40; k < i + 8 && k < m_data.size(); k++)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)m_data[k];
            rh.raw_hex = oss.str();
            break;
        }
    }
    return rh;
}

// ─── File Header ─────────────────────────────────────────────────────────────
FileHeader PEParser::parse_file_header(const IMAGE_FILE_HEADER* fh) {
    FileHeader h{};
    h.machine                  = fh->Machine;
    h.machine_str              = resolve_machine(fh->Machine);
    h.number_of_sections       = fh->NumberOfSections;
    h.time_date_stamp          = fh->TimeDateStamp;
    h.timestamp_str            = decode_timestamp(fh->TimeDateStamp);
    h.pointer_to_symbol_table  = fh->PointerToSymbolTable;
    h.number_of_symbols        = fh->NumberOfSymbols;
    h.size_of_optional_header  = fh->SizeOfOptionalHeader;
    h.characteristics          = fh->Characteristics;
    h.characteristics_flags    = decode_characteristics(fh->Characteristics);
    return h;
}

// ─── Optional Header ─────────────────────────────────────────────────────────
OptionalHeader PEParser::parse_optional_header(uint64_t off) {
    OptionalHeader h{};
    h.magic = read_at<uint16_t>(off);
    h.is_64bit = (h.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    static const std::array<std::string, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> DD_NAMES = {
        "Export", "Import", "Resource", "Exception", "Security",
        "BaseReloc", "Debug", "Architecture", "GlobalPtr", "TLS",
        "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved"
    };

    if (h.is_64bit) {
        auto* opt = ptr_at<IMAGE_OPTIONAL_HEADER64>(off);
        if (!opt) return h;
        h.major_linker_version       = opt->MajorLinkerVersion;
        h.minor_linker_version       = opt->MinorLinkerVersion;
        h.size_of_code               = opt->SizeOfCode;
        h.size_of_initialized_data   = opt->SizeOfInitializedData;
        h.size_of_uninitialized_data = opt->SizeOfUninitializedData;
        h.address_of_entry_point     = opt->AddressOfEntryPoint;
        h.base_of_code               = opt->BaseOfCode;
        h.base_of_data               = 0;
        h.image_base                 = opt->ImageBase;
        h.section_alignment          = opt->SectionAlignment;
        h.file_alignment             = opt->FileAlignment;
        h.major_os_version           = opt->MajorOperatingSystemVersion;
        h.minor_os_version           = opt->MinorOperatingSystemVersion;
        h.major_image_version        = opt->MajorImageVersion;
        h.minor_image_version        = opt->MinorImageVersion;
        h.major_subsystem_version    = opt->MajorSubsystemVersion;
        h.minor_subsystem_version    = opt->MinorSubsystemVersion;
        h.win32_version_value        = opt->Win32VersionValue;
        h.size_of_image              = opt->SizeOfImage;
        h.size_of_headers            = opt->SizeOfHeaders;
        h.checksum                   = opt->CheckSum;
        h.subsystem                  = opt->Subsystem;
        h.subsystem_str              = resolve_subsystem(opt->Subsystem);
        h.dll_characteristics        = opt->DllCharacteristics;
        h.dll_characteristics_flags  = decode_dll_characteristics(opt->DllCharacteristics);
        h.size_of_stack_reserve      = opt->SizeOfStackReserve;
        h.size_of_stack_commit       = opt->SizeOfStackCommit;
        h.size_of_heap_reserve       = opt->SizeOfHeapReserve;
        h.size_of_heap_commit        = opt->SizeOfHeapCommit;
        h.loader_flags               = opt->LoaderFlags;
        h.number_of_rva_and_sizes    = opt->NumberOfRvaAndSizes;
        for (int i = 0; i < std::min((int)opt->NumberOfRvaAndSizes, 16); i++) {
            DataDirectory dd;
            dd.virtual_address = opt->DataDirectory[i].VirtualAddress;
            dd.size            = opt->DataDirectory[i].Size;
            dd.name            = DD_NAMES[i];
            h.data_directories.push_back(dd);
        }
    } else {
        auto* opt = ptr_at<IMAGE_OPTIONAL_HEADER32>(off);
        if (!opt) return h;
        h.major_linker_version       = opt->MajorLinkerVersion;
        h.minor_linker_version       = opt->MinorLinkerVersion;
        h.size_of_code               = opt->SizeOfCode;
        h.size_of_initialized_data   = opt->SizeOfInitializedData;
        h.size_of_uninitialized_data = opt->SizeOfUninitializedData;
        h.address_of_entry_point     = opt->AddressOfEntryPoint;
        h.base_of_code               = opt->BaseOfCode;
        h.base_of_data               = opt->BaseOfData;
        h.image_base                 = opt->ImageBase;
        h.section_alignment          = opt->SectionAlignment;
        h.file_alignment             = opt->FileAlignment;
        h.major_os_version           = opt->MajorOperatingSystemVersion;
        h.minor_os_version           = opt->MinorOperatingSystemVersion;
        h.major_image_version        = opt->MajorImageVersion;
        h.minor_image_version        = opt->MinorImageVersion;
        h.major_subsystem_version    = opt->MajorSubsystemVersion;
        h.minor_subsystem_version    = opt->MinorSubsystemVersion;
        h.win32_version_value        = opt->Win32VersionValue;
        h.size_of_image              = opt->SizeOfImage;
        h.size_of_headers            = opt->SizeOfHeaders;
        h.checksum                   = opt->CheckSum;
        h.subsystem                  = opt->Subsystem;
        h.subsystem_str              = resolve_subsystem(opt->Subsystem);
        h.dll_characteristics        = opt->DllCharacteristics;
        h.dll_characteristics_flags  = decode_dll_characteristics(opt->DllCharacteristics);
        h.size_of_stack_reserve      = opt->SizeOfStackReserve;
        h.size_of_stack_commit       = opt->SizeOfStackCommit;
        h.size_of_heap_reserve       = opt->SizeOfHeapReserve;
        h.size_of_heap_commit        = opt->SizeOfHeapCommit;
        h.loader_flags               = opt->LoaderFlags;
        h.number_of_rva_and_sizes    = opt->NumberOfRvaAndSizes;
        for (int i = 0; i < std::min((int)opt->NumberOfRvaAndSizes, 16); i++) {
            DataDirectory dd;
            dd.virtual_address = opt->DataDirectory[i].VirtualAddress;
            dd.size            = opt->DataDirectory[i].Size;
            dd.name            = DD_NAMES[i];
            h.data_directories.push_back(dd);
        }
    }

    // Verify checksum
    // Standard PE checksum algorithm
    uint32_t computed = 0;
    uint64_t remain = 0;
    uint32_t checksum_offset = m_nt_offset + 4 +
        sizeof(IMAGE_FILE_HEADER) +
        (h.is_64bit ? offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum)
                    : offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum));
    uint64_t fsize = m_data.size();
    for (uint64_t i = 0; i < fsize; i += 2) {
        // Treat the 4-byte CheckSum field as zero during computation
        if (i == checksum_offset || i == checksum_offset + 2) continue;
        uint16_t w = 0;
        if (i + 1 < fsize) w = *reinterpret_cast<const uint16_t*>(base() + i);
        else                w = m_data[i];
        computed += w;
        if (computed >> 16) computed = (computed & 0xFFFF) + (computed >> 16);
    }
    computed = (computed & 0xFFFF) + (computed >> 16);
    computed += (uint32_t)fsize;
    h.checksum_valid = (computed == h.checksum);

    return h;
}

// ─── Sections ────────────────────────────────────────────────────────────────
std::vector<SectionInfo> PEParser::parse_sections(uint64_t off, uint16_t count) {
    std::vector<SectionInfo> sects;
    for (uint16_t i = 0; i < count; i++) {
        auto* sh = ptr_at<IMAGE_SECTION_HEADER>(off + i * sizeof(IMAGE_SECTION_HEADER));
        if (!sh) break;
        SectionInfo s;
        char name_buf[9] = {};
        std::memcpy(name_buf, sh->Name, 8);
        s.name = name_buf;
        s.virtual_size          = sh->Misc.VirtualSize;
        s.virtual_address       = sh->VirtualAddress;
        s.raw_size              = sh->SizeOfRawData;
        s.raw_offset            = sh->PointerToRawData;
        s.pointer_to_relocations = sh->PointerToRelocations;
        s.pointer_to_line_numbers = sh->PointerToLinenumbers;
        s.number_of_relocations  = sh->NumberOfRelocations;
        s.number_of_line_numbers = sh->NumberOfLinenumbers;
        s.characteristics        = sh->Characteristics;
        s.characteristics_flags  = decode_section_characteristics(sh->Characteristics);
        s.is_executable   = (sh->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        s.is_writable     = (sh->Characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
        s.is_readable     = (sh->Characteristics & IMAGE_SCN_MEM_READ)    != 0;
        s.is_code         = (sh->Characteristics & IMAGE_SCN_CNT_CODE)    != 0;
        s.is_initialized_data   = (sh->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)   != 0;
        s.is_uninitialized_data = (sh->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
        s.has_rwx         = s.is_executable && s.is_writable;
        s.size_mismatch   = (s.virtual_size > 0 && s.raw_size > 0 &&
                             std::abs((int64_t)s.virtual_size - (int64_t)s.raw_size) > 0x1000);
        s.raw_beyond_eof  = (s.raw_offset + s.raw_size > m_data.size());

        // Entropy & hash
        if (s.raw_offset < m_data.size() && s.raw_size > 0) {
            uint64_t actual_size = std::min((uint64_t)s.raw_size,
                                            m_data.size() - s.raw_offset);
            const uint8_t* sd = base() + s.raw_offset;
            s.entropy = compute_entropy(sd, actual_size);
            s.md5     = hash_md5(sd, actual_size);
            s.sha256  = hash_sha256(sd, actual_size);
        }
        sects.push_back(s);
    }
    return sects;
}

// ─── Imports ─────────────────────────────────────────────────────────────────
std::vector<ImportDLL> PEParser::parse_imports() {
    std::vector<ImportDLL> dlls;
    auto& idd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!idd.VirtualAddress || !idd.Size) return dlls;

    uint64_t off = rva_to_offset(idd.VirtualAddress);
    if (off == UINT64_MAX) return dlls;

    while (valid_offset(off, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
        auto* desc = ptr_at<IMAGE_IMPORT_DESCRIPTOR>(off);
        if (!desc || (!desc->Name && !desc->FirstThunk)) break;

        ImportDLL dll;
        uint64_t name_off = rva_to_offset(desc->Name);
        dll.name              = (name_off != UINT64_MAX) ? read_string(name_off) : "";
        dll.name_rva          = desc->Name;
        dll.first_thunk       = desc->FirstThunk;
        dll.original_first_thunk = desc->OriginalFirstThunk;
        dll.time_date_stamp   = desc->TimeDateStamp;
        dll.is_bound          = (desc->TimeDateStamp == 0xFFFFFFFF);

        // Walk INT (import name table) / IAT
        uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint64_t thunk_off = rva_to_offset(thunk_rva);
        uint64_t iat_off   = rva_to_offset(desc->FirstThunk);

        if (thunk_off != UINT64_MAX) {
            uint32_t idx = 0;
            while (valid_offset(thunk_off + idx * (m_is_64bit ? 8 : 4),
                                 m_is_64bit ? 8 : 4)) {
                uint64_t thunk_val = m_is_64bit
                    ? read_at<uint64_t>(thunk_off + idx * 8)
                    : read_at<uint32_t>(thunk_off + idx * 4);
                if (!thunk_val) break;

                ImportedFunction fn;
                fn.thunk_rva = thunk_rva + idx * (m_is_64bit ? 8 : 4);
                if (iat_off != UINT64_MAX)
                    fn.iat_rva = desc->FirstThunk + idx * (m_is_64bit ? 8 : 4);

                uint64_t ord_flag = m_is_64bit ? 0x8000000000000000ULL : 0x80000000UL;
                if (thunk_val & ord_flag) {
                    fn.by_ordinal = true;
                    fn.ordinal    = (uint16_t)(thunk_val & 0xFFFF);
                    fn.name       = "#" + std::to_string(fn.ordinal);
                } else {
                    fn.by_ordinal = false;
                    uint64_t hin_off = rva_to_offset((uint32_t)thunk_val);
                    if (hin_off != UINT64_MAX && valid_offset(hin_off, 3)) {
                        fn.ordinal = read_at<uint16_t>(hin_off); // hint
                        fn.name    = read_string(hin_off + 2);
                    }
                }

                // Bound address
                if (dll.is_bound && iat_off != UINT64_MAX) {
                    fn.bound_address = m_is_64bit
                        ? read_at<uint64_t>(iat_off + idx * 8)
                        : read_at<uint32_t>(iat_off + idx * 4);
                    fn.is_bound = true;
                }

                dll.functions.push_back(fn);
                idx++;
                if (idx > 4096) break; // safety
            }
        }
        dlls.push_back(dll);
        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (dlls.size() > 512) break;
    }
    return dlls;
}

// ─── Delay Imports ───────────────────────────────────────────────────────────
std::vector<DelayImportDLL> PEParser::parse_delay_imports() {
    std::vector<DelayImportDLL> dlls;
    auto& didd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!didd.VirtualAddress || !didd.Size) return dlls;

    uint64_t off = rva_to_offset(didd.VirtualAddress);
    if (off == UINT64_MAX) return dlls;

    struct ImgDelayDescr {
        uint32_t grAttrs;
        uint32_t szName;
        uint32_t phmod;
        uint32_t pIAT;
        uint32_t pINT;
        uint32_t pBoundIAT;
        uint32_t pUnloadIAT;
        uint32_t dwTimeStamp;
    };

    while (valid_offset(off, sizeof(ImgDelayDescr))) {
        auto* desc = ptr_at<ImgDelayDescr>(off);
        if (!desc || !desc->szName) break;

        DelayImportDLL d;
        d.attributes = desc->grAttrs;
        d.dll_name_rva = desc->szName;
        d.hmodule_rva = desc->phmod;
        d.iat_rva = desc->pIAT;
        d.int_rva = desc->pINT;
        d.bound_iat_rva = desc->pBoundIAT;
        d.unload_iat_rva = desc->pUnloadIAT;
        d.time_date_stamp = desc->dwTimeStamp;

        // Attributes bit 1 = RVA based
        bool rva_based = (desc->grAttrs & 1) != 0;
        uint64_t name_off = rva_based ? rva_to_offset(desc->szName) : desc->szName;
        d.name = (name_off != UINT64_MAX) ? read_string(name_off) : "";

        // Walk INT
        if (desc->pINT) {
            uint64_t int_off = rva_based ? rva_to_offset(desc->pINT) : desc->pINT;
            uint64_t iat_off = rva_based ? rva_to_offset(desc->pIAT) : desc->pIAT;
            uint32_t idx = 0;
            while (int_off != UINT64_MAX &&
                   valid_offset(int_off + idx * (m_is_64bit ? 8 : 4))) {
                uint64_t val = m_is_64bit
                    ? read_at<uint64_t>(int_off + idx * 8)
                    : read_at<uint32_t>(int_off + idx * 4);
                if (!val) break;

                ImportedFunction fn;
                uint64_t ord_flag = m_is_64bit ? 0x8000000000000000ULL : 0x80000000UL;
                if (val & ord_flag) {
                    fn.by_ordinal = true;
                    fn.ordinal    = (uint16_t)(val & 0xFFFF);
                    fn.name       = "#" + std::to_string(fn.ordinal);
                } else {
                    uint64_t hin_off = rva_based ? rva_to_offset((uint32_t)val) : val;
                    if (hin_off != UINT64_MAX) {
                        fn.ordinal = read_at<uint16_t>(hin_off);
                        fn.name    = read_string(hin_off + 2);
                    }
                }
                d.functions.push_back(fn);
                idx++;
                if (idx > 4096) break;
            }
        }

        dlls.push_back(d);
        off += sizeof(ImgDelayDescr);
        if (dlls.size() > 256) break;
    }
    return dlls;
}

// ─── Exports ─────────────────────────────────────────────────────────────────
ExportDirectory PEParser::parse_exports() {
    ExportDirectory exp{};
    auto& edd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!edd.VirtualAddress || !edd.Size) return exp;

    uint64_t off = rva_to_offset(edd.VirtualAddress);
    if (off == UINT64_MAX) return exp;

    auto* ed = ptr_at<IMAGE_EXPORT_DIRECTORY>(off);
    if (!ed) return exp;

    exp.present              = true;
    exp.characteristics      = ed->Characteristics;
    exp.time_date_stamp      = ed->TimeDateStamp;
    exp.major_version        = ed->MajorVersion;
    exp.minor_version        = ed->MinorVersion;
    exp.ordinal_base         = ed->Base;
    exp.number_of_functions  = ed->NumberOfFunctions;
    exp.number_of_names      = ed->NumberOfNames;

    uint64_t name_off = rva_to_offset(ed->Name);
    exp.name = (name_off != UINT64_MAX) ? read_string(name_off) : "";

    // Address table
    uint64_t eat_off = rva_to_offset(ed->AddressOfFunctions);
    uint64_t ent_off = rva_to_offset(ed->AddressOfNames);
    uint64_t eot_off = rva_to_offset(ed->AddressOfNameOrdinals);

    // Build name -> ordinal map
    std::map<uint16_t, std::string> ordinal_to_name;
    if (ent_off != UINT64_MAX && eot_off != UINT64_MAX) {
        for (uint32_t i = 0; i < ed->NumberOfNames && i < 65536; i++) {
            uint32_t fn_name_rva = read_at<uint32_t>(ent_off + i * 4);
            uint16_t ord_idx     = read_at<uint16_t>(eot_off + i * 2);
            uint64_t fn_name_off = rva_to_offset(fn_name_rva);
            if (fn_name_off != UINT64_MAX)
                ordinal_to_name[ord_idx] = read_string(fn_name_off);
        }
    }

    uint32_t export_dir_start = edd.VirtualAddress;
    uint32_t export_dir_end   = edd.VirtualAddress + edd.Size;

    for (uint32_t i = 0; i < ed->NumberOfFunctions && i < 65536; i++) {
        uint32_t fn_rva = (eat_off != UINT64_MAX) ? read_at<uint32_t>(eat_off + i * 4) : 0;
        if (!fn_rva) continue;

        ExportedFunction fn;
        fn.ordinal = ed->Base + i;
        fn.address = fn_rva;

        auto it = ordinal_to_name.find((uint16_t)i);
        fn.has_name = (it != ordinal_to_name.end());
        fn.name     = fn.has_name ? it->second : "";

        // Forwarder: address inside export directory
        fn.is_forwarder = (fn_rva >= export_dir_start && fn_rva < export_dir_end);
        if (fn.is_forwarder) {
            uint64_t fwd_off = rva_to_offset(fn_rva);
            fn.forwarder_string = (fwd_off != UINT64_MAX) ? read_string(fwd_off) : "";
        }
        exp.functions.push_back(fn);
    }
    return exp;
}

// ─── Resources ───────────────────────────────────────────────────────────────
ResourceNode PEParser::parse_resources() {
    ResourceNode root{};
    root.name = "Resources";
    root.is_directory = true;

    auto& rdd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!rdd.VirtualAddress || !rdd.Size) return root;

    uint64_t base_offset = rva_to_offset(rdd.VirtualAddress);
    if (base_offset == UINT64_MAX) return root;

    root = parse_resource_dir(base_offset, base_offset, 0, "", -1);
    root.name = "Resources";
    return root;
}

ResourceNode PEParser::parse_resource_dir(uint64_t base_off, uint64_t dir_off,
                                            int depth, const std::string& parent_type,
                                            int type_id) {
    ResourceNode node{};
    node.is_directory = true;

    if (depth > 3 || !valid_offset(dir_off, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
        return node;
    }

    auto* dir = ptr_at<IMAGE_RESOURCE_DIRECTORY>(dir_off);
    if (!dir) return node;

    node.characteristics = dir->Characteristics;
    node.time_date_stamp = dir->TimeDateStamp;
    node.major_version   = dir->MajorVersion;
    node.minor_version   = dir->MinorVersion;

    uint32_t total_entries = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    uint64_t entry_off = dir_off + sizeof(IMAGE_RESOURCE_DIRECTORY);

    for (uint32_t i = 0; i < total_entries && i < 4096; i++) {
        if (!valid_offset(entry_off, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) break;
        auto* entry = ptr_at<IMAGE_RESOURCE_DIRECTORY_ENTRY>(entry_off);
        if (!entry) break;

        ResourceNode child{};

        // Name or ID
        if (entry->NameIsString) {
            child.is_named = true;
            uint64_t name_off = base_off + (entry->NameOffset & ~0x80000000);
            if (valid_offset(name_off, 2)) {
                uint16_t len = read_at<uint16_t>(name_off);
                std::wstring wname;
                for (uint16_t c = 0; c < len && valid_offset(name_off + 2 + c * 2, 2); c++)
                    wname += (wchar_t)read_at<uint16_t>(name_off + 2 + c * 2);
                // Convert to UTF-8 simple
                for (wchar_t wc : wname) {
                    if (wc < 128) child.name += (char)wc;
                    else child.name += '?';
                }
            }
            child.id = -1;
        } else {
            child.is_named = false;
            child.id = entry->Id;
            if (depth == 0) {
                child.name = resolve_resource_type(entry->Id);
                type_id = entry->Id;
            } else if (depth == 1) {
                child.name = "ID_" + std::to_string(entry->Id);
            } else {
                child.name = "LANG_" + std::to_string(entry->Id);
            }
        }

        if (entry->DataIsDirectory) {
            uint64_t subdir_off = base_off + (entry->OffsetToDirectory & ~0x80000000);
            child = parse_resource_dir(base_off, subdir_off, depth + 1,
                                       depth == 0 ? child.name : parent_type, type_id);
            if (depth == 0 && !child.is_named) {
                child.name = resolve_resource_type(entry->Id);
                child.id   = entry->Id;
            }
        } else {
            // Data entry
            uint64_t data_entry_off = base_off + entry->OffsetToData;
            if (valid_offset(data_entry_off, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
                auto* de = ptr_at<IMAGE_RESOURCE_DATA_ENTRY>(data_entry_off);
                if (de) {
                    child.is_directory = false;
                    ResourceLeaf leaf;
                    leaf.offset_to_data = de->OffsetToData;
                    leaf.size           = de->Size;
                    leaf.code_page      = de->CodePage;
                    leaf.type_name      = parent_type.empty() ? child.name : parent_type;
                    leaf.resource_id    = child.id;

                    uint64_t data_off = rva_to_offset(de->OffsetToData);
                    if (data_off != UINT64_MAX && de->Size > 0) {
                        uint32_t preview_sz = std::min((uint32_t)de->Size, (uint32_t)256);
                        std::ostringstream oss;
                        for (uint32_t b = 0; b < preview_sz && valid_offset(data_off + b); b++)
                            oss << std::hex << std::setw(2) << std::setfill('0')
                                << (int)m_data[data_off + b] << ' ';
                        leaf.hex_preview     = oss.str();
                        leaf.entropy         = compute_entropy(base() + data_off,
                                                               std::min((uint64_t)de->Size,
                                                                        static_cast<uint64_t>(m_data.size()-data_off)));
                        leaf.detected_format = detect_format(base() + data_off,
                                                              std::min((uint64_t)de->Size, (uint64_t)16));
                    }
                    child.leaf = leaf;
                }
            }
        }

        node.children.push_back(child);
        entry_off += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    }
    return node;
}

// ─── Debug Directory ─────────────────────────────────────────────────────────
std::vector<DebugEntry> PEParser::parse_debug() {
    std::vector<DebugEntry> entries;
    auto& ddd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!ddd.VirtualAddress || !ddd.Size) return entries;

    uint64_t off = rva_to_offset(ddd.VirtualAddress);
    if (off == UINT64_MAX) return entries;

    uint32_t count = ddd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (uint32_t i = 0; i < count; i++) {
        auto* dd = ptr_at<IMAGE_DEBUG_DIRECTORY>(off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
        if (!dd) break;
        DebugEntry e;
        e.characteristics      = dd->Characteristics;
        e.time_date_stamp      = dd->TimeDateStamp;
        e.major_version        = dd->MajorVersion;
        e.minor_version        = dd->MinorVersion;
        e.type                 = dd->Type;
        e.type_str             = resolve_debug_type(dd->Type);
        e.size_of_data         = dd->SizeOfData;
        e.address_of_raw_data  = dd->AddressOfRawData;
        e.pointer_to_raw_data  = dd->PointerToRawData;

        // CodeView PDB info
        if (dd->Type == IMAGE_DEBUG_TYPE_CODEVIEW && dd->PointerToRawData &&
            valid_offset(dd->PointerToRawData, 4)) {
            uint32_t cv_sig = read_at<uint32_t>(dd->PointerToRawData);
            if (cv_sig == 0x53445352) { // RSDS
                // GUID (16 bytes) + Age (4 bytes) + PDB path
                uint64_t guid_off = dd->PointerToRawData + 4;
                if (valid_offset(guid_off, 20)) {
                    // Format GUID
                    struct { uint32_t d1; uint16_t d2, d3; uint8_t d4[8]; } guid;
                    std::memcpy(&guid, base() + guid_off, 16);
                    char gbuf[40];
                    snprintf(gbuf, sizeof(gbuf),
                        "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        guid.d1, guid.d2, guid.d3,
                        guid.d4[0], guid.d4[1], guid.d4[2], guid.d4[3],
                        guid.d4[4], guid.d4[5], guid.d4[6], guid.d4[7]);
                    e.guid = gbuf;
                    e.age  = read_at<uint32_t>(guid_off + 16);
                    e.pdb_path = read_string(guid_off + 20);
                }
            }
        }
        entries.push_back(e);
    }
    return entries;
}

// ─── TLS ─────────────────────────────────────────────────────────────────────
TlsDirectory PEParser::parse_tls() {
    TlsDirectory tls{};
    auto& tdd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tdd.VirtualAddress || !tdd.Size) return tls;

    uint64_t off = rva_to_offset(tdd.VirtualAddress);
    if (off == UINT64_MAX) return tls;

    tls.present = true;
    if (m_is_64bit) {
        auto* t = ptr_at<IMAGE_TLS_DIRECTORY64>(off);
        if (!t) return tls;
        tls.start_address_of_raw_data = t->StartAddressOfRawData;
        tls.end_address_of_raw_data   = t->EndAddressOfRawData;
        tls.address_of_index          = t->AddressOfIndex;
        tls.address_of_callbacks      = t->AddressOfCallBacks;
        tls.size_of_zero_fill         = t->SizeOfZeroFill;
        tls.characteristics           = t->Characteristics;
        // Walk callback array
        if (t->AddressOfCallBacks) {
            uint64_t cb_va = t->AddressOfCallBacks;
            uint64_t cb_off = rva_to_offset(cb_va - m_image_base);
            if (cb_off == UINT64_MAX) cb_off = rva_to_offset((uint32_t)(cb_va - m_image_base));
            for (int i = 0; i < 64 && cb_off != UINT64_MAX; i++) {
                uint64_t cb = read_at<uint64_t>(cb_off + i * 8);
                if (!cb) break;
                tls.callbacks.push_back(cb);
            }
        }
    } else {
        auto* t = ptr_at<IMAGE_TLS_DIRECTORY32>(off);
        if (!t) return tls;
        tls.start_address_of_raw_data = t->StartAddressOfRawData;
        tls.end_address_of_raw_data   = t->EndAddressOfRawData;
        tls.address_of_index          = t->AddressOfIndex;
        tls.address_of_callbacks      = t->AddressOfCallBacks;
        tls.size_of_zero_fill         = t->SizeOfZeroFill;
        tls.characteristics           = t->Characteristics;
    }
    return tls;
}

// ─── Load Config ─────────────────────────────────────────────────────────────
#pragma pack(push, 8)
struct ImageLoadConfig64Full {
    DWORD      Size;
    DWORD      TimeDateStamp;
    WORD       MajorVersion;
    WORD       MinorVersion;
    DWORD      GlobalFlagsClear;
    DWORD      GlobalFlagsSet;
    DWORD      CriticalSectionDefaultTimeout;
    ULONGLONG  DeCommitFreeBlockThreshold;
    ULONGLONG  DeCommitTotalFreeThreshold;
    ULONGLONG  LockPrefixTable;
    ULONGLONG  MaximumAllocationSize;
    ULONGLONG  VirtualMemoryThreshold;
    ULONGLONG  ProcessAffinityMask;
    DWORD      ProcessHeapFlags;
    WORD       CSDVersion;
    WORD       Reserved1;
    ULONGLONG  EditList;
    ULONGLONG  SecurityCookie;
    ULONGLONG  SEHandlerTable;
    ULONGLONG  SEHandlerCount;
    ULONGLONG  GuardCFCheckFunctionPointer;
    ULONGLONG  GuardCFDispatchFunctionPointer;
    ULONGLONG  GuardCFFunctionTable;
    ULONGLONG  GuardCFFunctionCount;
    DWORD      GuardFlags;
};

struct ImageLoadConfig32Full {
    DWORD      Size;
    DWORD      TimeDateStamp;
    WORD       MajorVersion;
    WORD       MinorVersion;
    DWORD      GlobalFlagsClear;
    DWORD      GlobalFlagsSet;
    DWORD      CriticalSectionDefaultTimeout;
    DWORD      DeCommitFreeBlockThreshold;
    DWORD      DeCommitTotalFreeThreshold;
    DWORD      LockPrefixTable;
    DWORD      MaximumAllocationSize;
    DWORD      VirtualMemoryThreshold;
    DWORD      ProcessHeapFlags;
    DWORD      ProcessAffinityMask;
    WORD       CSDVersion;
    WORD       Reserved1;
    DWORD      EditList;
    DWORD      SecurityCookie;
    DWORD      SEHandlerTable;
    DWORD      SEHandlerCount;
    DWORD      GuardCFCheckFunctionPointer;
    DWORD      GuardCFDispatchFunctionPointer;
    DWORD      GuardCFFunctionTable;
    DWORD      GuardCFFunctionCount;
    DWORD      GuardFlags;
};
#pragma pack(pop)

LoadConfig PEParser::parse_load_config() {
    LoadConfig lc{};
    auto& lcd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!lcd.VirtualAddress || !lcd.Size) return lc;
    uint64_t off = rva_to_offset(lcd.VirtualAddress);
    if (off == UINT64_MAX) return lc;
    lc.present = true;
    if (m_is_64bit) {
        auto* l = ptr_at<ImageLoadConfig64Full>(off);
        if (!l) return lc;
        lc.size                  = l->Size;
        lc.security_cookie       = l->SecurityCookie;
        lc.has_security_cookie   = (l->SecurityCookie != 0);
        if (l->Size >= offsetof(ImageLoadConfig64Full, GuardFlags) + sizeof(DWORD)) {
            lc.guard_cf_check_function_pointer    = l->GuardCFCheckFunctionPointer;
            lc.guard_cf_dispatch_function_pointer = l->GuardCFDispatchFunctionPointer;
            lc.guard_cf_function_table            = l->GuardCFFunctionTable;
            lc.guard_cf_function_count            = l->GuardCFFunctionCount;
            lc.guard_flags          = l->GuardFlags;
            lc.has_cfg              = (l->GuardFlags & 0x100) != 0; // CF_INSTRUMENTED
        }
        lc.seh_handler_count    = l->SEHandlerCount;
        lc.has_seh              = (l->SEHandlerCount > 0);
    } else {
        auto* l = ptr_at<ImageLoadConfig32Full>(off);
        if (!l) return lc;
        lc.size                  = l->Size;
        lc.security_cookie       = l->SecurityCookie;
        lc.has_security_cookie   = (l->SecurityCookie != 0);
        if (l->Size >= offsetof(ImageLoadConfig32Full, GuardFlags) + sizeof(DWORD)) {
            lc.guard_flags          = l->GuardFlags;
            lc.has_cfg              = (l->GuardFlags & 0x100) != 0;
        }
        lc.seh_handler_count    = l->SEHandlerCount;
        lc.has_seh              = (l->SEHandlerCount > 0);
    }
    // Decode guard flags
    if (lc.guard_flags & 0x100) lc.guard_flags_decoded.push_back("CF_INSTRUMENTED");
    if (lc.guard_flags & 0x200) lc.guard_flags_decoded.push_back("CFW_INSTRUMENTED");
    if (lc.guard_flags & 0x400) lc.guard_flags_decoded.push_back("CF_FUNCTION_TABLE_PRESENT");
    if (lc.guard_flags & 0x800) lc.guard_flags_decoded.push_back("SECURITY_COOKIE_UNUSED");
    if (lc.guard_flags & 0x1000) lc.guard_flags_decoded.push_back("PROTECT_DELAYLOAD_IAT");
    if (lc.guard_flags & 0x2000) lc.guard_flags_decoded.push_back("DELAYLOAD_IAT_IN_ITS_OWN_SECTION");
    if (lc.guard_flags & 0x4000) lc.guard_flags_decoded.push_back("CF_EXPORT_SUPPRESSION_INFO_PRESENT");
    if (lc.guard_flags & 0x8000) lc.guard_flags_decoded.push_back("CF_ENABLE_EXPORT_SUPPRESSION");
    if (lc.guard_flags & 0x10000) lc.guard_flags_decoded.push_back("CF_LONGJUMP_TABLE_PRESENT");
    if (lc.guard_flags & 0x20000000) lc.guard_flags_decoded.push_back("EH_CONTINUATION_TABLE_PRESENT");
    return lc;
}

// ─── Exceptions ──────────────────────────────────────────────────────────────
std::vector<ExceptionEntry> PEParser::parse_exceptions() {
    std::vector<ExceptionEntry> entries;
    if (!m_is_64bit) return entries; // Only x64 has structured exception table here
    auto& edd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!edd.VirtualAddress || !edd.Size) return entries;
    uint64_t off = rva_to_offset(edd.VirtualAddress);
    if (off == UINT64_MAX) return entries;
    struct RUNTIME_FUNCTION { uint32_t BeginAddress, EndAddress, UnwindInfoAddress; };
    uint32_t count = edd.Size / sizeof(RUNTIME_FUNCTION);
    for (uint32_t i = 0; i < count && i < 65536; i++) {
        auto* rf = ptr_at<RUNTIME_FUNCTION>(off + i * sizeof(RUNTIME_FUNCTION));
        if (!rf || !rf->BeginAddress) break;
        entries.push_back({rf->BeginAddress, rf->EndAddress, rf->UnwindInfoAddress});
    }
    return entries;
}

// ─── Relocations ─────────────────────────────────────────────────────────────
std::vector<RelocationBlock> PEParser::parse_relocations() {
    std::vector<RelocationBlock> blocks;
    auto& rrd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!rrd.VirtualAddress || !rrd.Size) return blocks;
    uint64_t off = rva_to_offset(rrd.VirtualAddress);
    if (off == UINT64_MAX) return blocks;
    uint64_t end = off + rrd.Size;

    while (off + 8 <= end && off < m_data.size()) {
        uint32_t va   = read_at<uint32_t>(off);
        uint32_t size = read_at<uint32_t>(off + 4);
        if (!size || size < 8) break;

        RelocationBlock blk;
        blk.virtual_address = va;
        blk.size_of_block   = size;
        blk.entry_count     = (size - 8) / 2;

        for (uint32_t i = 0; i < blk.entry_count && i < 4096; i++) {
            uint16_t entry = read_at<uint16_t>(off + 8 + i * 2);
            uint16_t type  = entry >> 12;
            uint16_t delta = entry & 0x0FFF;
            blk.entries.push_back({delta, resolve_reloc_type(type)});
        }
        blocks.push_back(blk);
        off += size;
        if (blocks.size() > 8192) break;
    }
    return blocks;
}

// ─── CLR ─────────────────────────────────────────────────────────────────────
ClrHeader PEParser::parse_clr() {
    ClrHeader clr{};
    auto& cdd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if (!cdd.VirtualAddress || !cdd.Size) return clr;
    uint64_t off = rva_to_offset(cdd.VirtualAddress);
    if (off == UINT64_MAX) return clr;

    struct IMAGE_COR20_HEADER {
        uint32_t cb;
        uint16_t MajorRuntimeVersion, MinorRuntimeVersion;
        uint32_t MetaDataRva, MetaDataSize;
        uint32_t Flags;
        uint32_t EntryPointTokenOrRva;
        uint32_t ResourcesRva, ResourcesSize;
        uint32_t StrongNameSignatureRva, StrongNameSignatureSize;
        uint32_t CodeManagerTableRva, CodeManagerTableSize;
        uint32_t VTableFixupsRva, VTableFixupsSize;
        uint32_t ExportAddressTableJumpsRva, ExportAddressTableJumpsSize;
        uint32_t ManagedNativeHeaderRva, ManagedNativeHeaderSize;
    };

    auto* h = ptr_at<IMAGE_COR20_HEADER>(off);
    if (!h) return clr;
    clr.present                = true;
    clr.major_runtime_version  = h->MajorRuntimeVersion;
    clr.minor_runtime_version  = h->MinorRuntimeVersion;
    clr.metadata_rva           = h->MetaDataRva;
    clr.metadata_size          = h->MetaDataSize;
    clr.flags                  = h->Flags;
    clr.entry_point_token      = h->EntryPointTokenOrRva;

    if (h->Flags & 1)  clr.flags_decoded.push_back("IL_ONLY");
    if (h->Flags & 2)  clr.flags_decoded.push_back("32BIT_REQUIRED");
    if (h->Flags & 4)  clr.flags_decoded.push_back("IL_LIBRARY");
    if (h->Flags & 8)  clr.flags_decoded.push_back("STRONGNAMESIGNED");
    if (h->Flags & 0x10) clr.flags_decoded.push_back("NATIVE_ENTRYPOINT");
    if (h->Flags & 0x10000) clr.flags_decoded.push_back("TRACKDEBUGDATA");
    if (h->Flags & 0x20000) clr.flags_decoded.push_back("PREFER_32BIT");

    return clr;
}

// ─── Overlay ─────────────────────────────────────────────────────────────────
OverlayInfo PEParser::detect_overlay() {
    OverlayInfo ov{};
    // Find end of last section
    uint64_t max_end = 0;
    for (const auto& s : m_sections) {
        if (s.raw_size > 0)
            max_end = std::max(max_end, (uint64_t)s.raw_off + s.raw_size);
    }
    // Also account for security directory (signature)
    auto& sec = m_data_dirs[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sec.VirtualAddress > max_end) max_end = sec.VirtualAddress + sec.Size;

    if (max_end > 0 && max_end < m_data.size()) {
        ov.present = true;
        ov.offset  = max_end;
        ov.size    = m_data.size() - max_end;
        ov.entropy = compute_entropy(base() + max_end, ov.size);
        ov.detected_format = detect_format(base() + max_end, std::min((uint64_t)16, ov.size));
        std::ostringstream oss;
        for (uint64_t i = 0; i < std::min(ov.size, (uint64_t)128); i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)m_data[max_end+i] << ' ';
        ov.hex_preview = oss.str();
    }
    return ov;
}

// ─── Hashes ──────────────────────────────────────────────────────────────────
FileHashes PEParser::compute_hashes() {
    FileHashes h;
    h.md5    = hash_md5(base(), m_data.size());
    h.sha256 = hash_sha256(base(), m_data.size());

    // SHA-1
    unsigned char sha1buf[SHA_DIGEST_LENGTH];
    SHA1(base(), m_data.size(), sha1buf);
    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)sha1buf[i];
    h.sha1 = oss.str();

    return h;
}

// ─── Signature (stub) ────────────────────────────────────────────────────────
Signature PEParser::parse_signature() {
    Signature sig{};
    // Check security directory
    auto& sdd = m_data_dirs[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (!sdd.VirtualAddress || !sdd.Size) return sig;
    sig.signed_file = true;
    // Full Authenticode parsing requires CryptQueryObject / WinVerifyTrust
    // on Windows. Here we just note it's signed.
    return sig;
}

// ─── Anomaly Detection ───────────────────────────────────────────────────────
std::vector<Anomaly> PEParser::detect_anomalies(const PEInfo& info) {
    std::vector<Anomaly> anomalies;

    auto add = [&](Anomaly::Severity sev, const std::string& cat,
                   const std::string& desc, const std::string& detail = "") {
        anomalies.push_back({sev, cat, desc, detail});
    };

    // Timestamp
    if (info.file_header.time_date_stamp == 0)
        add(Anomaly::Severity::MEDIUM, "Header", "Zero timestamp",
            "TimeDateStamp is 0, may indicate stripping or malware");
    else if (info.file_header.time_date_stamp > 0xFFFFFFFF - 86400)
        add(Anomaly::Severity::HIGH, "Header", "Implausible future timestamp",
            "Timestamp is in the distant future");
    if (info.file_header.time_date_stamp > 0 && info.file_header.time_date_stamp < 0x3F000000)
        add(Anomaly::Severity::LOW, "Header", "Very old timestamp (pre-1999)",
            "May be forged or stripped");

    // Sections
    for (auto& s : info.sections) {
        if (s.has_rwx)
            add(Anomaly::Severity::HIGH, "Section",
                "RWX section: " + s.name,
                "Writable+Executable memory is commonly used by shellcode/packers");
        if (s.entropy > 7.0)
            add(Anomaly::Severity::MEDIUM, "Section",
                "High entropy in " + s.name + " (" + std::to_string(s.entropy).substr(0,4) + ")",
                "May indicate packed/encrypted code");
        if (s.raw_beyond_eof)
            add(Anomaly::Severity::HIGH, "Section",
                "Section " + s.name + " raw data exceeds file size",
                "Corrupt or maliciously crafted PE");
        if (s.name.empty())
            add(Anomaly::Severity::LOW, "Section", "Section with empty name",
                "Unusual, may indicate tool-generated PE");
    }

    // EP in non-code section
    if (!info.sections.empty() && info.optional_header.address_of_entry_point) {
        uint32_t ep = info.optional_header.address_of_entry_point;
        bool ep_in_code = false;
        for (auto& s : info.sections) {
            if (ep >= s.virtual_address && ep < s.virtual_address + s.virtual_size) {
                if (!s.is_executable)
                    add(Anomaly::Severity::HIGH, "EntryPoint",
                        "Entry point in non-executable section: " + s.name,
                        "Common indicator of packing or modification");
                if (s.is_writable)
                    add(Anomaly::Severity::HIGH, "EntryPoint",
                        "Entry point in writable section: " + s.name, "");
                ep_in_code = true;
                break;
            }
        }
        if (!ep_in_code)
            add(Anomaly::Severity::CRITICAL, "EntryPoint",
                "Entry point outside any section",
                "EP RVA 0x" + [&](){
                    std::ostringstream o; o << std::hex << ep; return o.str();
                }() + " doesn't map to any section");
    }

    // No imports = likely packed/shellcode
    if (info.imports.empty() && !info.clr.present)
        add(Anomaly::Severity::HIGH, "Imports",
            "No imports found", "Packed, obfuscated, or shellcode PE");
    else if (info.imports.size() == 1 && info.imports[0].functions.size() <= 3)
        add(Anomaly::Severity::MEDIUM, "Imports",
            "Very few imports (" + std::to_string(info.import_count) + ")",
            "Possibly packed");

    // TLS callbacks (execution before main)
    if (info.tls.present && !info.tls.callbacks.empty())
        add(Anomaly::Severity::MEDIUM, "TLS",
            "TLS callbacks present (" + std::to_string(info.tls.callbacks.size()) + ")",
            "Code executes before entry point - used by anti-debug/packers");

    // Rich header
    if (!info.rich_header.present)
        add(Anomaly::Severity::LOW, "RichHeader",
            "No Rich header", "Uncommon in MS-built binaries");

    // Checksum
    if (info.optional_header.checksum && !info.optional_header.checksum_valid)
        add(Anomaly::Severity::MEDIUM, "Checksum",
            "Invalid PE checksum", "File may have been modified post-build");

    // Overlay
    if (info.overlay.present) {
        Anomaly::Severity sev = info.overlay.size > 1024*1024
            ? Anomaly::Severity::HIGH : Anomaly::Severity::MEDIUM;
        add(sev, "Overlay",
            "Overlay data detected (" + std::to_string(info.overlay.size) + " bytes, entropy " +
            std::to_string(info.overlay.entropy).substr(0,4) + ")",
            "Data appended after last section - may contain payload");
    }

    // High file entropy
    if (info.file_entropy > 7.2)
        add(Anomaly::Severity::MEDIUM, "Entropy",
            "High overall file entropy (" + std::to_string(info.file_entropy).substr(0,4) + ")",
            "Indicative of packing or encryption");

    // .NET specific
    if (info.clr.present)
        add(Anomaly::Severity::INFO, "CLR",
            "Managed .NET assembly detected", "");

    // Suspicious imports
    static const std::vector<std::string> suspicious_apis = {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "SetWindowsHookEx", "GetProcAddress", "LoadLibrary", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OpenProcess",
        "ReadProcessMemory", "AdjustTokenPrivileges", "CreateService", "RegSetValue",
        "InternetOpenUrl", "WinExec", "ShellExecute", "CreateProcessWith"
    };
    std::vector<std::string> found_suspicious;
    for (auto& dll : info.imports)
        for (auto& fn : dll.functions)
            for (auto& api : suspicious_apis)
                if (fn.name.find(api) != std::string::npos)
                    found_suspicious.push_back(fn.name);

    if (!found_suspicious.empty()) {
        std::string detail;
        for (size_t i = 0; i < std::min(found_suspicious.size(), size_t(5)); i++)
            detail += found_suspicious[i] + " ";
        add(Anomaly::Severity::MEDIUM, "Imports",
            "Suspicious API imports (" + std::to_string(found_suspicious.size()) + ")",
            detail);
    }

    return anomalies;
}

// ─── Utility Functions ───────────────────────────────────────────────────────
double PEParser::compute_entropy(const uint8_t* data, size_t size) const {
    if (!data || size == 0) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / size;
        ent -= p * std::log2(p);
    }
    return ent;
}

std::string PEParser::hash_md5(const uint8_t* data, size_t size) const {
    unsigned char buf[MD5_DIGEST_LENGTH];
    MD5(data, size, buf);
    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    return oss.str();
}

std::string PEParser::hash_sha256(const uint8_t* data, size_t size) const {
    unsigned char buf[SHA256_DIGEST_LENGTH];
    SHA256(data, size, buf);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    return oss.str();
}

std::string PEParser::decode_timestamp(uint32_t ts) const {
    if (!ts) return "0 (stripped/invalid)";
    time_t t = (time_t)ts;
    char buf[64] = {};
    struct tm tmr = {};
#if defined(_WIN32)
    gmtime_s(&tmr, &t);
#else
    gmtime_r(&t, &tmr);
#endif
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tmr);
    return buf;
}

std::string PEParser::detect_format(const uint8_t* data, size_t size) const {
    if (size < 4) return "Unknown";
    uint32_t sig = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];
    if (data[0]==0x4D&&data[1]==0x5A) return "PE/MZ";
    if (data[0]==0x7F&&data[1]=='E'&&data[2]=='L'&&data[3]=='F') return "ELF";
    if (sig==0x89504E47) return "PNG";
    if (data[0]==0xFF&&data[1]==0xD8) return "JPEG";
    if (data[0]=='P'&&data[1]=='K'&&data[2]==3&&data[3]==4) return "ZIP";
    if (data[0]=='M'&&data[1]=='Z') return "MZ";
    if (sig==0x52617221) return "RAR";
    if (sig==0x1F8B0800||data[0]==0x1F&&data[1]==0x8B) return "GZIP";
    if (data[0]=='B'&&data[1]=='Z'&&data[2]=='h') return "BZIP2";
    if (sig==0x377ABCAFU) return "7-Zip";
    if (data[0]==0xCA&&data[1]==0xFE&&data[2]==0xBA&&data[3]==0xBE) return "Java Class";
    if (data[0]==0x25&&data[1]==0x50&&data[2]==0x44&&data[3]==0x46) return "PDF";
    if (data[0]=='<') return "XML/HTML";
    return "Unknown";
}

std::string PEParser::resolve_machine(uint16_t m) const {
    switch(m) {
    case IMAGE_FILE_MACHINE_I386:   return "x86 (I386)";
    case IMAGE_FILE_MACHINE_AMD64:  return "x64 (AMD64)";
    case IMAGE_FILE_MACHINE_ARM:    return "ARM";
    case IMAGE_FILE_MACHINE_ARM64:  return "ARM64";
    case IMAGE_FILE_MACHINE_IA64:   return "IA-64";
    case 0x0EBC:                    return "EFI Byte Code";
    case IMAGE_FILE_MACHINE_UNKNOWN: return "Unknown";
    default: {
        std::ostringstream o; o << "Unknown (0x" << std::hex << m << ")"; return o.str();
    }}
}

std::string PEParser::resolve_subsystem(uint16_t s) const {
    switch(s) {
    case IMAGE_SUBSYSTEM_NATIVE:                  return "Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:             return "Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:             return "Windows Console";
    case IMAGE_SUBSYSTEM_OS2_CUI:                 return "OS/2 Console";
    case IMAGE_SUBSYSTEM_POSIX_CUI:               return "Posix Console";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:          return "Windows CE GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return "EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:      return "EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_EFI_ROM:                 return "EFI ROM";
    case IMAGE_SUBSYSTEM_XBOX:                    return "Xbox";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Windows Boot Application";
    default: return "Unknown";
    }
}

std::vector<std::string> PEParser::decode_characteristics(uint16_t c) const {
    std::vector<std::string> r;
    if (c & IMAGE_FILE_RELOCS_STRIPPED)       r.push_back("RELOCS_STRIPPED");
    if (c & IMAGE_FILE_EXECUTABLE_IMAGE)      r.push_back("EXECUTABLE_IMAGE");
    if (c & IMAGE_FILE_LINE_NUMS_STRIPPED)    r.push_back("LINE_NUMS_STRIPPED");
    if (c & IMAGE_FILE_LOCAL_SYMS_STRIPPED)   r.push_back("LOCAL_SYMS_STRIPPED");
    if (c & IMAGE_FILE_AGGRESIVE_WS_TRIM)     r.push_back("AGGRESSIVE_WS_TRIM");
    if (c & IMAGE_FILE_LARGE_ADDRESS_AWARE)   r.push_back("LARGE_ADDRESS_AWARE");
    if (c & IMAGE_FILE_BYTES_REVERSED_LO)     r.push_back("BYTES_REVERSED_LO");
    if (c & IMAGE_FILE_32BIT_MACHINE)         r.push_back("32BIT_MACHINE");
    if (c & IMAGE_FILE_DEBUG_STRIPPED)        r.push_back("DEBUG_STRIPPED");
    if (c & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) r.push_back("REMOVABLE_RUN_FROM_SWAP");
    if (c & IMAGE_FILE_NET_RUN_FROM_SWAP)     r.push_back("NET_RUN_FROM_SWAP");
    if (c & IMAGE_FILE_SYSTEM)                r.push_back("SYSTEM");
    if (c & IMAGE_FILE_DLL)                   r.push_back("DLL");
    if (c & IMAGE_FILE_UP_SYSTEM_ONLY)        r.push_back("UP_SYSTEM_ONLY");
    if (c & IMAGE_FILE_BYTES_REVERSED_HI)     r.push_back("BYTES_REVERSED_HI");
    return r;
}

std::vector<std::string> PEParser::decode_dll_characteristics(uint16_t c) const {
    std::vector<std::string> r;
    if (c & 0x0020) r.push_back("HIGH_ENTROPY_VA");
    if (c & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) r.push_back("DYNAMIC_BASE (ASLR)");
    if (c & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) r.push_back("FORCE_INTEGRITY");
    if (c & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) r.push_back("NX_COMPAT (DEP)");
    if (c & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) r.push_back("NO_ISOLATION");
    if (c & IMAGE_DLLCHARACTERISTICS_NO_SEH) r.push_back("NO_SEH");
    if (c & IMAGE_DLLCHARACTERISTICS_NO_BIND) r.push_back("NO_BIND");
    if (c & 0x1000) r.push_back("APPCONTAINER");
    if (c & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) r.push_back("WDM_DRIVER");
    if (c & 0x4000) r.push_back("GUARD_CF");
    if (c & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) r.push_back("TERMINAL_SERVER_AWARE");
    return r;
}

std::vector<std::string> PEParser::decode_section_characteristics(uint32_t c) const {
    std::vector<std::string> r;
    if (c & IMAGE_SCN_CNT_CODE)               r.push_back("CNT_CODE");
    if (c & IMAGE_SCN_CNT_INITIALIZED_DATA)   r.push_back("CNT_INITIALIZED_DATA");
    if (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) r.push_back("CNT_UNINITIALIZED_DATA");
    if (c & IMAGE_SCN_LNK_INFO)               r.push_back("LNK_INFO");
    if (c & IMAGE_SCN_LNK_REMOVE)             r.push_back("LNK_REMOVE");
    if (c & IMAGE_SCN_LNK_COMDAT)             r.push_back("LNK_COMDAT");
    if (c & IMAGE_SCN_NO_DEFER_SPEC_EXC)      r.push_back("NO_DEFER_SPEC_EXC");
    if (c & IMAGE_SCN_GPREL)                  r.push_back("GPREL");
    if (c & IMAGE_SCN_MEM_PURGEABLE)          r.push_back("MEM_PURGEABLE");
    if (c & IMAGE_SCN_MEM_LOCKED)             r.push_back("MEM_LOCKED");
    if (c & IMAGE_SCN_MEM_PRELOAD)            r.push_back("MEM_PRELOAD");
    if (c & IMAGE_SCN_ALIGN_1BYTES)           r.push_back("ALIGN_1BYTES");
    if (c & IMAGE_SCN_LNK_NRELOC_OVFL)       r.push_back("LNK_NRELOC_OVFL");
    if (c & IMAGE_SCN_MEM_DISCARDABLE)        r.push_back("MEM_DISCARDABLE");
    if (c & IMAGE_SCN_MEM_NOT_CACHED)         r.push_back("MEM_NOT_CACHED");
    if (c & IMAGE_SCN_MEM_NOT_PAGED)          r.push_back("MEM_NOT_PAGED");
    if (c & IMAGE_SCN_MEM_SHARED)             r.push_back("MEM_SHARED");
    if (c & IMAGE_SCN_MEM_EXECUTE)            r.push_back("MEM_EXECUTE");
    if (c & IMAGE_SCN_MEM_READ)               r.push_back("MEM_READ");
    if (c & IMAGE_SCN_MEM_WRITE)              r.push_back("MEM_WRITE");
    return r;
}

std::string PEParser::resolve_resource_type(int id) const {
    switch(id) {
    case 1: return "RT_CURSOR"; case 2: return "RT_BITMAP";
    case 3: return "RT_ICON";   case 4: return "RT_MENU";
    case 5: return "RT_DIALOG"; case 6: return "RT_STRING";
    case 7: return "RT_FONTDIR";case 8: return "RT_FONT";
    case 9: return "RT_ACCELERATOR"; case 10: return "RT_RCDATA";
    case 11: return "RT_MESSAGETABLE"; case 12: return "RT_GROUP_CURSOR";
    case 14: return "RT_GROUP_ICON";   case 16: return "RT_VERSION";
    case 17: return "RT_DLGINCLUDE";   case 19: return "RT_PLUGPLAY";
    case 20: return "RT_VXD";          case 21: return "RT_ANICURSOR";
    case 22: return "RT_ANIICON";      case 23: return "RT_HTML";
    case 24: return "RT_MANIFEST";
    default: return "RT_" + std::to_string(id);
    }
}

std::string PEParser::resolve_debug_type(uint32_t t) const {
    switch(t) {
    case IMAGE_DEBUG_TYPE_UNKNOWN:    return "UNKNOWN";
    case IMAGE_DEBUG_TYPE_COFF:       return "COFF";
    case IMAGE_DEBUG_TYPE_CODEVIEW:   return "CODEVIEW (PDB)";
    case IMAGE_DEBUG_TYPE_FPO:        return "FPO";
    case IMAGE_DEBUG_TYPE_MISC:       return "MISC";
    case IMAGE_DEBUG_TYPE_EXCEPTION:  return "EXCEPTION";
    case IMAGE_DEBUG_TYPE_FIXUP:      return "FIXUP";
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:   return "OMAP_TO_SRC";
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: return "OMAP_FROM_SRC";
    case IMAGE_DEBUG_TYPE_BORLAND:    return "BORLAND";
    case 13: return "REPRO";
    case 16: return "ILTCG";
    case 17: return "MPX";
    case 19: return "POGO";
    case 20: return "ILTCG2";
    case 21: return "HASH";
    case 22: return "EX_DLLCHARACTERISTICS";
    default: {
        std::ostringstream o; o << "TYPE_" << t; return o.str();
    }}
}

std::string PEParser::resolve_reloc_type(uint16_t t) const {
    switch(t) {
    case IMAGE_REL_BASED_ABSOLUTE:   return "ABSOLUTE";
    case IMAGE_REL_BASED_HIGH:       return "HIGH";
    case IMAGE_REL_BASED_LOW:        return "LOW";
    case IMAGE_REL_BASED_HIGHLOW:    return "HIGHLOW";
    case IMAGE_REL_BASED_HIGHADJ:    return "HIGHADJ";
    case IMAGE_REL_BASED_DIR64:      return "DIR64";
    default: return "TYPE_" + std::to_string(t);
    }
}

// ─── Hex dump / on-demand ────────────────────────────────────────────────────
nlohmann::json PEParser::get_hex_dump(uint64_t rva, uint32_t size) {
    uint64_t off = rva_to_offset(rva);
    if (off == UINT64_MAX) return {{"error", "Invalid RVA"}};
    size = (uint32_t)std::min((uint64_t)size, m_data.size() - off);
    size = std::min(size, 65536u);

    nlohmann::json rows = nlohmann::json::array();
    for (uint32_t i = 0; i < size; i += 16) {
        nlohmann::json row;
        row["offset"] = rva + i;
        std::string hex_str, ascii_str;
        for (int j = 0; j < 16; j++) {
            if (i + j < size) {
                uint8_t b = m_data[off + i + j];
                char buf[4]; snprintf(buf, sizeof(buf), "%02X ", b);
                hex_str += buf;
                ascii_str += (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            } else {
                hex_str  += "   ";
                ascii_str += ' ';
            }
        }
        row["hex"]   = hex_str;
        row["ascii"] = ascii_str;
        rows.push_back(row);
    }
    return rows;
}

// ─── JSON serialization ──────────────────────────────────────────────────────
static nlohmann::json anomaly_to_json(const Anomaly& a) {
    static const char* sevs[] = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
    return {
        {"severity",    sevs[(int)a.severity]},
        {"category",    a.category},
        {"description", a.description},
        {"detail",      a.detail}
    };
}

static nlohmann::json resource_node_to_json(const ResourceNode& n) {
    nlohmann::json j;
    j["name"]         = n.name;
    j["id"]           = n.id;
    j["is_named"]     = n.is_named;
    j["is_directory"] = n.is_directory;
    if (n.leaf) {
        j["leaf"] = {
            {"offset",          n.leaf->offset_to_data},
            {"size",            n.leaf->size},
            {"code_page",       n.leaf->code_page},
            {"type_name",       n.leaf->type_name},
            {"entropy",         n.leaf->entropy},
            {"detected_format", n.leaf->detected_format},
            {"hex_preview",     n.leaf->hex_preview}
        };
    }
    j["children"] = nlohmann::json::array();
    for (auto& c : n.children)
        j["children"].push_back(resource_node_to_json(c));
    return j;
}

nlohmann::json pe_info_to_json(const PEInfo& info) {
    if (!info.valid) return {{"valid", false}, {"error", info.error}};

    nlohmann::json j;
    j["valid"]      = true;
    j["file_path"]  = info.file_path;
    j["file_size"]  = info.file_size;
    j["pe_type"]    = info.pe_type;
    j["file_entropy"] = info.file_entropy;
    j["import_count"] = info.import_count;
    j["export_count"] = info.export_count;
    j["string_count"] = info.string_count;
    j["timestamp_epoch"] = info.timestamp_epoch;

    // Hashes
    j["hashes"] = {
        {"md5",     info.hashes.md5},
        {"sha1",    info.hashes.sha1},
        {"sha256",  info.hashes.sha256},
        {"imphash", info.hashes.imphash},
    };

    // DOS Header
    auto& d = info.dos_header;
    j["dos_header"] = {
        {"e_magic",   d.e_magic},   {"e_cblp", d.e_cblp},
        {"e_cp",      d.e_cp},      {"e_crlc", d.e_crlc},
        {"e_cparhdr", d.e_cparhdr}, {"e_minalloc", d.e_minalloc},
        {"e_maxalloc",d.e_maxalloc},{"e_ss", d.e_ss},
        {"e_sp",      d.e_sp},      {"e_csum", d.e_csum},
        {"e_ip",      d.e_ip},      {"e_cs", d.e_cs},
        {"e_lfanew",  d.e_lfanew},
    };

    // Rich Header
    auto& rh = info.rich_header;
    j["rich_header"] = {
        {"present",        rh.present},
        {"xor_key",        rh.xor_key},
        {"checksum",       rh.checksum},
        {"checksum_valid", rh.checksum_valid},
        {"raw_hex",        rh.raw_hex},
        {"entries",        nlohmann::json::array()}
    };
    for (auto& e : rh.entries)
        j["rich_header"]["entries"].push_back({
            {"build_id", e.build_id}, {"product_id", e.product_id},
            {"use_count", e.use_count}, {"product_name", e.product_name}
        });

    // File Header
    auto& fh = info.file_header;
    j["file_header"] = {
        {"machine",                    fh.machine},
        {"machine_str",                fh.machine_str},
        {"number_of_sections",         fh.number_of_sections},
        {"time_date_stamp",            fh.time_date_stamp},
        {"timestamp_str",              fh.timestamp_str},
        {"pointer_to_symbol_table",    fh.pointer_to_symbol_table},
        {"number_of_symbols",          fh.number_of_symbols},
        {"size_of_optional_header",    fh.size_of_optional_header},
        {"characteristics",            fh.characteristics},
        {"characteristics_flags",      fh.characteristics_flags},
    };

    // Optional Header
    auto& oh = info.optional_header;
    j["optional_header"] = {
        {"magic",                    oh.magic},
        {"is_64bit",                 oh.is_64bit},
        {"linker_version",           std::to_string(oh.major_linker_version) + "." +
                                     std::to_string(oh.minor_linker_version)},
        {"size_of_code",             oh.size_of_code},
        {"size_of_initialized_data", oh.size_of_initialized_data},
        {"address_of_entry_point",   oh.address_of_entry_point},
        {"base_of_code",             oh.base_of_code},
        {"image_base",               oh.image_base},
        {"section_alignment",        oh.section_alignment},
        {"file_alignment",           oh.file_alignment},
        {"os_version",               std::to_string(oh.major_os_version)+"."+
                                     std::to_string(oh.minor_os_version)},
        {"image_version",            std::to_string(oh.major_image_version)+"."+
                                     std::to_string(oh.minor_image_version)},
        {"subsystem_version",        std::to_string(oh.major_subsystem_version)+"."+
                                     std::to_string(oh.minor_subsystem_version)},
        {"size_of_image",            oh.size_of_image},
        {"size_of_headers",          oh.size_of_headers},
        {"checksum",                 oh.checksum},
        {"checksum_valid",           oh.checksum_valid},
        {"subsystem",                oh.subsystem},
        {"subsystem_str",            oh.subsystem_str},
        {"dll_characteristics",      oh.dll_characteristics},
        {"dll_characteristics_flags",oh.dll_characteristics_flags},
        {"size_of_stack_reserve",    oh.size_of_stack_reserve},
        {"size_of_stack_commit",     oh.size_of_stack_commit},
        {"size_of_heap_reserve",     oh.size_of_heap_reserve},
        {"size_of_heap_commit",      oh.size_of_heap_commit},
        {"number_of_rva_and_sizes",  oh.number_of_rva_and_sizes},
        {"data_directories",         nlohmann::json::array()},
    };
    for (auto& dd : oh.data_directories)
        j["optional_header"]["data_directories"].push_back({
            {"name", dd.name}, {"rva", dd.virtual_address}, {"size", dd.size}
        });

    // Sections
    j["sections"] = nlohmann::json::array();
    for (auto& s : info.sections) {
        j["sections"].push_back({
            {"name",                s.name},
            {"virtual_size",        s.virtual_size},
            {"virtual_address",     s.virtual_address},
            {"raw_size",            s.raw_size},
            {"raw_offset",          s.raw_offset},
            {"characteristics",     s.characteristics},
            {"characteristics_flags", s.characteristics_flags},
            {"entropy",             s.entropy},
            {"md5",                 s.md5},
            {"sha256",              s.sha256},
            {"is_executable",       s.is_executable},
            {"is_writable",         s.is_writable},
            {"is_readable",         s.is_readable},
            {"has_rwx",             s.has_rwx},
            {"raw_beyond_eof",      s.raw_beyond_eof},
        });
    }

    // Imports
    j["imports"] = nlohmann::json::array();
    for (auto& dll : info.imports) {
        nlohmann::json jdll;
        jdll["name"]              = dll.name;
        jdll["time_date_stamp"]   = dll.time_date_stamp;
        jdll["is_bound"]          = dll.is_bound;
        jdll["functions"]         = nlohmann::json::array();
        for (auto& fn : dll.functions) {
            jdll["functions"].push_back({
                {"name",       fn.name},
                {"ordinal",    fn.ordinal},
                {"by_ordinal", fn.by_ordinal},
                {"thunk_rva",  fn.thunk_rva},
                {"iat_rva",    fn.iat_rva},
                {"is_bound",   fn.is_bound},
                {"bound_address", fn.bound_address},
            });
        }
        j["imports"].push_back(jdll);
    }

    // Delay imports
    j["delay_imports"] = nlohmann::json::array();
    for (auto& dll : info.delay_imports) {
        nlohmann::json jd;
        jd["name"]      = dll.name;
        jd["functions"] = nlohmann::json::array();
        for (auto& fn : dll.functions)
            jd["functions"].push_back({{"name", fn.name}, {"ordinal", fn.ordinal}});
        j["delay_imports"].push_back(jd);
    }

    // Exports
    auto& ex = info.exports;
    j["exports"] = {
        {"present",            ex.present},
        {"name",               ex.name},
        {"ordinal_base",       ex.ordinal_base},
        {"number_of_functions",ex.number_of_functions},
        {"number_of_names",    ex.number_of_names},
        {"time_date_stamp",    ex.time_date_stamp},
        {"functions",          nlohmann::json::array()},
    };
    for (auto& fn : ex.functions)
        j["exports"]["functions"].push_back({
            {"name",            fn.name},
            {"ordinal",         fn.ordinal},
            {"address",         fn.address},
            {"is_forwarder",    fn.is_forwarder},
            {"forwarder_string",fn.forwarder_string},
            {"has_name",        fn.has_name},
        });

    // Resources
    j["resources"] = resource_node_to_json(info.resources);

    // Debug
    j["debug"] = nlohmann::json::array();
    for (auto& de : info.debug_entries)
        j["debug"].push_back({
            {"type",         de.type},
            {"type_str",     de.type_str},
            {"time_stamp",   de.time_date_stamp},
            {"major_version",de.major_version},
            {"minor_version",de.minor_version},
            {"size",         de.size_of_data},
            {"pdb_path",     de.pdb_path},
            {"guid",         de.guid},
            {"age",          de.age},
        });

    // TLS
    j["tls"] = {
        {"present",                   info.tls.present},
        {"start_address_of_raw_data", info.tls.start_address_of_raw_data},
        {"end_address_of_raw_data",   info.tls.end_address_of_raw_data},
        {"address_of_index",          info.tls.address_of_index},
        {"address_of_callbacks",      info.tls.address_of_callbacks},
        {"size_of_zero_fill",         info.tls.size_of_zero_fill},
        {"callbacks",                 info.tls.callbacks},
    };

    // Load Config
    j["load_config"] = {
        {"present",            info.load_config.present},
        {"has_cfg",            info.load_config.has_cfg},
        {"has_seh",            info.load_config.has_seh},
        {"has_security_cookie",info.load_config.has_security_cookie},
        {"security_cookie",    info.load_config.security_cookie},
        {"guard_flags",        info.load_config.guard_flags},
        {"guard_flags_decoded",info.load_config.guard_flags_decoded},
        {"seh_handler_count",  info.load_config.seh_handler_count},
    };

    // Exceptions
    j["exceptions_count"] = info.exceptions.size();
    j["exceptions"] = nlohmann::json::array();
    for (size_t i = 0; i < std::min(info.exceptions.size(), size_t(1000)); i++)
        j["exceptions"].push_back({
            {"begin", info.exceptions[i].begin_address},
            {"end",   info.exceptions[i].end_address},
            {"unwind",info.exceptions[i].unwind_info_address}
        });

    // Relocations
    j["relocations_blocks"] = info.relocations.size();
    j["relocations"] = nlohmann::json::array();
    for (auto& rb : info.relocations) {
        j["relocations"].push_back({
            {"virtual_address", rb.virtual_address},
            {"size",            rb.size_of_block},
            {"entry_count",     rb.entry_count},
        });
    }

    // CLR
    j["clr"] = {
        {"present",               info.clr.present},
        {"major_runtime_version", info.clr.major_runtime_version},
        {"minor_runtime_version", info.clr.minor_runtime_version},
        {"flags",                 info.clr.flags},
        {"flags_decoded",         info.clr.flags_decoded},
        {"entry_point_token",     info.clr.entry_point_token},
    };

    // Overlay
    j["overlay"] = {
        {"present",         info.overlay.present},
        {"offset",          info.overlay.offset},
        {"size",            info.overlay.size},
        {"entropy",         info.overlay.entropy},
        {"detected_format", info.overlay.detected_format},
        {"hex_preview",     info.overlay.hex_preview},
    };

    // Signature
    j["signature"] = {
        {"signed_file", info.signature.signed_file},
        {"verified",    info.signature.verified},
        {"signer",      info.signature.signer},
        {"issuer",      info.signature.issuer},
    };

    // Anomalies
    j["anomalies"] = nlohmann::json::array();
    for (auto& a : info.anomalies)
        j["anomalies"].push_back(anomaly_to_json(a));

    // Strings (first 2000)
    j["strings"] = nlohmann::json::array();
    for (size_t i = 0; i < std::min(info.strings.size(), size_t(2000)); i++) {
        auto& s = info.strings[i];
        j["strings"].push_back({
            {"value",    s.value},
            {"offset",   s.offset},
            {"encoding", s.encoding},
            {"section",  s.section},
            {"category", s.category},
        });
    }

    return j;
}

} // namespace pe
