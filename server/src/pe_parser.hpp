#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winnt.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <functional>
#include <nlohmann/json.hpp>

namespace pe {

// ─── Hashing ──────────────────────────────────────────────────────────────────
struct FileHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
    std::string imphash;       // Import hash
    std::string ssdeep;        // Fuzzy hash (optional)
};

// ─── Rich Header ──────────────────────────────────────────────────────────────
struct RichEntry {
    uint16_t build_id;
    uint16_t product_id;
    uint32_t use_count;
    std::string product_name;  // Resolved from known table
    std::string vs_version;
};

struct RichHeader {
    bool present = false;
    uint32_t xor_key = 0;
    uint32_t checksum = 0;
    bool checksum_valid = false;
    std::vector<RichEntry> entries;
    std::string raw_hex;       // Raw XOR'd bytes
};

// ─── DOS Header ───────────────────────────────────────────────────────────────
struct DosHeader {
    uint16_t e_magic;           // MZ
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint32_t e_lfanew;         // Offset to NT headers
    std::vector<uint8_t> stub; // DOS stub bytes
};

// ─── NT File Header ───────────────────────────────────────────────────────────
struct FileHeader {
    uint16_t machine;
    std::string machine_str;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    std::string timestamp_str;  // Parsed UTC
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
    std::vector<std::string> characteristics_flags;
};

// ─── Data Directory ───────────────────────────────────────────────────────────
struct DataDirectory {
    uint32_t virtual_address;
    uint32_t size;
    std::string name;
};

// ─── Optional Header ──────────────────────────────────────────────────────────
struct OptionalHeader {
    uint16_t magic;               // PE32 or PE32+
    bool is_64bit;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;        // Only PE32
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    bool checksum_valid;
    uint16_t subsystem;
    std::string subsystem_str;
    uint16_t dll_characteristics;
    std::vector<std::string> dll_characteristics_flags;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    std::vector<DataDirectory> data_directories;
};

// ─── Section ──────────────────────────────────────────────────────────────────
struct SectionInfo {
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
    std::vector<std::string> characteristics_flags;
    double   entropy;
    std::string md5;
    std::string sha256;
    bool     is_executable;
    bool     is_writable;
    bool     is_readable;
    bool     is_code;
    bool     is_initialized_data;
    bool     is_uninitialized_data;
    // Anomalies
    bool     has_rwx;            // Writable+Executable (suspicious)
    bool     size_mismatch;      // Virtual != Raw mismatch
    bool     raw_beyond_eof;     // Raw data extends beyond file
};

// ─── Import Table ─────────────────────────────────────────────────────────────
struct ImportedFunction {
    std::string name;
    uint16_t    ordinal;
    bool        by_ordinal;
    uint64_t    thunk_rva;
    uint64_t    iat_rva;
    std::string hint_name_table_rva_str;
    // Resolved binding
    uint64_t    bound_address;
    bool        is_bound;
};

struct ImportDLL {
    std::string name;
    uint32_t    name_rva;
    uint32_t    first_thunk;
    uint32_t    original_first_thunk;
    uint32_t    time_date_stamp;
    bool        is_bound;
    std::vector<ImportedFunction> functions;
};

struct DelayImportDLL {
    std::string name;
    uint32_t    attributes;
    uint32_t    dll_name_rva;
    uint32_t    hmodule_rva;
    uint32_t    iat_rva;
    uint32_t    int_rva;
    uint32_t    bound_iat_rva;
    uint32_t    unload_iat_rva;
    uint32_t    time_date_stamp;
    std::vector<ImportedFunction> functions;
};

// ─── Export Table ─────────────────────────────────────────────────────────────
struct ExportedFunction {
    std::string name;
    uint32_t    ordinal;
    uint32_t    address;
    bool        is_forwarder;
    std::string forwarder_string;
    uint32_t    name_rva;
    bool        has_name;
};

struct ExportDirectory {
    bool     present = false;
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    std::string name;          // DLL name
    uint32_t ordinal_base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    std::vector<ExportedFunction> functions;
};

// ─── Resources ────────────────────────────────────────────────────────────────
struct ResourceLeaf {
    uint32_t offset_to_data;
    uint32_t size;
    uint32_t code_page;
    std::string type_name;
    int      resource_id;
    std::string lang_str;
    // Content preview (first 256 bytes hex)
    std::string hex_preview;
    double   entropy;
    std::string detected_format; // PE, ZIP, PNG, etc.
};

struct ResourceNode {
    std::string name;
    int id = -1;
    bool is_named;
    bool is_directory;
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    std::vector<ResourceNode> children;
    std::optional<ResourceLeaf> leaf;
};

// ─── Debug Directory ──────────────────────────────────────────────────────────
struct DebugEntry {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t type;
    std::string type_str;
    uint32_t size_of_data;
    uint32_t address_of_raw_data;
    uint32_t pointer_to_raw_data;
    // For CodeView/PDB info
    std::string pdb_path;
    std::string guid;
    uint32_t age;
    // For Reproducible/REPRO
    std::string repro_hash;
};

// ─── TLS Directory ────────────────────────────────────────────────────────────
struct TlsDirectory {
    bool present = false;
    uint64_t start_address_of_raw_data;
    uint64_t end_address_of_raw_data;
    uint64_t address_of_index;
    uint64_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
    std::vector<uint64_t> callbacks;  // Resolved callback VAs
};

// ─── Load Config ──────────────────────────────────────────────────────────────
struct LoadConfig {
    bool present = false;
    uint32_t size;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t global_flags_clear;
    uint32_t global_flags_set;
    uint32_t critical_section_default_timeout;
    uint64_t decommit_free_block_threshold;
    uint64_t decommit_total_free_threshold;
    uint64_t lock_prefix_table;
    uint64_t maximum_allocation_size;
    uint64_t virtual_memory_threshold;
    uint64_t process_affinity_mask;
    uint32_t process_heap_flags;
    uint16_t csd_version;
    uint16_t dependent_load_flags;
    uint64_t edit_list;
    uint64_t security_cookie;
    // Guard CF
    uint64_t guard_cf_check_function_pointer;
    uint64_t guard_cf_dispatch_function_pointer;
    uint64_t guard_cf_function_table;
    uint64_t guard_cf_function_count;
    uint32_t guard_flags;
    std::vector<std::string> guard_flags_decoded;
    // SEH
    std::vector<uint64_t> seh_handler_table;
    uint64_t seh_handler_count;
    // CFG
    bool has_cfg;
    bool has_seh;
    bool has_security_cookie;
};

// ─── Exception Directory ──────────────────────────────────────────────────────
struct ExceptionEntry {
    uint32_t begin_address;
    uint32_t end_address;
    uint32_t unwind_info_address;
};

// ─── Relocation ───────────────────────────────────────────────────────────────
struct RelocationBlock {
    uint32_t virtual_address;
    uint32_t size_of_block;
    uint32_t entry_count;
    std::vector<std::pair<uint16_t, std::string>> entries; // (offset, type_str)
};

// ─── .NET / CLR Header ────────────────────────────────────────────────────────
struct ClrHeader {
    bool present = false;
    uint16_t major_runtime_version;
    uint16_t minor_runtime_version;
    uint32_t metadata_rva;
    uint32_t metadata_size;
    uint32_t flags;
    std::vector<std::string> flags_decoded;
    uint32_t entry_point_token;
    std::string assembly_name;
    std::string assembly_version;
    std::string target_framework;
};

// ─── Overlay ──────────────────────────────────────────────────────────────────
struct OverlayInfo {
    bool present = false;
    uint64_t offset;
    uint64_t size;
    double   entropy;
    std::string detected_format;
    std::string hex_preview;
};

// ─── Anomaly ──────────────────────────────────────────────────────────────────
struct Anomaly {
    enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL };
    Severity    severity;
    std::string category;
    std::string description;
    std::string detail;
};

// ─── Extracted String ─────────────────────────────────────────────────────────
struct ExtractedString {
    std::string value;
    uint64_t    offset;
    std::string encoding;  // ASCII, UTF-16LE
    std::string section;
    std::string category;  // URL, IP, Registry, Path, Email, etc.
};

// ─── Signature ────────────────────────────────────────────────────────────────
struct Signature {
    bool signed_file = false;
    bool verified    = false;
    std::string signer;
    std::string issuer;
    std::string serial;
    std::string not_before;
    std::string not_after;
    std::string digest_algorithm;
    std::vector<std::string> cert_chain;
    std::string countersign_time;
};

// ─── Full PE Result ───────────────────────────────────────────────────────────
struct PEInfo {
    bool     valid = false;
    std::string error;
    std::string file_path;
    uint64_t file_size;
    FileHashes  hashes;
    DosHeader   dos_header;
    RichHeader  rich_header;
    FileHeader  file_header;
    OptionalHeader optional_header;
    std::vector<SectionInfo>    sections;
    std::vector<ImportDLL>      imports;
    std::vector<DelayImportDLL> delay_imports;
    ExportDirectory             exports;
    ResourceNode                resources;
    std::vector<DebugEntry>     debug_entries;
    TlsDirectory                tls;
    LoadConfig                  load_config;
    std::vector<ExceptionEntry> exceptions;
    std::vector<RelocationBlock> relocations;
    ClrHeader                   clr;
    OverlayInfo                 overlay;
    std::vector<Anomaly>        anomalies;
    std::vector<ExtractedString> strings;
    Signature                   signature;
    // Statistics
    double   file_entropy;
    uint32_t string_count;
    uint32_t import_count;
    uint32_t export_count;
    uint64_t timestamp_epoch;
    // PE type
    std::string pe_type; // EXE, DLL, SYS, OCX, etc.
};

// ─── Parser Class ─────────────────────────────────────────────────────────────
class PEParser {
public:
    explicit PEParser(const std::string& path);
    explicit PEParser(const std::vector<uint8_t>& data, const std::string& name = "buffer");
    ~PEParser() = default;

    PEInfo parse();
    
    // Partial parsers for on-demand use
    nlohmann::json disassemble_range(uint64_t rva, uint32_t size, uint32_t max_insns = 1000);
    nlohmann::json get_hex_dump(uint64_t rva, uint32_t size);
    std::vector<uint8_t> get_section_data(const std::string& section_name);
    std::vector<uint8_t> get_raw_at_rva(uint64_t rva, uint32_t size);
    
private:
    std::vector<uint8_t> m_data;
    std::string          m_path;
    
    // Mapping helpers
    const uint8_t* base() const { return m_data.data(); }
    uint64_t       file_size() const { return m_data.size(); }
    bool           valid_offset(uint64_t off, uint64_t sz = 1) const;
    
    template<typename T>
    const T* ptr_at(uint64_t offset) const;
    
    template<typename T>
    T read_at(uint64_t offset) const;
    
    std::string  read_string(uint64_t offset, uint32_t max_len = 512) const;
    std::wstring read_wstring(uint64_t offset, uint32_t max_len = 512) const;
    
    // RVA translation
    uint64_t rva_to_offset(uint64_t rva) const;
    uint64_t offset_to_rva(uint64_t offset) const;
    
    // Sub-parsers
    DosHeader       parse_dos_header();
    RichHeader      parse_rich_header();
    FileHeader      parse_file_header(const IMAGE_FILE_HEADER* fh);
    OptionalHeader  parse_optional_header(uint64_t opt_offset);
    std::vector<SectionInfo> parse_sections(uint64_t sect_offset, uint16_t count);
    std::vector<ImportDLL>   parse_imports();
    std::vector<DelayImportDLL> parse_delay_imports();
    ExportDirectory parse_exports();
    ResourceNode    parse_resources();
    ResourceNode    parse_resource_dir(uint64_t base_offset, uint64_t dir_offset,
                                       int depth, const std::string& type_name, int type_id);
    std::vector<DebugEntry>  parse_debug();
    TlsDirectory    parse_tls();
    LoadConfig      parse_load_config();
    std::vector<ExceptionEntry> parse_exceptions();
    std::vector<RelocationBlock> parse_relocations();
    ClrHeader       parse_clr();
    OverlayInfo     detect_overlay();
    std::vector<Anomaly> detect_anomalies(const PEInfo& info);
    std::vector<ExtractedString> extract_strings();
    FileHashes      compute_hashes();
    Signature       parse_signature();
    
    // Helpers
    double compute_entropy(const uint8_t* data, size_t size) const;
    std::string detect_format(const uint8_t* data, size_t size) const;
    std::string hash_md5(const uint8_t* data, size_t size) const;
    std::string hash_sha256(const uint8_t* data, size_t size) const;
    std::string compute_imphash(const std::vector<ImportDLL>& imports) const;
    std::string categorize_string(const std::string& s) const;
    std::string decode_timestamp(uint32_t ts) const;
    std::string resolve_machine(uint16_t machine) const;
    std::string resolve_subsystem(uint16_t sub) const;
    std::vector<std::string> decode_characteristics(uint16_t chars) const;
    std::vector<std::string> decode_dll_characteristics(uint16_t chars) const;
    std::vector<std::string> decode_section_characteristics(uint32_t chars) const;
    std::string resolve_resource_type(int type_id) const;
    std::string resolve_debug_type(uint32_t type) const;
    std::string resolve_reloc_type(uint16_t type) const;
    std::string resolve_rich_product(uint16_t pid) const;
    
    // Section list for RVA translation
    struct Section {
        uint32_t va;
        uint32_t vsize;
        uint32_t raw_off;
        uint32_t raw_size;
    };
    std::vector<Section> m_sections;
    bool                 m_is_64bit = false;
    uint64_t             m_image_base = 0;
    uint32_t             m_nt_offset = 0;
    IMAGE_DATA_DIRECTORY m_data_dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {};
};

// ─── JSON Serialization ───────────────────────────────────────────────────────
nlohmann::json pe_info_to_json(const PEInfo& info);

} // namespace pe
