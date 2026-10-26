#include "pe_parser.hpp"
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <regex>

namespace pe {

// ─── Known Packer Section Names ───────────────────────────────────────────────
static const std::unordered_set<std::string> PACKER_SECTIONS = {
    "UPX0","UPX1","UPX2",
    ".nsp0",".nsp1",".nsp2",
    "ASPack",".aspack",".adata",
    "PECompact",".pec",".pec1",".pec2",
    "NSPack",
    "Themida",".themida",
    "obsidium",".obs",
    ".vmp0",".vmp1",
    ".boot",".petite",".shrink1",
    "FSG!",".fsg",
    "MPRESS1","MPRESS2",
    "yP","yG",
    ".enigma1",".enigma2",
};

// ─── Suspicious DLL Names ─────────────────────────────────────────────────────
static const std::unordered_set<std::string> SUSPICIOUS_DLLS = {
    "MSWSOCK.DLL","WS2_32.DLL","WININET.DLL","URLMON.DLL",
    "WINHTTP.DLL","RASAPI32.DLL",
};

// ─── API Sets for behavioral classification ───────────────────────────────────
// Store as unordered_sets for O(1) lookup. The original code used
// std::vector + triple nested loop → O(imports × functions × apis) which is
// O(N³) and collapses on 100k strings or large import tables.
static const std::unordered_set<std::string> ANTI_DEBUG_APIS = {
    "IsDebuggerPresent","CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess","OutputDebugStringA","OutputDebugStringW",
    "ZwSetInformationThread","NtSetInformationThread",
    "QueryPerformanceCounter","GetTickCount",
    "FindWindowA","FindWindowW",
    "ZwQueryInformationProcess","NtQuerySystemInformation",
    "DbgBreakPoint","DbgUiRemoteBreakin",
};

static const std::unordered_set<std::string> INJECTION_APIS = {
    "VirtualAllocEx","VirtualProtectEx",
    "WriteProcessMemory","ReadProcessMemory",
    "CreateRemoteThread","CreateRemoteThreadEx",
    "NtCreateThreadEx","RtlCreateUserThread",
    "QueueUserAPC","NtQueueApcThread",
    "SetThreadContext",
    "OpenProcess","NtOpenProcess",
    "MapViewOfFile","NtMapViewOfSection","NtCreateSection",
};

static const std::unordered_set<std::string> NETWORK_APIS = {
    "InternetOpenA","InternetOpenW",
    "InternetOpenUrlA","InternetOpenUrlW",
    "HttpSendRequestA","HttpSendRequestW",
    "WSAConnect","WSAStartup",
    "connect","send","recv",
    "WinHttpOpen","WinHttpConnect",
    "URLDownloadToFileA","URLDownloadToFileW",
    "FtpPutFileA",
};

static const std::unordered_set<std::string> PERSISTENCE_APIS = {
    "RegSetValueExA","RegSetValueExW",
    "RegCreateKeyExA","RegCreateKeyExW",
    "CreateServiceA","CreateServiceW",
    "ChangeServiceConfigA","SHSetValue",
};

static const std::unordered_set<std::string> EVASION_APIS = {
    "VirtualProtect","HeapCreate",
    "NtAllocateVirtualMemory","ZwAllocateVirtualMemory",
    "RtlDecompressBuffer","RtlDecryptMemory",
    "BCryptDecrypt","CryptDecrypt",
};

// Build a flat set of all imported function names in O(N) then do O(1) per-API lookups.
// This collapses the original O(imports × functions × |api_list|) to O(imports × functions + |api_lists|).
struct ImportProfile {
    std::unordered_set<std::string> all_names;  // all imported function names
    int anti_debug = 0;
    int injection  = 0;
    int network    = 0;
    int persistence= 0;
    int evasion    = 0;

    explicit ImportProfile(const std::vector<ImportDLL>& imports) {
        for (auto& dll : imports)
            for (auto& fn : dll.functions)
                if (!fn.name.empty())
                    all_names.insert(fn.name);

        for (auto& name : all_names) {
            if (ANTI_DEBUG_APIS.count(name))  anti_debug++;
            if (INJECTION_APIS.count(name))   injection++;
            if (NETWORK_APIS.count(name))     network++;
            if (PERSISTENCE_APIS.count(name)) persistence++;
            if (EVASION_APIS.count(name))     evasion++;
        }
    }
};

// ─── Extended Anomaly Detection ───────────────────────────────────────────────
std::vector<Anomaly> detect_extended_anomalies(const PEInfo& info) {
    std::vector<Anomaly> out;

    auto add = [&](Anomaly::Severity sev, const std::string& cat,
                   const std::string& desc, const std::string& detail = "") {
        out.push_back({sev, cat, desc, detail});
    };

    // Build import profile once — O(N) instead of O(N³)
    ImportProfile profile(info.imports);

    // ── Packer section names ────────────────────────────────────────────────
    for (auto& s : info.sections) {
        if (PACKER_SECTIONS.count(s.name))
            add(Anomaly::Severity::HIGH, "Packer",
                "Known packer section name: " + s.name,
                "File is likely packed with a known packer");
    }

    // ── Unusual characters in section names ────────────────────────────────
    for (auto& s : info.sections) {
        for (char c : s.name) {
            if (c != '\0' && (c < 0x20 || c > 0x7E)) {
                add(Anomaly::Severity::LOW, "Section",
                    "Section with non-printable characters in name",
                    "Section: [" + s.name + "]");
                break;
            }
        }
    }

    // ── Import behavioral analysis ──────────────────────────────────────────
    if (profile.anti_debug >= 3)
        add(Anomaly::Severity::HIGH, "AntiAnalysis",
            "Multiple anti-debugging APIs (" + std::to_string(profile.anti_debug) + ")",
            "Heavy use of anti-debug techniques");
    else if (profile.anti_debug > 0)
        add(Anomaly::Severity::MEDIUM, "AntiAnalysis",
            "Anti-debugging API found (" + std::to_string(profile.anti_debug) + ")");

    if (profile.injection >= 4)
        add(Anomaly::Severity::CRITICAL, "Injection",
            "Full process injection API set (" + std::to_string(profile.injection) + " APIs)",
            "Pattern matches process hollowing or injection toolkit");
    else if (profile.injection >= 2)
        add(Anomaly::Severity::HIGH, "Injection",
            "Process injection APIs (" + std::to_string(profile.injection) + ")");

    if (profile.network > 0)
        add(Anomaly::Severity::MEDIUM, "Network",
            "Network API imports found (" + std::to_string(profile.network) + ")",
            "File makes network connections");

    if (profile.persistence > 0)
        add(Anomaly::Severity::HIGH, "Persistence",
            "Persistence-related API imports (" + std::to_string(profile.persistence) + ")");

    if (profile.evasion >= 2)
        add(Anomaly::Severity::HIGH, "Evasion",
            "Evasion-related API imports (" + std::to_string(profile.evasion) + ")");

    // ── Rich Header checksum mismatch ───────────────────────────────────────
    if (info.rich_header.present && !info.rich_header.checksum_valid)
        add(Anomaly::Severity::MEDIUM, "RichHeader",
            "Rich header checksum mismatch",
            "File may have been modified (patched/repacked) after compilation");

    // ── EP exactly at section start (not in code) ───────────────────────────
    uint32_t ep = info.optional_header.address_of_entry_point;
    for (auto& s : info.sections) {
        if (ep == s.virtual_address && !s.is_code)
            add(Anomaly::Severity::HIGH, "EntryPoint",
                "Entry point exactly at start of non-code section: " + s.name,
                "Common packer behavior");
    }

    // ── Section virtual/raw size anomalies ──────────────────────────────────
    for (auto& s : info.sections) {
        if (s.raw_size == 0 && s.virtual_size > 0x10000)
            add(Anomaly::Severity::MEDIUM, "Section",
                "Large virtual section with zero raw data: " + s.name,
                "Possible BSS or loader-resolved section");

        if (s.virtual_size > 0 && s.raw_size > 0) {
            double ratio = static_cast<double>(s.raw_size) / s.virtual_size;
            if (ratio < 0.1 && s.virtual_size > 0x10000)
                add(Anomaly::Severity::MEDIUM, "Section",
                    "Suspicious virtual/raw size ratio in " + s.name,
                    "VirtSize=" + std::to_string(s.virtual_size) +
                    " RawSize="  + std::to_string(s.raw_size));
        }
    }

    // ── Duplicate section names ─────────────────────────────────────────────
    std::unordered_map<std::string, int> sec_name_count;
    for (auto& s : info.sections) sec_name_count[s.name]++;
    for (auto& [name, cnt] : sec_name_count)
        if (cnt > 1 && !name.empty())
            add(Anomaly::Severity::LOW, "Section",
                "Duplicate section name: " + name + " (" + std::to_string(cnt) + " times)");

    // ── EXE with many exports ───────────────────────────────────────────────
    if (!(info.file_header.characteristics & IMAGE_FILE_DLL) &&
        info.exports.present && info.exports.number_of_functions > 50)
        add(Anomaly::Severity::MEDIUM, "Exports",
            "EXE with many exports (" + std::to_string(info.exports.number_of_functions) + ")",
            "Unusual for non-DLL executables");

    // ── Mixed-mode .NET ─────────────────────────────────────────────────────
    if (info.clr.present && info.imports.size() > 5) {
        bool il_only = false;
        for (auto& f : info.clr.flags_decoded)
            if (f == "IL_ONLY") { il_only = true; break; }
        if (!il_only)
            add(Anomaly::Severity::INFO, "CLR",
                "Mixed-mode .NET assembly (native + managed code)");
    }

    // ── Network DLL imports ─────────────────────────────────────────────────
    for (auto& dll : info.imports) {
        std::string upper = dll.name;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
        if (SUSPICIOUS_DLLS.count(upper))
            add(Anomaly::Severity::INFO, "Network",
                "Imports from network DLL: " + dll.name,
                std::to_string(dll.functions.size()) + " functions");
    }

    // ── String-based IOC counters ───────────────────────────────────────────
    int url_count = 0, ip_count = 0, reg_count = 0;
    for (auto& s : info.strings) {
        if      (s.category == "URL")       url_count++;
        else if (s.category == "IP Address") ip_count++;
        else if (s.category == "Registry")  reg_count++;
    }

    if (url_count > 5)
        add(Anomaly::Severity::MEDIUM, "Indicators",
            std::to_string(url_count) + " hardcoded URLs found",
            "May include C2 or download URLs");
    if (ip_count > 3)
        add(Anomaly::Severity::MEDIUM, "Indicators",
            std::to_string(ip_count) + " hardcoded IP addresses found");
    if (reg_count > 5)
        add(Anomaly::Severity::MEDIUM, "Indicators",
            std::to_string(reg_count) + " registry key strings found",
            "May indicate persistence or configuration storage");

    // ── File/Section alignment sanity ───────────────────────────────────────
    uint32_t fa = info.optional_header.file_alignment;
    uint32_t sa = info.optional_header.section_alignment;
    if (fa > 0 && sa > 0) {
        if (fa > sa)
            add(Anomaly::Severity::MEDIUM, "Header",
                "FileAlignment > SectionAlignment",
                "Invalid per PE specification");
        if (fa != 0 && (fa & (fa - 1)) != 0)
            add(Anomaly::Severity::LOW, "Header",
                "FileAlignment not a power of 2: " + std::to_string(fa));
        if (sa != 0 && (sa & (sa - 1)) != 0)
            add(Anomaly::Severity::LOW, "Header",
                "SectionAlignment not a power of 2: " + std::to_string(sa));
    }

    // ── SizeOfImage vs actual section layout ────────────────────────────────
    uint32_t max_va = 0;
    for (auto& s : info.sections)
        max_va = std::max(max_va, s.virtual_address + s.virtual_size);
    if (max_va > 0 && info.optional_header.size_of_image < max_va)
        add(Anomaly::Severity::HIGH, "Header",
            "SizeOfImage smaller than last section end",
            "SizeOfImage=" + std::to_string(info.optional_header.size_of_image) +
            " LastSectionEnd=" + std::to_string(max_va));

    // ── Bloated SizeOfImage (anti-analysis) ────────────────────────────────
    if (info.optional_header.size_of_image > 0x10000000)
        add(Anomaly::Severity::MEDIUM, "Header",
            "Unusually large SizeOfImage: " +
            std::to_string(info.optional_header.size_of_image / 1024 / 1024) + " MB",
            "Anti-analysis: forces large allocation on load");

    // ── Non-standard NumberOfRvaAndSizes ────────────────────────────────────
    uint32_t nrvas = info.optional_header.number_of_rva_and_sizes;
    if (nrvas > 0 && nrvas < 16)
        add(Anomaly::Severity::LOW, "Header",
            "NumberOfRvaAndSizes = " + std::to_string(nrvas),
            "Non-standard value; may cause loader behavior differences");

    return out;
}

} // namespace pe
