#include "pe_parser.hpp"
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cctype>

namespace pe {

// ─── String Categorization Patterns ──────────────────────────────────────────
static const std::vector<std::pair<std::string, std::regex>> CATEGORY_PATTERNS = {
    {"URL",
     std::regex(R"(https?://[\w\-./:%?=&@#+]+)", std::regex::icase | std::regex::optimize)},
    {"IP Address",
     std::regex(R"(\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b)",
                std::regex::optimize)},
    {"Email",
     std::regex(R"([\w.+\-]+@[\w\-]+\.[\w]{2,})", std::regex::icase | std::regex::optimize)},
    {"Registry",
     std::regex(R"(HKEY_|HKLM\\|HKCU\\|HKCR\\|HKU\\|HKCC\\|Software\\|System\\CurrentControlSet)",
                std::regex::icase | std::regex::optimize)},
    {"File Path",
     std::regex(R"([A-Za-z]:\\[\\\\w\s.\-:(){}@#$%^&!+,;'`~]+|\\\\[\w.$\-]+(\\[\w.\-$]+)+)",
                std::regex::optimize)},
    {"Base64",
     std::regex(R"([A-Za-z0-9+/]{40,}={0,2})", std::regex::optimize)},
    {"Hex String",
     std::regex(R"((?:0x[0-9A-Fa-f]{4,}|[0-9A-Fa-f]{16,}))", std::regex::optimize)},
    {"GUID",
     std::regex(R"(\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})",
                std::regex::optimize)},
    {"Domain",
     std::regex(R"(\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|co|ru|cn|de|uk|info|biz|xyz|top|pw|cc)\b)",
                std::regex::icase | std::regex::optimize)},
    {"API Import",
     std::regex(R"(^[A-Z][a-zA-Z0-9]{4,}(?:A|W|Ex)?$)", std::regex::optimize)},
};

// ─── Interesting keyword set (lowercase) ──────────────────────────────────────
// Use unordered_set of substrings for O(1) lookup instead of O(N) linear scan.
static const std::unordered_set<std::string> INTERESTING_KEYWORDS = {
    "password","passwd","secret","token","apikey","api_key",
    "private","credential","username","admin",
    "cmd.exe","powershell","wscript","cscript",
    "inject","shellcode","exploit","payload",
    "encrypt","decrypt","cipher",
    "base64","xor","rot13",
    "createprocess","loadlibrary","getprocaddress",
    "virtualalloc","writeprocess","readprocess",
    "hkey_local_machine","hkey_current_user",
    "software\\microsoft\\windows\\currentversion\\run",
    "\\system32\\","\\syswow64\\",
    ".exe",".dll",".bat",".ps1",".vbs",
    "mimikatz","meterpreter","cobalt","beacon",
    "mutex","event","pipe","mailslot",
};

static const int MIN_STRING_LEN = 4;
static const int MAX_STRING_LEN = 512;
static const int MAX_TOTAL      = 100000;

std::string PEParser::categorize_string(const std::string& s) const {
    if ((int)s.size() < MIN_STRING_LEN) return "Generic";

    for (auto& [cat, re] : CATEGORY_PATTERNS) {
        if (std::regex_search(s, re)) return cat;
    }

    // Case-insensitive keyword match using lowercased string
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (auto& kw : INTERESTING_KEYWORDS) {
        if (lower.find(kw) != std::string::npos)
            return "Interesting";
    }
    return "Generic";
}

std::vector<ExtractedString> PEParser::extract_strings() {
    std::vector<ExtractedString> results;
    results.reserve(8192);

    // Build section name lookup: [raw_off, raw_off+raw_size) → section name
    // This avoids the get_section_name lambda returning "sec_N" instead of real names.
    struct SectionRange {
        uint64_t    start;
        uint64_t    end;
        std::string name;
    };
    std::vector<SectionRange> sec_ranges;
    sec_ranges.reserve(m_sections.size());

    // Cross-reference m_sections (address info) with info.sections (names).
    // We stored section order identically, so index aligns.
    // However pe_parser.cpp builds m_sections without names. We store them here
    // by re-reading the section headers via the already-populated m_sections vector
    // and matching against what was parsed. For full name resolution, walk NT headers.
    {
        uint64_t sect_hdr_off = m_nt_offset + 4
            + sizeof(IMAGE_FILE_HEADER)
            + read_at<uint16_t>(m_nt_offset + 4 + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));

        uint16_t num_sections = read_at<uint16_t>(
            m_nt_offset + 4 + offsetof(IMAGE_FILE_HEADER, NumberOfSections));

        for (uint16_t i = 0; i < num_sections && i < (uint16_t)m_sections.size(); i++) {
            uint64_t sh_off = sect_hdr_off + (uint64_t)i * sizeof(IMAGE_SECTION_HEADER);
            if (!valid_offset(sh_off, sizeof(IMAGE_SECTION_HEADER))) break;

            char name_buf[9] = {};
            std::memcpy(name_buf,
                reinterpret_cast<const char*>(base() + sh_off), 8);

            auto& s = m_sections[i];
            sec_ranges.push_back({
                s.raw_off,
                s.raw_off + std::max(s.raw_size, uint32_t(1)),
                name_buf
            });
        }
    }

    auto get_section_name = [&](uint64_t offset) -> std::string {
        for (auto& sr : sec_ranges) {
            if (offset >= sr.start && offset < sr.end)
                return sr.name;
        }
        uint64_t first_raw = sec_ranges.empty() ? 0x200 : sec_ranges.front().start;
        return offset < first_raw ? ".header" : ".overlay";
    };

    auto flush_string = [&](std::string& cur, uint64_t start_off, const std::string& enc) {
        if ((int)cur.size() >= MIN_STRING_LEN && (int)cur.size() <= MAX_STRING_LEN) {
            ExtractedString es;
            es.value    = cur;
            es.offset   = start_off;
            es.encoding = enc;
            es.section  = get_section_name(start_off);
            es.category = categorize_string(cur);
            results.push_back(std::move(es));
        }
        cur.clear();
    };

    // ── ASCII strings ──────────────────────────────────────────────────────────
    {
        std::string cur;
        uint64_t start_off = 0;
        for (uint64_t i = 0; i < m_data.size() && (int)results.size() < MAX_TOTAL; i++) {
            uint8_t b = m_data[i];
            if ((b >= 0x20 && b < 0x7F) || b == 0x09 || b == 0x0A || b == 0x0D) {
                if (cur.empty()) start_off = i;
                cur += static_cast<char>(b);
                if ((int)cur.size() >= MAX_STRING_LEN) flush_string(cur, start_off, "ASCII");
            } else {
                flush_string(cur, start_off, "ASCII");
            }
        }
        flush_string(cur, 0, "ASCII");
    }

    // ── UTF-16LE strings ───────────────────────────────────────────────────────
    {
        std::string cur;
        uint64_t start_off = 0;
        for (uint64_t i = 0; i + 1 < m_data.size() && (int)results.size() < MAX_TOTAL; i += 2) {
            uint16_t wc = static_cast<uint16_t>(m_data[i]) |
                          (static_cast<uint16_t>(m_data[i + 1]) << 8);
            if ((wc >= 0x0020 && wc < 0x007F) || wc == 0x0009 || wc == 0x000A || wc == 0x000D) {
                if (cur.empty()) start_off = i;
                cur += static_cast<char>(wc & 0xFF);
                if ((int)cur.size() >= MAX_STRING_LEN) flush_string(cur, start_off, "UTF-16LE");
            } else if (wc >= 0x0080 && wc < 0x0100) {
                if (cur.empty()) start_off = i;
                cur += '?';
            } else {
                flush_string(cur, start_off, "UTF-16LE");
            }
        }
        flush_string(cur, 0, "UTF-16LE");
    }

    // Sort by file offset for consistent output
    std::stable_sort(results.begin(), results.end(),
        [](const ExtractedString& a, const ExtractedString& b) {
            return a.offset < b.offset;
        });

    return results;
}

// ─── ImpHash ──────────────────────────────────────────────────────────────────
std::string PEParser::compute_imphash(const std::vector<ImportDLL>& imports) const {
    auto normalize_dll = [](std::string name) -> std::string {
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        for (auto& ext : {".dll", ".ocx", ".sys"}) {
            size_t el = strlen(ext);
            if (name.size() > el && name.substr(name.size() - el) == ext)
                name = name.substr(0, name.size() - el);
        }
        return name;
    };

    auto normalize_fn = [](std::string name) -> std::string {
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        return name;
    };

    std::string imp_string;
    bool first = true;
    for (auto& dll : imports) {
        std::string dll_name = normalize_dll(dll.name);
        for (auto& fn : dll.functions) {
            if (fn.by_ordinal) continue;
            if (!first) imp_string += ',';
            first = false;
            imp_string += dll_name + '.' + normalize_fn(fn.name);
        }
    }

    if (imp_string.empty()) return "";
    return hash_md5(
        reinterpret_cast<const uint8_t*>(imp_string.data()),
        imp_string.size());
}

} // namespace pe
