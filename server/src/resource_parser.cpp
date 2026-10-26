#include "pe_parser.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace pe {

// ─── VS_VERSIONINFO parser ─────────────────────────────────────────────────────
struct VersionInfo {
    std::string file_version;
    std::string product_version;
    std::string company_name;
    std::string product_name;
    std::string original_filename;
    std::string file_description;
    std::string legal_copyright;
    std::string comments;
    std::string internal_name;
};

static VersionInfo parse_version_info(const uint8_t* data, size_t size) {
    VersionInfo vi;
    if (size < 40) return vi;

    // Find VS_FIXEDFILEINFO magic (0xFEEF04BD)
    for (size_t i = 0; i + sizeof(VS_FIXEDFILEINFO) <= size; i++) {
        uint32_t sig;
        std::memcpy(&sig, data + i, sizeof(sig));
        if (sig != 0xFEEF04BD) continue;

        VS_FIXEDFILEINFO ffi;
        std::memcpy(&ffi, data + i, sizeof(ffi));   // safe aligned copy

        auto fmt_ver = [](uint32_t ms, uint32_t ls) -> std::string {
            return std::to_string(HIWORD(ms)) + "." + std::to_string(LOWORD(ms)) + "." +
                   std::to_string(HIWORD(ls)) + "." + std::to_string(LOWORD(ls));
        };
        vi.file_version    = fmt_ver(ffi.dwFileVersionMS,    ffi.dwFileVersionLS);
        vi.product_version = fmt_ver(ffi.dwProductVersionMS, ffi.dwProductVersionLS);
        break;
    }

    // UTF-16LE key→value extraction: find known field names encoded as UTF-16LE
    // then read the value string that follows the key, length prefix, and alignment.
    auto read_wstr_at = [&](size_t off) -> std::string {
        std::string result;
        result.reserve(64);
        while (off + 1 < size) {
            uint16_t wc;
            std::memcpy(&wc, data + off, 2);   // unaligned-safe
            if (!wc) break;
            result += (wc < 128) ? static_cast<char>(wc) : '?';
            off += 2;
        }
        return result;
    };

    static const std::vector<std::pair<std::string, std::string*>> FIELDS = {
        {"CompanyName",     &vi.company_name},
        {"ProductName",     &vi.product_name},
        {"FileDescription", &vi.file_description},
        {"OriginalFilename",&vi.original_filename},
        {"LegalCopyright",  &vi.legal_copyright},
        {"Comments",        &vi.comments},
        {"InternalName",    &vi.internal_name},
    };

    for (auto& [key, dst] : FIELDS) {
        // Build UTF-16LE pattern for key + null terminator
        std::vector<uint8_t> pat;
        pat.reserve(key.size() * 2 + 2);
        for (char c : key) { pat.push_back((uint8_t)c); pat.push_back(0); }
        pat.push_back(0); pat.push_back(0);

        for (size_t i = 0; i + pat.size() + 8 < size; i++) {
            if (std::memcmp(data + i, pat.data(), pat.size()) != 0) continue;

            size_t val_off = i + pat.size();
            // Align to 4-byte boundary
            val_off = (val_off + 3) & ~size_t(3);
            if (val_off + 6 >= size) break;

            // Skip wLength (2) + wValueLength (2) + wType (2)
            val_off += 6;
            // Align again
            val_off = (val_off + 3) & ~size_t(3);

            *dst = read_wstr_at(val_off);
            break;
        }
    }

    return vi;
}

// ─── Manifest XML extractor ───────────────────────────────────────────────────
static std::string extract_manifest_info(const uint8_t* data, size_t size) {
    std::string xml(reinterpret_cast<const char*>(data),
                    std::min(size, size_t(4096)));
    // Strip UTF-8 BOM
    if (xml.size() >= 3 &&
        (uint8_t)xml[0] == 0xEF &&
        (uint8_t)xml[1] == 0xBB &&
        (uint8_t)xml[2] == 0xBF)
        xml = xml.substr(3);
    return xml;
}

// ─── Resource data enrichment ─────────────────────────────────────────────────
nlohmann::json enrich_resource_leaf(
    const uint8_t* data, size_t size,
    const std::string& type_name)
{
    nlohmann::json extra;
    if (type_name == "RT_VERSION" && size > 40) {
        auto vi = parse_version_info(data, size);
        extra["version_info"] = {
            {"file_version",     vi.file_version},
            {"product_version",  vi.product_version},
            {"company_name",     vi.company_name},
            {"product_name",     vi.product_name},
            {"file_description", vi.file_description},
            {"original_filename",vi.original_filename},
            {"legal_copyright",  vi.legal_copyright},
            {"internal_name",    vi.internal_name},
            {"comments",         vi.comments},
        };
    } else if (type_name == "RT_MANIFEST") {
        extra["manifest_xml"] = extract_manifest_info(data, size);
    }
    return extra;
}

// ─── RT_STRING table parser ────────────────────────────────────────────────────
// RT_STRING stores 16 UTF-16LE length-prefixed strings per block.
// Fixed: original used raw pointer casts on potentially misaligned data.
// Use memcpy to perform unaligned-safe reads throughout.
std::vector<std::string> parse_string_table(const uint8_t* data, size_t size) {
    std::vector<std::string> strs;
    strs.reserve(16);
    size_t off = 0;

    while (off + 2 <= size && strs.size() < 16) {
        uint16_t len;
        std::memcpy(&len, data + off, 2);  // unaligned-safe
        off += 2;

        std::string s;
        s.reserve(len);
        for (uint16_t i = 0; i < len && off + 2 <= size; i++, off += 2) {
            uint16_t wc;
            std::memcpy(&wc, data + off, 2);
            s += (wc < 128) ? static_cast<char>(wc) : '?';
        }
        strs.push_back(std::move(s));
    }
    return strs;
}

} // namespace pe
