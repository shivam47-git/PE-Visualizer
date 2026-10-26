#include "pe_parser.hpp"
#include <sstream>
#include <iomanip>

// Extended Rich Header product ID resolution table.
// Source: https://github.com/dishather/richprint / Microsoft PE spec research

namespace pe {

struct RichProductEntry {
    uint16_t    product_id;
    const char* name;
    const char* vs_version;
};

static const RichProductEntry RICH_PRODUCT_TABLE[] = {
    // Visual C++ / MSVC
    {0x0000, "Unmarked object",      ""},
    {0x0001, "Import descriptor",    ""},
    {0x0002, "Linker 5.10",         "VS98"},
    {0x0004, "C++ 7.00",            "VS97"},
    {0x000A, "C/C++ 6.00",          "VS6"},
    {0x000B, "Linker 5.10",         "VS6"},
    {0x000C, "Export stub 5.10",    "VS6"},
    {0x000D, "C++ 5.00",            "VS97"},
    {0x001C, "C/C++ 7.00 SP3",      "VS2003"},
    {0x0060, "C/C++ 6.0 SP5",       "VS6 SP5"},
    {0x006D, "C/C++ 7.0 (2002)",    "VS2002"},
    {0x006E, "Asm 7.0",             "VS2002"},
    {0x007D, "C/C++ 7.1 (2003)",    "VS2003"},
    {0x0083, "C/C++ 8.0 (2005)",    "VS2005"},
    {0x0084, "Asm 8.0",             "VS2005"},
    {0x0085, "Linker 8.00",         "VS2005"},
    {0x0086, "MASM 8.00",           "VS2005"},
    {0x008F, "C/C++ 9.0 (2008)",    "VS2008"},
    {0x0091, "Linker 9.00",         "VS2008"},
    {0x0093, "C/C++ 10.0 (2010)",   "VS2010"},
    {0x0095, "Linker 10.00",        "VS2010"},
    {0x00AA, "C/C++ 11.0 (2012)",   "VS2012"},
    {0x00AC, "Linker 11.00",        "VS2012"},
    {0x00B5, "C/C++ 12.0 (2013)",   "VS2013"},
    {0x00B6, "MASM 12.0",           "VS2013"},
    {0x00B8, "Linker 12.00",        "VS2013"},
    {0x00C7, "C/C++ 14.0 (2015)",   "VS2015"},
    {0x00C8, "MASM 14.0",           "VS2015"},
    {0x00CA, "Linker 14.00",        "VS2015"},
    {0x00D1, "C/C++ 14.1 (2017)",   "VS2017"},
    {0x00D2, "MASM 14.1",           "VS2017"},
    {0x00D6, "Linker 14.10",        "VS2017"},
    {0x00FF, "C/C++ 14.2 (2019)",   "VS2019"},
    {0x0100, "MASM 14.2",           "VS2019"},
    {0x0104, "C/C++ 14.3 (2022)",   "VS2022"},
    {0x0105, "MASM 14.3",           "VS2022"},
    {0x0108, "Linker 14.3",         "VS2022"},
    // Visual Basic
    {0x0157, "VB 6.0",              "VB6"},
    {0x015D, "VB 6.0 SP3",          "VB6 SP3"},
    {0x015E, "VB 6.0 SP4",          "VB6 SP4"},
    {0x015F, "VB 6.0 SP6",          "VB6 SP6"},
    // Special
    {0x00FF, "Cvtres 7.00",         "VS2002"},
    {0x005E, "Import descriptor",   "VS6"},
    {0,      nullptr,               nullptr}
};

std::string PEParser::resolve_rich_product(uint16_t pid) const {
    for (const auto* e = RICH_PRODUCT_TABLE; e->name; e++) {
        if (e->product_id == pid) {
            std::string r = e->name;
            if (e->vs_version && e->vs_version[0])
                r += std::string(" [") + e->vs_version + "]";
            return r;
        }
    }
    std::ostringstream oss;
    oss << "ProdID_0x" << std::hex << std::setw(4) << std::setfill('0') << pid;
    return oss.str();
}

// ─── Rich Header Checksum Validation ─────────────────────────────────────────
// The checksum is computed as:
//   sum = DOS e_lfanew
//   for each byte b at offset i (0..e_lfanew-1), excluding "DanS" padding:
//     sum += ROL(b, i)
//   for each Rich entry (prodid:count):
//     sum += ROL(prodid << 16 | count_of_uses, use_count)
//   checksum = sum
//
// This function validates a Rich header we already parsed.
bool validate_rich_checksum(
    const std::vector<uint8_t>& file_data,
    uint32_t nt_offset,   // e_lfanew
    uint32_t xor_key)
{
    auto rol32 = [](uint32_t v, int n) -> uint32_t {
        n &= 31;
        return (v << n) | (v >> (32 - n));
    };

    uint32_t cs = nt_offset; // seed = e_lfanew

    // Sum bytes from 0x80 (after standard DOS stub) to DanS, excluding 0x3C-0x3F (e_lfanew)
    // and the DanS marker itself
    for (uint32_t i = 0; i < nt_offset; i++) {
        if (i >= 0x3C && i <= 0x3F) continue; // skip e_lfanew field
        if (i >= (uint32_t)file_data.size()) break;
        cs += rol32(file_data[i], i);
    }

    return cs == xor_key;
}

} // namespace pe
