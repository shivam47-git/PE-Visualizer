#include "pe_parser.hpp"
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace pe {

// ─── Shannon Entropy ──────────────────────────────────────────────────────────
double compute_entropy_standalone(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = static_cast<double>(freq[i]) / size;
        ent -= p * std::log2(p);
    }
    return ent;
}

// ─── Byte frequency histogram ─────────────────────────────────────────────────
std::array<uint32_t, 256> byte_histogram(const uint8_t* data, size_t size) {
    std::array<uint32_t, 256> hist{};
    for (size_t i = 0; i < size; i++) hist[data[i]]++;
    return hist;
}

// ─── Chi-square test for randomness ──────────────────────────────────────────
// Returns chi-square statistic. Values near 256 = uniform (encrypted/compressed).
double chi_square(const uint8_t* data, size_t size) {
    if (size < 256) return 0.0;
    auto hist     = byte_histogram(data, size);
    double expected = static_cast<double>(size) / 256.0;
    double chi2   = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = static_cast<double>(hist[i]) - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}

// ─── Monte Carlo Pi estimation ────────────────────────────────────────────────
// Fixed: original code had shift-then-OR ordering wrong — each byte was being
// shifted left by 8 before the previous byte had been accumulated, effectively
// discarding high bytes. Use straightforward uint32_t accumulation.
double monte_carlo_pi(const uint8_t* data, size_t size) {
    if (size < 12) return 0.0;
    uint64_t in_circle = 0;
    uint64_t trials    = size / 12;  // 6 bytes per trial, split into two uint24s

    for (uint64_t i = 0; i < trials; i++) {
        const uint8_t* p = data + i * 12;
        // Build two 32-bit values from 6 bytes each (big-endian grouping)
        uint32_t xr = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
        uint32_t yr = ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 8) | p[5];
        double x = static_cast<double>(xr) / 0xFFFFFF;
        double y = static_cast<double>(yr) / 0xFFFFFF;
        if (x * x + y * y <= 1.0) in_circle++;
    }
    if (trials == 0) return 0.0;
    return 4.0 * static_cast<double>(in_circle) / static_cast<double>(trials);
}

// ─── Serial correlation coefficient ──────────────────────────────────────────
double serial_correlation(const uint8_t* data, size_t size) {
    if (size < 2) return 0.0;
    double scct1 = 0, scct2 = 0, scct3 = 0;
    for (size_t i = 0; i < size; i++) {
        double v = data[i];
        scct1 += v * v;
        scct2 += v;
        if (i > 0) scct3 += static_cast<double>(data[i - 1]) * v;
    }
    double scca = static_cast<double>(size) * scct3 - scct2 * (scct2 - data[0]);
    double sccb = static_cast<double>(size) * scct1 - scct2 * scct2;
    if (sccb == 0.0) return 0.0;
    return scca / sccb;
}

// ─── Block entropy for entropy map ───────────────────────────────────────────
// Downsample to max_blocks data points for large files.
nlohmann::json compute_block_entropy_json(
    const uint8_t* data, size_t size,
    uint32_t block_size,
    uint32_t max_blocks)
{
    nlohmann::json blocks = nlohmann::json::array();
    if (!data || size == 0) return blocks;

    uint64_t num_blocks = (size + block_size - 1) / block_size;
    uint64_t step       = std::max(uint64_t(1), num_blocks / max_blocks);

    blocks.get_ref<nlohmann::json::array_t&>().reserve(
        static_cast<size_t>((num_blocks + step - 1) / step));

    for (uint64_t i = 0; i < num_blocks; i += step) {
        uint64_t off = i * block_size;
        uint32_t bsz = static_cast<uint32_t>(
            std::min(static_cast<uint64_t>(block_size), size - off));
        double ent = compute_entropy_standalone(data + off, bsz);
        blocks.push_back({
            {"offset",  off},
            {"size",    bsz},
            {"entropy", ent}
        });
    }
    return blocks;
}

// ─── Printability analysis ────────────────────────────────────────────────────
struct PrintabilityStats {
    double printable_ratio;
    double null_ratio;
    double high_byte_ratio;
    bool   likely_text;
    bool   likely_binary;
    bool   likely_unicode;
};

PrintabilityStats analyze_printability(const uint8_t* data, size_t size) {
    PrintabilityStats s{};
    if (!data || !size) return s;

    uint64_t printable = 0, nulls = 0, high = 0, utf16_pattern = 0;
    for (size_t i = 0; i < size; i++) {
        uint8_t b = data[i];
        if      (b >= 0x20 && b < 0x7F) printable++;
        else if (b == 0)                 nulls++;
        else if (b >= 0x80)              high++;

        if (i > 0 && (i & 1) == 1 && b == 0 && data[i - 1] >= 0x20 && data[i - 1] < 0x7F)
            utf16_pattern++;
    }

    s.printable_ratio  = static_cast<double>(printable)    / size;
    s.null_ratio       = static_cast<double>(nulls)        / size;
    s.high_byte_ratio  = static_cast<double>(high)         / size;
    s.likely_text      = s.printable_ratio > 0.85 && s.null_ratio < 0.01;
    s.likely_unicode   = utf16_pattern > size / 8;
    s.likely_binary    = s.high_byte_ratio > 0.15 || s.null_ratio > 0.05;
    return s;
}

} // namespaceeeeeeeeeeeeeee
