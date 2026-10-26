#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#if __has_include(<yara/yara.h>)
#include <yara/yara.h>
#else
#include <yara.h>
#endif

namespace pe {

struct YaraMatch {
    std::string rule_name;
    std::string namespace_str;
    std::string tags;
    std::vector<std::string> meta_pairs; // "key = value"
    struct StringMatch {
        std::string identifier;
        uint64_t    offset;
        std::string data_hex;
        std::string data_ascii;
    };
    std::vector<StringMatch> string_matches;
};

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    // Load rules from file or string
    bool load_rules_file(const std::string& path, std::string& error);
    bool load_rules_string(const std::string& source, const std::string& ns,
                           std::string& error);
    // Clear and reload
    void clear_rules();

    // Scan a buffer
    std::vector<YaraMatch> scan(const uint8_t* data, size_t size,
                                 int timeout_secs = 30);

    nlohmann::json scan_json(const uint8_t* data, size_t size,
                              int timeout_secs = 30);

    // Get loaded rule count
    size_t rule_count() const { return m_rule_count; }

    // Get built-in default rules (common malware detections)
    static std::string builtin_rules();

private:
    YR_COMPILER* m_compiler = nullptr;
    YR_RULES*    m_rules    = nullptr;
    size_t       m_rule_count = 0;

    static int scan_callback(YR_SCAN_CONTEXT* ctx, int message,
                              void* message_data, void* user_data);

    struct ScanContext {
        std::vector<YaraMatch>* matches;
    };
};

} // namespace pe
