#include "pe_parser.hpp"
#include "disassembler.hpp"
#include "yara_scanner.hpp"
#include "http_handler.hpp"
#include <iostream>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <shared_mutex>
#include <unordered_map>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>
#include <array>
#include <atomic>
#include <thread>

namespace fs = std::filesystem;

// ─── Session Cache ────────────────────────────────────────────────────────────
struct Session {
    std::string id;
    std::vector<uint8_t> data;
    std::string filename;
    pe::PEInfo  info;
    nlohmann::json info_json;
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point last_accessed;
};

static std::shared_mutex             g_sessions_mutex;
static std::unordered_map<std::string, Session> g_sessions;
static constexpr auto SESSION_TTL  = std::chrono::minutes(60);
static constexpr size_t MAX_SESSIONS = 64;

// Crypto-quality session ID: 128-bit via /dev/urandom or rd_rand fallback
static std::string generate_id() {
    static std::mt19937_64 rng([] {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd()};
        std::array<uint64_t,1> seeds;
        seq.generate(seeds.begin(), seeds.end());
        return seeds[0];
    }());
    static std::mutex rng_mutex;

    uint64_t a, b;
    {
        std::lock_guard<std::mutex> lk(rng_mutex);
        a = rng();
        b = rng();
    }
    char buf[33];
    snprintf(buf, sizeof(buf), "%016llx%016llx",
             (unsigned long long)a, (unsigned long long)b);
    return buf;
}

// Evict sessions older than TTL; also enforce max session cap (LRU).
// Must be called with g_sessions_mutex held for write.
static void evict_sessions_locked() {
    auto now = std::chrono::steady_clock::now();

    // TTL eviction
    for (auto it = g_sessions.begin(); it != g_sessions.end(); ) {
        if (now - it->second.created > SESSION_TTL)
            it = g_sessions.erase(it);
        else
            ++it;
    }

    // Hard cap: drop oldest-accessed sessions
    if (g_sessions.size() > MAX_SESSIONS) {
        std::vector<std::pair<std::chrono::steady_clock::time_point, std::string>> order;
        order.reserve(g_sessions.size());
        for (auto& [id, s] : g_sessions)
            order.emplace_back(s.last_accessed, id);
        std::sort(order.begin(), order.end());
        size_t to_drop = g_sessions.size() - MAX_SESSIONS;
        for (size_t i = 0; i < to_drop; i++)
            g_sessions.erase(order[i].second);
    }
}

static Session* get_session(const std::string& id) {
    // Shared lock for read
    std::shared_lock<std::shared_mutex> lk(g_sessions_mutex);
    auto it = g_sessions.find(id);
    if (it == g_sessions.end()) return nullptr;
    it->second.last_accessed = std::chrono::steady_clock::now();
    return &it->second;
}

// ─── Base64 decode ────────────────────────────────────────────────────────────
static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    std::vector<uint8_t> out;
    out.reserve(encoded.size() * 3 / 4);
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=') { valb -= 6; continue; }
        auto pos = B64_CHARS.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + (int)pos;
        valb += 6;
        if (valb >= 0) {
            out.push_back((uint8_t)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ─── Multipart parser ────────────────────────────────────────────────────────
// Parses multipart/form-data body to extract binary file data and filename.
static bool parse_multipart(
    const std::string& body,
    const std::string& content_type,
    std::vector<uint8_t>& out_data,
    std::string& out_filename)
{
    // Extract boundary from Content-Type header
    // e.g. "multipart/form-data; boundary=----WebKitFormBoundaryXXX"
    auto b_pos = content_type.find("boundary=");
    if (b_pos == std::string::npos) return false;
    std::string boundary = "--" + content_type.substr(b_pos + 9);
    // Strip quotes if present
    if (!boundary.empty() && boundary.front() == '"') boundary = boundary.substr(1);
    if (!boundary.empty() && boundary.back()  == '"') boundary.pop_back();

    // Find each part
    size_t pos = 0;
    while (pos < body.size()) {
        size_t part_start = body.find(boundary, pos);
        if (part_start == std::string::npos) break;
        part_start += boundary.size();
        if (part_start + 2 > body.size()) break;
        // Check for final boundary --
        if (body[part_start] == '-' && body[part_start+1] == '-') break;
        // Skip \r\n after boundary
        if (body[part_start] == '\r') part_start++;
        if (body[part_start] == '\n') part_start++;

        // Find end of headers (blank line)
        size_t hdr_end = body.find("\r\n\r\n", part_start);
        if (hdr_end == std::string::npos) break;
        std::string part_headers = body.substr(part_start, hdr_end - part_start);
        size_t data_start = hdr_end + 4;

        // Find next boundary
        size_t data_end = body.find("\r\n" + boundary, data_start);
        if (data_end == std::string::npos) data_end = body.size();

        // Extract filename from Content-Disposition
        auto cd_pos = part_headers.find("Content-Disposition:");
        if (cd_pos != std::string::npos) {
            auto fn_pos = part_headers.find("filename=\"", cd_pos);
            if (fn_pos != std::string::npos) {
                fn_pos += 10;
                auto fn_end = part_headers.find('"', fn_pos);
                if (fn_end != std::string::npos)
                    out_filename = part_headers.substr(fn_pos, fn_end - fn_pos);
            }
        }

        // This is the file part — copy binary data
        out_data.assign(
            reinterpret_cast<const uint8_t*>(body.data() + data_start),
            reinterpret_cast<const uint8_t*>(body.data() + data_end));
        return true;
    }
    return false;
}

// ─── Route Implementations ────────────────────────────────────────────────────

// POST /api/upload  multipart/form-data with file field
pe_server::Response handle_upload(const pe_server::Request& req) {
    try {
        std::vector<uint8_t> data;
        std::string filename = "unknown.exe";

        // Check content type — support both multipart and legacy base64 JSON
        auto ct_it = req.headers.find("Content-Type");
        if (ct_it == req.headers.end()) ct_it = req.headers.find("content-type");
        std::string ct = (ct_it != req.headers.end()) ? ct_it->second : "";

        if (ct.find("multipart/form-data") != std::string::npos) {
            // Multipart upload (new path)
            if (!parse_multipart(req.body, ct, data, filename)) {
                return {400, "{\"error\":\"Failed to parse multipart body\"}", "application/json"};
            }
        } else {
            // Legacy base64 JSON (fallback)
            auto j = nlohmann::json::parse(req.body);
            filename          = j.value("filename", "unknown.exe");
            std::string b64   = j.value("data", "");
            if (b64.empty())
                return {400, "{\"error\":\"No file data\"}", "application/json"};
            data = base64_decode(b64);
        }

        if (data.size() < 64)
            return {400, "{\"error\":\"File too small\"}", "application/json"};
        if (data.size() > 2ULL * 1024 * 1024 * 1024)
            return {413, "{\"error\":\"File too large (max 2 GB)\"}", "application/json"};

        // Sanitize filename (strip path components)
        filename = fs::path(filename).filename().string();
        if (filename.empty()) filename = "unknown.exe";

        pe::PEParser parser(data, filename);
        auto info = parser.parse();

        if (!info.valid)
            return {422, nlohmann::json({{"error", info.error}}).dump(), "application/json"};

        Session sess;
        sess.id           = generate_id();
        sess.data         = std::move(data);
        sess.filename     = filename;
        sess.info         = info;
        sess.info_json    = pe::pe_info_to_json(info);
        sess.created      = std::chrono::steady_clock::now();
        sess.last_accessed= sess.created;

        std::string sid = sess.id;

        {
            std::unique_lock<std::shared_mutex> lk(g_sessions_mutex);
            evict_sessions_locked();
            g_sessions[sid] = std::move(sess);
        }

        nlohmann::json resp;
        resp["session_id"] = sid;
        resp["filename"]   = filename;
        resp["file_size"]  = info.file_size;
        resp["pe_type"]    = info.pe_type;
        resp["valid"]      = info.valid;
        return {200, resp.dump(), "application/json"};

    } catch (const std::exception& e) {
        return {500, nlohmann::json({{"error", e.what()}}).dump(), "application/json"};
    }
}

// GET /api/analyze?session=ID
pe_server::Response handle_analyze(const pe_server::Request& req) {
    auto it = req.query_params.find("session");
    if (it == req.query_params.end())
        return {400, "{\"error\":\"Missing session param\"}", "application/json"};

    auto* sess = get_session(it->second);
    if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

    return {200, sess->info_json.dump(), "application/json"};
}

// GET /api/disasm?session=ID&rva=ADDR&size=N&mode=32|64&max=N
pe_server::Response handle_disasm(const pe_server::Request& req) {
    auto sess_it = req.query_params.find("session");
    if (sess_it == req.query_params.end())
        return {400, "{\"error\":\"Missing session\"}", "application/json"};
    auto* sess = get_session(sess_it->second);
    if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

    uint64_t rva       = 0;
    uint32_t size      = 512;
    uint32_t max_insns = 1000;
    bool force64       = sess->info.optional_header.is_64bit;

    try {
        if (auto i = req.query_params.find("rva");  i != req.query_params.end())
            rva = std::stoull(i->second, nullptr, 0);
        if (auto i = req.query_params.find("size"); i != req.query_params.end())
            size = (uint32_t)std::min((unsigned long)std::stoul(i->second), 65536ul);
        if (auto i = req.query_params.find("max");  i != req.query_params.end())
            max_insns = (uint32_t)std::min((unsigned long)std::stoul(i->second), 8000ul);
        if (auto i = req.query_params.find("mode"); i != req.query_params.end())
            force64 = (i->second == "64");
    } catch (...) {
        return {400, "{\"error\":\"Invalid numeric parameter\"}", "application/json"};
    }

    // RVA → file offset via section table
    uint64_t file_offset = UINT64_MAX;
    for (auto& s : sess->info.sections) {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
            file_offset = (uint64_t)s.raw_offset + (rva - s.virtual_address);
            break;
        }
    }
    if (file_offset == UINT64_MAX) {
        // Header region fallback
        uint32_t first_va = sess->info.sections.empty() ? 0x1000
                            : sess->info.sections.front().virtual_address;
        if (rva < first_va)
            file_offset = rva;
        else
            return {400, "{\"error\":\"RVA not in any section\"}", "application/json"};
    }
    if (file_offset >= sess->data.size())
        return {400, "{\"error\":\"Offset out of bounds\"}", "application/json"};

    uint32_t actual_size = (uint32_t)std::min(
        (uint64_t)size, sess->data.size() - file_offset);

    pe::Disassembler dis(force64 ? pe::Disassembler::Mode::X86_64
                                  : pe::Disassembler::Mode::X86_32);
    uint64_t va = sess->info.optional_header.image_base + rva;
    auto insns  = dis.disassemble_json(
        sess->data.data() + file_offset, actual_size, va, max_insns);

    // Hex dump
    pe::PEParser parser(sess->data, sess->filename);
    auto hex_j = parser.get_hex_dump(rva, actual_size);

    nlohmann::json resp;
    resp["rva"]          = rva;
    resp["va"]           = va;
    resp["file_offset"]  = file_offset;
    resp["size"]         = actual_size;
    resp["instructions"] = insns;
    resp["hex"]          = hex_j;
    return {200, resp.dump(), "application/json"};
}

// GET /api/hexdump?session=ID&rva=ADDR&size=N
pe_server::Response handle_hexdump(const pe_server::Request& req) {
    auto sess_it = req.query_params.find("session");
    if (sess_it == req.query_params.end())
        return {400, "{\"error\":\"Missing session\"}", "application/json"};
    auto* sess = get_session(sess_it->second);
    if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

    uint64_t rva  = 0;
    uint32_t size = 256;
    try {
        if (auto it = req.query_params.find("rva");  it != req.query_params.end())
            rva  = std::stoull(it->second, nullptr, 0);
        if (auto it = req.query_params.find("size"); it != req.query_params.end())
            size = (uint32_t)std::min((unsigned long)std::stoul(it->second), 65536ul);
    } catch (...) {
        return {400, "{\"error\":\"Invalid numeric parameter\"}", "application/json"};
    }

    pe::PEParser parser(sess->data, sess->filename);
    auto j = parser.get_hex_dump(rva, size);
    return {200, j.dump(), "application/json"};
}

// POST /api/yara { session: ID, rules: string }
pe_server::Response handle_yara(const pe_server::Request& req) {
    try {
        auto j = nlohmann::json::parse(req.body);
        std::string sid   = j.value("session", "");
        std::string rules = j.value("rules",   "");

        auto* sess = get_session(sid);
        if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

        if (rules.empty())
            rules = pe::YaraScanner::builtin_rules();

        // Size guard: prevent DoS via huge rule sets
        if (rules.size() > 4 * 1024 * 1024)
            return {413, "{\"error\":\"Rules too large (max 4 MB)\"}", "application/json"};

        pe::YaraScanner scanner;
        std::string err;
        if (!scanner.load_rules_string(rules, "user", err))
            return {422, nlohmann::json({{"error", err}}).dump(), "application/json"};

        auto matches = scanner.scan_json(sess->data.data(), sess->data.size());

        nlohmann::json resp;
        resp["rule_count"]  = scanner.rule_count();
        resp["match_count"] = matches.size();
        resp["matches"]     = matches;
        return {200, resp.dump(), "application/json"};

    } catch (const std::exception& e) {
        return {500, nlohmann::json({{"error", e.what()}}).dump(), "application/json"};
    }
}

// GET /api/strings?session=ID&filter=CATEGORY&encoding=ASCII|UTF-16LE&q=QUERY&limit=N&offset=N
pe_server::Response handle_strings(const pe_server::Request& req) {
    auto sess_it = req.query_params.find("session");
    if (sess_it == req.query_params.end())
        return {400, "{\"error\":\"Missing session\"}", "application/json"};
    auto* sess = get_session(sess_it->second);
    if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

    std::string filter_cat, filter_enc, query;
    uint32_t limit = 500, offset = 0;

    if (auto it = req.query_params.find("filter");   it != req.query_params.end()) filter_cat = it->second;
    if (auto it = req.query_params.find("encoding"); it != req.query_params.end()) filter_enc = it->second;
    if (auto it = req.query_params.find("q");        it != req.query_params.end()) query      = it->second;
    try {
        if (auto it = req.query_params.find("limit");  it != req.query_params.end())
            limit  = (uint32_t)std::min((unsigned long)std::stoul(it->second), 5000ul);
        if (auto it = req.query_params.find("offset"); it != req.query_params.end())
            offset = (uint32_t)std::stoul(it->second);
    } catch (...) {
        return {400, "{\"error\":\"Invalid numeric parameter\"}", "application/json"};
    }

    nlohmann::json arr = nlohmann::json::array();
    uint32_t total = 0, returned = 0;

    for (auto& s : sess->info.strings) {
        bool cat_ok = filter_cat.empty() || s.category == filter_cat;
        bool enc_ok = filter_enc.empty() || s.encoding == filter_enc;
        bool q_ok   = query.empty()      || s.value.find(query) != std::string::npos;
        if (cat_ok && enc_ok && q_ok) {
            if (total >= offset && returned < limit) {
                arr.push_back({
                    {"value",    s.value},
                    {"offset",   s.offset},
                    {"encoding", s.encoding},
                    {"section",  s.section},
                    {"category", s.category},
                });
                returned++;
            }
            total++;
        }
    }

    return {200, nlohmann::json({
        {"total", total}, {"returned", returned},
        {"offset", offset}, {"limit", limit},
        {"strings", arr}
    }).dump(), "application/json"};
}

// GET /api/section_data?session=ID&name=.text
pe_server::Response handle_section_data(const pe_server::Request& req) {
    auto sess_it = req.query_params.find("session");
    if (sess_it == req.query_params.end())
        return {400, "{\"error\":\"Missing session\"}", "application/json"};
    auto* sess = get_session(sess_it->second);
    if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

    std::string name;
    if (auto it = req.query_params.find("name"); it != req.query_params.end())
        name = it->second;

    for (auto& s : sess->info.sections) {
        if (s.name != name) continue;

        uint64_t raw_end = std::min(
            (uint64_t)s.raw_offset + s.raw_size,
            (uint64_t)sess->data.size());

        // Build hex string with pre-allocated buffer
        size_t raw_len = raw_end - s.raw_offset;
        std::string hex_str;
        hex_str.reserve(raw_len * 2);
        static const char HEX[] = "0123456789abcdef";
        for (uint64_t i = s.raw_offset; i < raw_end; i++) {
            uint8_t b = sess->data[i];
            hex_str += HEX[b >> 4];
            hex_str += HEX[b & 0xF];
        }

        return {200, nlohmann::json({
            {"name",    s.name},
            {"rva",     s.virtual_address},
            {"size",    s.raw_size},
            {"entropy", s.entropy},
            {"hex",     hex_str}
        }).dump(), "application/json"};
    }
    return {404, "{\"error\":\"Section not found\"}", "application/json"};
}

// GET /api/sessions
pe_server::Response handle_sessions(const pe_server::Request&) {
    std::shared_lock<std::shared_mutex> lk(g_sessions_mutex);
    nlohmann::json arr = nlohmann::json::array();
    for (auto& [id, sess] : g_sessions) {
        auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - sess.created).count();
        arr.push_back({
            {"id",       id},
            {"filename", sess.filename},
            {"size",     sess.data.size()},
            {"pe_type",  sess.info.pe_type},
            {"age_s",    age_s},
        });
    }
    return {200, arr.dump(), "application/json"};
}

// DELETE /api/session?id=ID
pe_server::Response handle_delete_session(const pe_server::Request& req) {
    auto it = req.query_params.find("id");
    if (it == req.query_params.end())
        return {400, "{\"error\":\"Missing id\"}", "application/json"};
    std::unique_lock<std::shared_mutex> lk(g_sessions_mutex);
    size_t erased = g_sessions.erase(it->second);
    return {200, nlohmann::json({{"ok", erased > 0}}).dump(), "application/json"};
}

// GET /api/entropy_map?session=ID&block_size=N
pe_server::Response handle_entropy_map(const pe_server::Request& req) {
    auto sess_it = req.query_params.find("session");
    if (sess_it == req.query_params.end())
        return {400, "{\"error\":\"Missing session\"}", "application/json"};
    auto* sess = get_session(sess_it->second);
    if (!sess) return {404, "{\"error\":\"Session not found\"}", "application/json"};

    uint32_t block_size = 256;
    try {
        if (auto it = req.query_params.find("block_size"); it != req.query_params.end())
            block_size = (uint32_t)std::clamp((unsigned long)std::stoul(it->second), 64ul, 4096ul);
    } catch (...) {}

    auto& data  = sess->data;
    const size_t total_blocks = (data.size() + block_size - 1) / block_size;
    // Downsample to at most 32k data points for large files
    const size_t step = std::max(size_t(1), total_blocks / 32768);

    nlohmann::json blocks = nlohmann::json::array();
    for (size_t i = 0; i < total_blocks; i += step) {
        uint64_t off = (uint64_t)i * block_size;
        uint32_t bsz = (uint32_t)std::min((uint64_t)block_size, (uint64_t)data.size() - off);

        uint64_t freq[256] = {};
        for (uint32_t k = 0; k < bsz; k++) freq[data[off + k]]++;
        double ent = 0.0;
        for (int k = 0; k < 256; k++) {
            if (!freq[k]) continue;
            double p = (double)freq[k] / bsz;
            ent -= p * std::log2(p);
        }
        blocks.push_back({{"offset", off}, {"size", bsz}, {"entropy", ent}});
    }

    nlohmann::json resp;
    resp["file_entropy"] = sess->info.file_entropy;
    resp["block_size"]   = block_size;
    resp["blocks"]       = std::move(blocks);
    resp["sections"]     = nlohmann::json::array();
    for (auto& s : sess->info.sections)
        resp["sections"].push_back({
            {"name",    s.name},
            {"rva",     s.virtual_address},
            {"size",    s.raw_size},
            {"entropy", s.entropy}
        });
    return {200, resp.dump(), "application/json"};
}

// GET /health
pe_server::Response handle_health(const pe_server::Request&) {
    std::shared_lock<std::shared_mutex> lk(g_sessions_mutex);
    return {200, nlohmann::json({
        {"status",   "ok"},
        {"version",  "2.0"},
        {"sessions", g_sessions.size()},
    }).dump(), "application/json"};
}

// ─── Background TTL reaper ────────────────────────────────────────────────────
static std::atomic<bool> g_running{true};
static std::mutex g_reaper_mutex;
static std::condition_variable g_reaper_cv;

static void session_reaper() {
    std::unique_lock<std::mutex> lk(g_reaper_mutex);
    while (g_running.load(std::memory_order_relaxed)) {
        if (g_reaper_cv.wait_for(lk, std::chrono::minutes(5), [] {
                return !g_running.load(std::memory_order_relaxed);
            }))
            break;
        lk.unlock();
        {
            std::unique_lock<std::shared_mutex> sessions_lock(g_sessions_mutex);
            evict_sessions_locked();
        }
        lk = std::unique_lock<std::mutex>(g_reaper_mutex);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    uint16_t port    = 9000;
    int threads      = std::max(4, (int)std::thread::hardware_concurrency());

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if      (arg == "--host"    && i + 1 < argc) host    = argv[++i];
        else if (arg == "--port"    && i + 1 < argc) port    = (uint16_t)std::stoi(argv[++i]);
        else if (arg == "--threads" && i + 1 < argc) threads = std::stoi(argv[++i]);
    }

    std::thread reaper(session_reaper);

    pe_server::HttpServer server(host, port, threads);

    server.route("GET",    "/health",           handle_health);
    server.route("GET",    "/api/sessions",     handle_sessions);
    server.route("POST",   "/api/upload",       handle_upload);
    server.route("GET",    "/api/analyze",      handle_analyze);
    server.route("GET",    "/api/disasm",       handle_disasm);
    server.route("GET",    "/api/hexdump",      handle_hexdump);
    server.route("POST",   "/api/yara",         handle_yara);
    server.route("GET",    "/api/strings",      handle_strings);
    server.route("GET",    "/api/section_data", handle_section_data);
    server.route("DELETE", "/api/session",      handle_delete_session);
    server.route("GET",    "/api/entropy_map",  handle_entropy_map);

    std::cout << "[PE-Visualizer Server v2.0]\n"
              << "  Host    : " << host    << "\n"
              << "  Port    : " << port    << "\n"
              << "  Threads : " << threads << "\n"
              << "  Sessions: max=" << MAX_SESSIONS
              << " TTL=" << SESSION_TTL.count() << "m\n"
              << "  Press Ctrl+C to stop\n";

    try {
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "[Fatal] " << e.what() << std::endl;
        g_running.store(false);
        g_reaper_cv.notify_one();
        reaper.join();
        return 1;
    }

    g_running.store(false);
    g_reaper_cv.notify_one();
    reaper.join();
    return 0;
}
