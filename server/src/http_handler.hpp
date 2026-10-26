#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <vector>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
using tcp = net::ip::tcp;

namespace pe_server {

// ─── Route Handler ─────────────────────────────────────────────────────────
struct Request {
    std::string method;
    std::string target;
    std::string body;
    std::unordered_map<std::string, std::string> query_params;
    std::unordered_map<std::string, std::string> headers;
};

struct Response {
    unsigned status_code = 200;
    std::string body;
    std::string content_type = "application/json";
    std::unordered_map<std::string, std::string> headers;
};

using Handler = std::function<Response(const Request&)>;

// ─── Server ────────────────────────────────────────────────────────────────
class HttpServer {
public:
    HttpServer(const std::string& host, uint16_t port,
               int threads = 4);
    ~HttpServer();

    // Register route: method = "GET" | "POST" | "PUT" | "DELETE" | "*"
    void route(const std::string& method, const std::string& path, Handler handler);

    void start();  // Blocking
    void stop();

private:
    std::string        m_host;
    uint16_t           m_port;
    int                m_threads;
    net::io_context    m_ioc;
    
    struct Route {
        std::string method;
        std::string path;
        Handler     handler;
    };
    std::vector<Route> m_routes;

    void do_accept(tcp::acceptor& acceptor);
    void handle_session(tcp::socket socket);
    Response dispatch(const Request& req);
    
    static std::string url_decode(const std::string& s);
    static std::unordered_map<std::string, std::string> parse_query(const std::string& query);
    static Response make_json_error(int code, const std::string& message);
    static Response make_cors_preflight();
};

} // namespace pe_server
