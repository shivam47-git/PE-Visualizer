#include "http_handler.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <iostream>
#include <thread>
#include <sstream>

namespace pe_server {

HttpServer::HttpServer(const std::string& host, uint16_t port, int threads)
    : m_host(host), m_port(port), m_threads(threads) {}

HttpServer::~HttpServer() { stop(); }

void HttpServer::route(const std::string& method, const std::string& path, Handler handler) {
    m_routes.push_back({method, path, std::move(handler)});
}

void HttpServer::start() {
    auto address = net::ip::make_address(m_host);
    tcp::acceptor acceptor{m_ioc, {address, m_port}};
    acceptor.set_option(tcp::acceptor::reuse_address(true));

    std::cout << "[PE-Server] Listening on " << m_host << ":" << m_port << std::endl;

    std::vector<std::thread> threads;
    for (int i = 0; i < m_threads - 1; i++)
        threads.emplace_back([this]{ m_ioc.run(); });

    do_accept(acceptor);
    m_ioc.run();

    for (auto& t : threads) t.join();
}

void HttpServer::stop() {
    m_ioc.stop();
}

void HttpServer::do_accept(tcp::acceptor& acceptor) {
    acceptor.async_accept(
        net::make_strand(m_ioc),
        [this, &acceptor](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                auto s = std::make_shared<tcp::socket>(std::move(socket));
                net::post(m_ioc, [this, s]() mutable {
                    handle_session(std::move(*s));
                });
            }
            do_accept(acceptor);
        });
}

void HttpServer::handle_session(tcp::socket socket) {
    try {
        // 6 GB flat buffer limit to handle large PE files
        beast::flat_buffer buffer;
        buffer.max_size(6ULL * 1024 * 1024 * 1024);

        for (;;) {
            http::request<http::string_body> req;
            // Per-message body limit: 6 GB
            http::request_parser<http::string_body> parser;
            parser.body_limit(6ULL * 1024 * 1024 * 1024);

            beast::error_code ec;
            http::read(socket, buffer, parser, ec);
            if (ec == http::error::end_of_stream) break;
            if (ec) {
                std::cerr << "[Session] read error: " << ec.message() << std::endl;
                break;
            }
            req = parser.release();

            Request our_req;
            our_req.method = req.method_string();
            std::string target = req.target();

            auto q_pos = target.find('?');
            if (q_pos != std::string::npos) {
                our_req.target = url_decode(target.substr(0, q_pos));
                our_req.query_params = parse_query(target.substr(q_pos + 1));
            } else {
                our_req.target = url_decode(target);
            }
            our_req.body = req.body();
            for (auto& f : req) {
                std::string key = f.name_string();
                std::string val = f.value();
                our_req.headers[key] = val;
            }

            Response our_res;
            if (our_req.method == "OPTIONS") {
                our_res = make_cors_preflight();
            } else {
                our_res = dispatch(our_req);
            }

            http::response<http::string_body> res{
                static_cast<http::status>(our_res.status_code),
                req.version()};
            res.set(http::field::server, "PE-Visualizer/2.0");
            res.set(http::field::content_type, our_res.content_type);
            res.set(http::field::access_control_allow_origin, "*");
            res.set(http::field::access_control_allow_methods,
                    "GET, POST, PUT, DELETE, OPTIONS");
            res.set(http::field::access_control_allow_headers,
                    "Content-Type, Authorization, X-Requested-With");
            res.set(http::field::access_control_max_age, "86400");
            for (auto& [k, v] : our_res.headers)
                res.set(k, v);
            res.keep_alive(req.keep_alive());
            res.body() = our_res.body;
            res.prepare_payload();

            http::write(socket, res, ec);
            if (ec || !req.keep_alive()) break;
        }
    } catch (const std::exception& e) {
        std::cerr << "[Session Error] " << e.what() << std::endl;
    }
}

Response HttpServer::dispatch(const Request& req) {
    for (auto& route : m_routes) {
        bool method_match = (route.method == "*" || route.method == req.method);
        bool path_match   = (route.path == req.target);
        if (method_match && path_match)
            return route.handler(req);
    }
    for (auto& route : m_routes) {
        bool method_match = (route.method == "*" || route.method == req.method);
        if (method_match && !route.path.empty() && route.path.back() == '*') {
            std::string prefix = route.path.substr(0, route.path.size() - 1);
            if (req.target.substr(0, prefix.size()) == prefix)
                return route.handler(req);
        }
    }
    return make_json_error(404, "Route not found: " + req.target);
}

std::string HttpServer::url_decode(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            unsigned int val = 0;
            std::istringstream iss(s.substr(i+1, 2));
            iss >> std::hex >> val;
            result += (char)val;
            i += 2;
        } else if (s[i] == '+') {
            result += ' ';
        } else {
            result += s[i];
        }
    }
    return result;
}

std::unordered_map<std::string, std::string>
HttpServer::parse_query(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    std::istringstream ss(query);
    std::string token;
    while (std::getline(ss, token, '&')) {
        auto eq = token.find('=');
        if (eq != std::string::npos)
            params[url_decode(token.substr(0, eq))] = url_decode(token.substr(eq + 1));
        else
            params[url_decode(token)] = "";
    }
    return params;
}

Response HttpServer::make_json_error(int code, const std::string& message) {
    nlohmann::json j = {{"error", message}, {"status", code}};
    return {(unsigned)code, j.dump(), "application/json"};
}

Response HttpServer::make_cors_preflight() {
    return {204, "", "text/plain"};
}

} // namespace pe_server
