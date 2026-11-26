#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>

namespace SchoolsOut
{
    namespace NetworkConfig
    {
        inline std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        inline std::string Trim(const std::string& value)
        {
            const std::size_t first = value.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) { return {}; }
            const std::size_t last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, last - first + 1);
        }

        inline bool ValidHost(const std::string& host)
        {
            if (host.empty() || host.size() > 253 || host.front() == '-' || host.back() == '-' ||
                host.back() == '.') {
                return false;
            }
            std::size_t start = 0;
            while (start < host.size()) {
                const std::size_t dot = host.find('.', start);
                const std::size_t end = dot == std::string::npos ? host.size() : dot;
                if (end == start || end - start > 63) { return false; }
                for (std::size_t i = start; i < end; ++i) {
                    const unsigned char c = static_cast<unsigned char>(host[i]);
                    if (!(std::isalnum(c) || c == '-')) { return false; }
                }
                if (dot == std::string::npos) { break; }
                start = dot + 1;
            }
            return true;
        }

        inline bool ValidPort(const std::string& port)
        {
            if (port.empty() || port.size() > 5) { return false; }
            unsigned long value = 0;
            for (const char c : port) {
                if (!std::isdigit(static_cast<unsigned char>(c))) { return false; }
                value = value * 10 + static_cast<unsigned long>(c - '0');
            }
            return value >= 1 && value <= 65535;
        }

        struct Endpoint
        {
            std::string scheme;
            std::string host;
            std::string port;

            bool FullOrigin() const { return !scheme.empty(); }
            std::string Authority() const { return port.empty() ? host : host + ":" + port; }
        };

        inline Endpoint ParseApiHost(std::string value)
        {
            value = Trim(value);
            if (value.empty()) { return {}; }
            Endpoint result;
            const std::size_t schemeEnd = value.find("://");
            if (schemeEnd != std::string::npos) {
                result.scheme = Lower(value.substr(0, schemeEnd));
                if (result.scheme != "http" && result.scheme != "https") {
                    throw std::runtime_error("ApiHost scheme must be http or https.");
                }
                value = value.substr(schemeEnd + 3);
            }
            if (value.empty() || value.find_first_of("/?#\\@") != std::string::npos) {
                throw std::runtime_error("ApiHost must be a bare host[:port] or a full origin with no path.");
            }
            const std::size_t colon = value.rfind(':');
            if (colon != std::string::npos) {
                result.port = value.substr(colon + 1);
                value = value.substr(0, colon);
                if (!ValidPort(result.port)) { throw std::runtime_error("ApiHost port is invalid."); }
            }
            result.host = Lower(value);
            if (!ValidHost(result.host)) { throw std::runtime_error("ApiHost host is invalid."); }
            return result;
        }

        inline std::string ParseDomain(std::string value)
        {
            value = Lower(Trim(value));
            if (value.empty()) { return {}; }
            if (!ValidHost(value)) { throw std::runtime_error("ServerDomain is invalid."); }
            return value;
        }

        inline bool InDomain(const std::string& host, const std::string& domain)
        {
            if (domain.empty() || host.empty()) { return false; }
            if (host == domain) { return true; }
            return host.size() > domain.size() && host.compare(host.size() - domain.size(), domain.size(), domain) == 0 &&
                   host[host.size() - domain.size() - 1] == '.';
        }

        inline bool ParseUrl(const std::string& url, std::string& scheme, std::string& authority,
                             std::string& suffix)
        {
            const std::size_t schemeEnd = url.find("://");
            if (schemeEnd == std::string::npos) { return false; }
            scheme = Lower(url.substr(0, schemeEnd));
            if (scheme != "http" && scheme != "https") { return false; }
            const std::size_t authorityStart = schemeEnd + 3;
            const std::size_t authorityEnd = url.find_first_of("/?#", authorityStart);
            authority = url.substr(authorityStart, authorityEnd - authorityStart);
            suffix = authorityEnd == std::string::npos ? std::string() : url.substr(authorityEnd);
            return !authority.empty();
        }

        inline std::string HostOf(const std::string& authority)
        {
            if (authority.empty()) { return {}; }
            if (authority.front() == '[') {
                const std::size_t end = authority.find(']');
                return end == std::string::npos ? std::string() : authority.substr(1, end - 1);
            }
            const std::size_t colon = authority.rfind(':');
            return colon == std::string::npos ? authority : authority.substr(0, colon);
        }

        // SignalR builds WebSocket URIs with ws:// or wss://. Those are not
        // accepted by ParseUrl above because REST rewriting must stay limited
        // to http(s), but the TLS bypass still has to recognize them.
        inline bool ParseUrlAny(const std::string& url, std::string& scheme,
                                std::string& authority, std::string& suffix)
        {
            const std::size_t schemeEnd = url.find("://");
            if (schemeEnd == std::string::npos) { return false; }
            scheme = Lower(url.substr(0, schemeEnd));
            if (scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss") {
                return false;
            }
            const std::size_t authorityStart = schemeEnd + 3;
            const std::size_t authorityEnd = url.find_first_of("/?#", authorityStart);
            authority = url.substr(authorityStart, authorityEnd - authorityStart);
            suffix = authorityEnd == std::string::npos ? std::string() : url.substr(authorityEnd);
            return !authority.empty();
        }

        inline std::string Rewrite(const std::string& url, const Endpoint& endpoint)
        {
            if (endpoint.host.empty()) { return url; }
            std::string scheme;
            std::string authority;
            std::string suffix;
            if (!ParseUrl(url, scheme, authority, suffix) || HostOf(authority) != "ns.rec.net") {
                return url;
            }
            const std::string newScheme = endpoint.FullOrigin() ? endpoint.scheme : scheme;
            return newScheme + "://" + endpoint.Authority() + suffix;
        }

        // BestHTTP's SendRequest hook only rewrites http(s) REST traffic. The
        // SignalR WebSocket URL is built separately as ws(s)://ns.rec.net and
        // bypasses that rewrite, so the WebSocket reaches TLS pinning with the
        // original host and fails with "Failed to connect". Rewrite the base
        // URI before WebSocketTransport.BuildUri derives the socket URL.
        inline std::string RewriteSignalR(const std::string& url, const Endpoint& endpoint)
        {
            if (endpoint.host.empty()) { return url; }
            std::string scheme;
            std::string authority;
            std::string suffix;
            if (!ParseUrlAny(url, scheme, authority, suffix) || HostOf(authority) != "ns.rec.net") {
                return url;
            }
            // An explicit ApiHost origin is authoritative about TLS. A bare
            // ApiHost leaves the original scheme in place, so https stays wss
            // and http stays ws after BuildUri converts it.
            const std::string newScheme = endpoint.FullOrigin()
                ? (endpoint.scheme == "https" ? "wss" : "ws")
                : scheme;
            return newScheme + "://" + endpoint.Authority() + suffix;
        }

        class Routing
        {
        public:
            Endpoint api;
            std::string serverDomain;

            std::string NameServerOrigin() const
            {
                if (api.host.empty()) { return {}; }
                const std::string scheme = api.FullOrigin() ? api.scheme : "https";
                return scheme + "://" + api.Authority();
            }

            std::string SslDomain() const
            {
                if (!serverDomain.empty()) { return serverDomain; }
                return api.host;
            }

            bool CertificateScope(const std::string& host) const
            {
                return InDomain(Lower(host), SslDomain());
            }
        };

        inline bool ValidPublicKey(const std::string& xml)
        {
            if (xml.empty()) { return true; }
            if (xml.size() > 4096) { return false; }
            const std::string text = Trim(xml);
            constexpr const char* openRoot = "<RSAKeyValue>";
            constexpr const char* closeRoot = "</RSAKeyValue>";
            const std::size_t openSize = std::string(openRoot).size();
            const std::size_t closeSize = std::string(closeRoot).size();
            if (text.compare(0, openSize, openRoot) != 0 || text.size() < openSize + closeSize ||
                text.compare(text.size() - closeSize, closeSize, closeRoot) != 0 ||
                text.find(openRoot, openSize) != std::string::npos) {
                return false;
            }
            const std::string body = text.substr(openSize, text.size() - openSize - closeSize);

            auto skipSpace = [&body](std::size_t& position) {
                while (position < body.size() && std::isspace(static_cast<unsigned char>(body[position]))) {
                    ++position;
                }
            };
            auto validBase64 = [](const std::string& value) {
                std::string compact;
                for (const char c : value) {
                    if (!std::isspace(static_cast<unsigned char>(c))) { compact.push_back(c); }
                }
                if (compact.empty() || compact.size() % 4 != 0) { return false; }
                const std::size_t padding = compact.find('=');
                if (padding != std::string::npos) {
                    if (compact.size() - padding > 2) { return false; }
                    for (std::size_t i = padding; i < compact.size(); ++i) {
                        if (compact[i] != '=') { return false; }
                    }
                }
                // npos means no padding; scanning up to npos would read past
                // the string and reject valid unpadded values like Exponent=AQAB.
                const std::size_t dataEnd = padding == std::string::npos ? compact.size() : padding;
                for (std::size_t i = 0; i < dataEnd; ++i) {
                    const unsigned char c = static_cast<unsigned char>(compact[i]);
                    if (!(std::isalnum(c) || c == '+' || c == '/')) { return false; }
                }
                return true;
            };

            const std::string fields[] = {"Modulus", "Exponent"};
            std::size_t position = 0;
            for (const std::string& field : fields) {
                skipSpace(position);
                const std::string open = "<" + field + ">";
                const std::string close = "</" + field + ">";
                if (body.compare(position, open.size(), open) != 0) { return false; }
                position += open.size();
                const std::size_t valueEnd = body.find(close, position);
                if (valueEnd == std::string::npos) { return false; }
                if (!validBase64(body.substr(position, valueEnd - position))) { return false; }
                position = valueEnd + close.size();
            }
            skipSpace(position);
            return position == body.size();
        }
    }
}
