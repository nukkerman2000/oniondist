// dist.h -- tiny dependency-free HTTP/JSON client for the oniondist coordinator.
//
// Uses POSIX sockets (Linux). HTTP/1.1 with "Connection: close": the server
// closes the socket after the response, so the body is read until EOF and the
// client never has to handle chunked transfer-encoding.
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <cstdio>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace dist {

struct Url {
  std::string host;
  int port = 80;
  std::string base;   // e.g. "" or "/oniondist"
  std::string token;  // optional Bearer token for the coordinator
};

inline bool parse_url(const std::string& url, Url& out) {
  std::string s = url;
  if (s.rfind("http://", 0) == 0) s = s.substr(7);
  size_t slash = s.find('/');
  std::string hostport = (slash == std::string::npos) ? s : s.substr(0, slash);
  out.base = (slash == std::string::npos) ? "" : s.substr(slash);
  while (!out.base.empty() && out.base.back() == '/') out.base.pop_back();
  size_t colon = hostport.find(':');
  if (colon == std::string::npos) {
    out.host = hostport;
    out.port = 80;
  } else {
    out.host = hostport.substr(0, colon);
    out.port = atoi(hostport.substr(colon + 1).c_str());
  }
  return !out.host.empty();
}

inline std::string http_request(const Url& u, const std::string& method,
                                const std::string& path,
                                const std::string& body, int timeout_sec) {
  struct addrinfo hints, *res = nullptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%d", u.port);

  if (getaddrinfo(u.host.c_str(), portstr, &hints, &res) != 0 || !res) return "";

  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) { freeaddrinfo(res); return ""; }

  struct timeval tv;
  tv.tv_sec = timeout_sec; tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
    close(fd); freeaddrinfo(res); return "";
  }
  freeaddrinfo(res);

  std::string req = method + " " + u.base + path + " HTTP/1.1\r\n";
  req += "Host: " + u.host + "\r\n";
  req += "User-Agent: oniondist-client\r\n";
  req += "Connection: close\r\n";
  if (!u.token.empty()) req += "Authorization: Bearer " + u.token + "\r\n";
  if (method == "POST") {
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  }
  req += "\r\n";
  if (method == "POST") req += body;

  size_t sent = 0;
  while (sent < req.size()) {
    ssize_t n = send(fd, req.data() + sent, req.size() - sent, 0);
    if (n <= 0) { close(fd); return ""; }
    sent += (size_t)n;
  }

  std::string raw;
  char buf[8192];
  for (;;) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    raw.append(buf, (size_t)n);
  }
  close(fd);

  size_t hdr = raw.find("\r\n\r\n");
  if (hdr == std::string::npos) return "";
  return raw.substr(hdr + 4);
}

// ---- minimal flat-JSON readers (enough for our fixed server responses) ----

inline bool json_find(const std::string& body, const std::string& key, size_t& pos) {
  std::string pat = "\"" + key + "\"";
  size_t k = body.find(pat);
  if (k == std::string::npos) return false;
  size_t c = body.find(':', k + pat.size());
  if (c == std::string::npos) return false;
  pos = c + 1;
  while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' ||
                               body[pos] == '\n' || body[pos] == '\r')) ++pos;
  return true;
}

inline std::string json_str(const std::string& body, const std::string& key,
                            const std::string& def = "") {
  size_t p;
  if (!json_find(body, key, p)) return def;
  if (p >= body.size() || body[p] != '"') return def;
  ++p;
  std::string out;
  while (p < body.size() && body[p] != '"') {
    if (body[p] == '\\' && p + 1 < body.size()) { ++p; }
    out.push_back(body[p++]);
  }
  return out;
}

inline uint64_t json_u64(const std::string& body, const std::string& key, uint64_t def = 0) {
  size_t p;
  if (!json_find(body, key, p)) return def;
  return strtoull(body.c_str() + p, nullptr, 10);
}

// ---- coordinator client ----

struct Work {
  std::string pattern;
  uint64_t start = 0;
  uint64_t count = 0;
  bool valid = false;
};

struct Coordinator {
  Url url;
  std::string name;
  std::string kind;   // "gpu" or "cpu"

  // Ask the server for the next counter range. `batch` is the caller's natural
  // work size, used only so the server can size the chunk sensibly.
  Work get_work(uint64_t batch) {
    std::string path = "/api/work?client=" + name + "&kind=" + kind +
                       "&batch=" + std::to_string(batch);
    std::string body = http_request(url, "GET", path, "", 30);
    Work w;
    w.pattern = json_str(body, "pattern");
    w.start = json_u64(body, "start", 0);
    w.count = json_u64(body, "count", 0);
    w.valid = !w.pattern.empty() && w.count > 0;
    return w;
  }

  void report(uint64_t tested, double rate, uint64_t chunks) {
    std::string body = "{\"client\":\"" + name + "\",\"kind\":\"" + kind +
                       "\",\"tested\":" + std::to_string(tested) +
                       ",\"rate\":" + std::to_string(rate) +
                       ",\"chunks\":" + std::to_string(chunks) + "}";
    http_request(url, "POST", "/api/report", body, 10);
  }

  void found(const std::string& hex_key, const std::string& pattern, uint64_t counter) {
    std::string body = "{\"client\":\"" + name + "\",\"key\":\"" + hex_key +
                       "\",\"pattern\":\"" + pattern +
                       "\",\"counter\":" + std::to_string(counter) + "}";
    http_request(url, "POST", "/api/found", body, 10);
  }
};

} // namespace dist
