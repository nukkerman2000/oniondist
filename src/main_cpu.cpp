// main_cpu.cpp -- portable CPU-only onion vanity client for oniondist.
//
// Two modes:
//   * local       : ./vanity_cpu [-t N] [-i] pattern [pattern...]
//   * distributed : ./vanity_cpu --server http://host:port --name NAME [-t N]
//                   (the target pattern is supplied by the coordinator)
//
// Builds without CUDA, so any machine can join the pool.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <csignal>
#include <unistd.h>

#include "keccak.h"
#include "search_common.h"
#include "hs_store.h"
#include "dist.h"

static std::atomic<bool> g_stop(false);
static std::mutex g_out;
static const char* g_keys_root = "keys";

static void on_sigint(int) { g_stop.store(true); }

// A worker pool that searches [start, start+count) cooperatively.
static void run_range(const uint8_t base[32], uint64_t start, uint64_t count,
                      const std::vector<std::string>& patterns, int threads,
                      std::atomic<uint64_t>* tested,
                      const std::function<void(const char*, const std::string&, uint64_t)>& on_found) {
  std::atomic<uint64_t> cursor(start);
  const uint64_t end = start + count;
  const uint64_t step = 4096;

  std::vector<std::thread> pool;
  for (int t = 0; t < threads; ++t) {
    pool.emplace_back([&]() {
      for (;;) {
        if (g_stop.load()) return;
        uint64_t s = cursor.fetch_add(step);
        if (s >= end) return;
        uint64_t c = end - s; if (c > step) c = step;
        cpu_search_counters(base, s, c, patterns, tested,
          [&](const char* hx, const std::string& pat) {
            std::lock_guard<std::mutex> lk(g_out);
            hs_save(g_keys_root, hx, pat, true);
            if (on_found) on_found(hx, pat, s);
          }, &g_stop);
      }
    });
  }
  for (auto& th : pool) th.join();
}

int main(int argc, char** argv) {
  std::signal(SIGINT, on_sigint);
  std::signal(SIGPIPE, SIG_IGN);

  int threads = (int)std::thread::hardware_concurrency();
  if (threads <= 0) threads = 1;
  bool rate = false;
  std::string server, name, kind = "cpu";
  std::vector<std::string> cli_patterns;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--server" && i + 1 < argc) { server = argv[++i]; continue; }
    if (a == "--name" && i + 1 < argc) { name = argv[++i]; continue; }
    if (a == "--keys" && i + 1 < argc) { g_keys_root = argv[++i]; continue; }
    if (a == "-t" && i + 1 < argc) { threads = atoi(argv[++i]); continue; }
    if (a == "-i") { rate = true; continue; }
    cli_patterns.push_back(a);
  }
  if (name.empty()) {
    char host[128] = "cpu";
    gethostname(host, sizeof(host) - 1);
    name = std::string(host) + "-" + std::to_string((long)getpid());
  }

  const bool distributed = !server.empty();

  // Normalise CLI patterns to 32-char uppercase with '?' padding.
  std::vector<std::string> patterns;
  for (auto& p : cli_patterns) {
    std::string s = p;
    if (s.size() > 32) s.resize(32);
    while (s.size() < 32) s += '?';
    for (auto& ch : s) if (ch >= 'a' && ch <= 'z') ch -= 32;
    patterns.push_back(s);
  }

  if (!distributed && patterns.empty()) {
    std::fprintf(stderr,
      "Usage:\n"
      "  local       : %s [-t N] [-i] pattern [pattern...]\n"
      "  distributed : %s --server http://host:port --name NAME [-t N]\n",
      argv[0], argv[0]);
    return 1;
  }

  uint8_t base[32];
  {
    std::random_device rd;
    uint32_t buf[256];
    for (auto& w : buf) w = rd();
    buf[0] ^= 0x5AU;
    keccak(buf, sizeof(buf), base, 32, 24);
  }

  std::printf("vanity_cpu: %d threads, mode=%s\n", threads,
              distributed ? "distributed" : "local");
  std::fflush(stdout);

  std::atomic<uint64_t> tested(0);

  if (!distributed) {
    // Local: cooperative search over an unbounded counter space, chunked by 1<<26.
    std::atomic<uint64_t> cursor(0);
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) {
      pool.emplace_back([&]() {
        for (;;) {
          if (g_stop.load()) return;
          uint64_t s = cursor.fetch_add((uint64_t)1 << 26);
          run_range(base, s, (uint64_t)1 << 26, patterns, 4, &tested,
                    nullptr);
          if (g_stop.load()) return;
        }
      });
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    uint64_t prev = 0;
    while (!g_stop.load()) {
      std::this_thread::sleep_for(std::chrono::seconds(20));
      auto t2 = std::chrono::high_resolution_clock::now();
      double dt = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() * 1e-9;
      uint64_t cur = tested.load();
      if (rate)
        std::printf("KEYRATE: %.4f million keys/second\n", (cur - prev) / dt * 1e-6);
      std::fflush(stdout);
      t1 = t2; prev = cur;
    }
    for (auto& th : pool) th.join();
    return 0;
  }

  // Distributed agent loop.
  dist::Coordinator coord;
  if (!dist::parse_url(server, coord.url)) {
    std::fprintf(stderr, "Bad --server URL: %s\n", server.c_str());
    return 1;
  }
  coord.name = name;
  coord.kind = kind;

  uint64_t chunks = 0;
  auto t1 = std::chrono::high_resolution_clock::now();
  uint64_t prev = 0;
  while (!g_stop.load()) {
    dist::Work w = coord.get_work((uint64_t)1 << 20);
    if (!w.valid) {
      std::fprintf(stderr, "No work from coordinator, retrying...\n");
      std::this_thread::sleep_for(std::chrono::seconds(3));
      continue;
    }
    std::vector<std::string> pats;
    { std::string p = w.pattern; if (p.size() > 32) p.resize(32); while (p.size() < 32) p += '?'; pats.push_back(p); }

    uint64_t tested_before = tested.load();
    run_range(base, w.start, w.count, pats, threads, &tested,
              [&](const char* hx, const std::string& pat, uint64_t counter) { coord.found(hx, pat, counter); });
    ++chunks;

    auto t2 = std::chrono::high_resolution_clock::now();
    double dt = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() * 1e-9;
    if (dt > 5.0) {
      uint64_t cur = tested.load();
      double r = (cur - prev) / dt;
      coord.report(cur, r, chunks);
      std::printf("chunk %llu [%llu..%llu)  rate %.4f M keys/s\n",
                  (unsigned long long)chunks,
                  (unsigned long long)w.start,
                  (unsigned long long)(w.start + w.count), r * 1e-6);
      std::fflush(stdout);
      t1 = t2; prev = cur;
    }
    (void)tested_before;
  }
  return 0;
}
