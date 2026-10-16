#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <set>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>
#ifdef _WIN32
#else
#include <unistd.h>
#endif
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "keccak.h"
#define EXPAND 10
#define EXPANDBUF 4096
#include "gpu_keccak.h"
#include "gpu_crypto.h"

constexpr size_t PATTERN_SIZE = 32;
#include "gpu_scan.h"

extern "C" {
#include "crypto-ops.h"
}

#include "hs_store.h"

using namespace std::chrono;

constexpr char alphabet32[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char alphabetB32CPU[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char* g_keys_root = "keys";

// Host copy of the base point multiplied by 8 (same constant as ge_eightpoint in gpu_crypto.h),
// used by the CPU expansion loop.
static const ge_cached ge_eightpoint_host = {
  {48496028, -16430416, 15164263, 11885335, 60784617, -4866353, 46481863, -2771805, 9708580, 2387263},
  {-10173472, -5540046, 21277639, 4080693, 1932823, -14916249, -9515873, -21787995, -36575460, 29827857},
  {25143927, -10256223, -3515585, 5715072, 19432778, -14905909, 22462083, -8862871, 13226552, 743677},
  {-784818, -8208065, -28479270, 5551579, 15746872, 4911053, 19117091, 11267669, -24569594, 14624995}
};

static std::mutex g_out;

static void b32_encode(const uint8_t* pub, char* out) {
  for (int j = 0; j < 4; ++j) {
    uint64_t t = 0;
    for (int x = 0, y = 4; x < 5; ++x, --y) t += (uint64_t)pub[x + j * 5] << (y * 8);
    for (int x = 0, y = 7; x < 8; ++x, --y) out[x + j * 8] = alphabetB32CPU[(t >> (y * 5)) & 0x1F];
  }
}

static inline int pattern_match(const char* enc, const std::vector<std::string>& pats) {
  for (size_t p = 0; p < pats.size(); ++p) {
    const std::string& s = pats[p];
    bool ok = true;
    for (int i = 0; i < 32; ++i) {
      char c = s[i];
      if (c != '?' && c != enc[i]) { ok = false; break; }
    }
    if (ok) return (int)p;
  }
  return -1;
}

static void hex32(const uint8_t* d, char* out) {
  for (int i = 0; i < 32; ++i) {
    out[i * 2]     = "0123456789abcdef"[d[i] >> 4];
    out[i * 2 + 1] = "0123456789abcdef"[d[i] & 15];
  }
  out[64] = '\0';
}

static uint64_t free_ram_bytes() {
#if defined(__linux__)
  // MemAvailable accounts for reclaimable page cache, so the CPU budget can use
  // nearly the whole machine instead of only the currently-idle pages.
  FILE* f = fopen("/proc/meminfo", "r");
  if (f) {
    char key[64], unit[16];
    unsigned long kb;
    while (fscanf(f, "%63s %lu %15s", key, &kb, unit) == 3) {
      if (strcmp(key, "MemAvailable:") == 0) {
        fclose(f);
        return (uint64_t)kb * 1024ull;
      }
    }
    fclose(f);
  }
#endif
#ifdef _SC_AVPHYS_PAGES
  long pages = sysconf(_SC_AVPHYS_PAGES);
  long psz = sysconf(_SC_PAGESIZE);
  if (pages > 0 && psz > 0) return (uint64_t)pages * (uint64_t)psz;
#endif
  return 0;
}

// One CPU worker: computes keys into a large RAM buffer, then scans the buffer for matches.
// The buffer size (cap_keys) is derived from the CPU memory budget, so RAM is actively used.
static void cpu_worker(int tid,
                       std::vector<std::string> patterns,
                       const void* rnd, size_t rndlen,
                       std::atomic<uint64_t>* keys_checked,
                       size_t cap_keys)
{
    const size_t EXP = EXPAND;

    // Raw (uninitialised) allocations: the whole budget is reserved up front so the
    // CPU has maximum RAM available, but pages commit lazily as the cycling windows
    // touch them -- no giant zero-fill stall at startup, and overcommit keeps the
    // reservation from failing on huge budgets.
    uint8_t* cands = nullptr;
    uint8_t* scal = nullptr;
    while (cap_keys >= 4096) {
      cands = (uint8_t*)malloc(cap_keys * EXP * 32);
      scal  = (uint8_t*)malloc(cap_keys * 32);
      if (cands && scal) break;
      if (cands) { free(cands); cands = nullptr; }
      if (scal)  { free(scal);  scal  = nullptr; }
      cap_keys /= 2;
    }
    if (!cands || !scal) {
      cap_keys = 4096;
      cands = (uint8_t*)malloc(cap_keys * EXP * 32);
      scal  = (uint8_t*)malloc(cap_keys * 32);
    }

  // Distinct key template per thread, mixed the same way the GPU does it.
  std::vector<uint8_t> tmp(rndlen);
  memcpy(tmp.data(), rnd, rndlen);
  tmp[0] ^= (uint8_t)tid;
  uint8_t base[32];
  keccak(tmp.data(), (int)rndlen, base, 32, 24);

  uint64_t n = 0;
  uint64_t pending = 0;
  // Process the big buffer in responsive windows so matches appear promptly
  // while the whole allocation still gets actively used as a rotating working set.
  const size_t SUB = (cap_keys < 16384) ? cap_keys : 16384;
  size_t pos = 0;

  for (;;) {
    if (pos + SUB > cap_keys) pos = 0;

    // fill window [pos, pos+SUB)
    for (size_t k = 0; k < SUB; ++k) {
      const size_t i = pos + k;
      uint8_t in[32];
      memcpy(in, base, 32);
      // High bits carry the thread id so CPU threads never collide with each other
      // nor with the low-counter GPU range.
      uint64_t idx = ((uint64_t)(uint32_t)tid << 48) | (n & 0xFFFFFFFFFFFFULL);
      *(uint64_t*)in ^= idx;

      uint8_t md[32];
      keccak(in, 32, md, 32, 12);
      sc_reduce32(md);
      memcpy(&scal[i * 32], md, 32);

      ge_p3 point;
      ge_scalarmult_base(&point, md);
      for (size_t s = 0; s < EXP; ++s) {
        ge_p1p1 sum;
        ge_add(&sum, &point, &ge_eightpoint_host);
        ge_p1p1_to_p3(&point, &sum);
        ge_p3_tobytes(&cands[(i * EXP + s) * 32], &point);
      }

      ++n; ++pending;
      if (pending >= 4096) {
        keys_checked->fetch_add(pending, std::memory_order_relaxed);
        pending = 0;
      }
    }
    if (pending) {
      keys_checked->fetch_add(pending, std::memory_order_relaxed);
      pending = 0;
    }

    // scan window [pos, pos+SUB)
    for (size_t k = 0; k < SUB; ++k) {
      const size_t i = pos + k;
      for (size_t s = 0; s < EXP; ++s) {
        char enc[33];
        b32_encode(&cands[(i * EXP + s) * 32], enc);
        enc[32] = '\0';
        int pi = pattern_match(enc, patterns);
        if (pi >= 0) {
          // slot s holds scalar + 8*(s+1)
          uint8_t fixup[32];
          memset(fixup, 0, 32);
          uint32_t incr = (uint32_t)((s + 1) * 8);
          memcpy(fixup, &incr, sizeof(incr));
          uint8_t out[32];
          scalar_add(out, &scal[i * 32], fixup);
          char hx[65];
          hex32(out, hx);
          std::lock_guard<std::mutex> lk(g_out);
          hs_save(g_keys_root, hx, patterns[pi], true);
        }
      }
    }

    pos += SUB;
  }
}

int main(int argc, char** argv)
{
#define CHECKED_CALL(X) do { \
        const cudaError_t err = X; \
        if (err != cudaSuccess) { \
            std::cerr << #X " (line " << __LINE__ << ") failed, error " << err; \
            return __LINE__; \
        } \
    } while(0)

    int device_count = 0;
    const cudaError_t init_err = cudaGetDeviceCount(&device_count);
    if (init_err != cudaSuccess) {
        std::cerr << "CUDA init failed: " << cudaGetErrorString(init_err) << " (continuing CPU-only)" << std::endl;
        device_count = 0;
    }

    bool rate_info = false;
    bool no_cpu = false;
    bool no_gpu = false;
    int cpu_threads_req = 0;   // 0 = hardware_concurrency
    double cpu_mem_gb = 0.0;   // 0 = auto (most of free RAM)

    std::string patterns_str;
    std::vector<std::string> pattern_vec;

    std::set<int> devices_to_use;

    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];

        // enable hashrate reporting
        if (s == "-i") {
          rate_info = true;
          continue;
        }

        // disable CPU workers (GPU only)
        if (s == "-C") {
          no_cpu = true;
          continue;
        }

        // disable GPU workers (CPU only)
        if (s == "-G") {
          no_gpu = true;
          continue;
        }

        // device selection
        if ((s == "-d") && (i + 1 < argc)) {
            ++i;
            const int id = strtol(argv[i], nullptr, 10);
            if (0 <= id && id < device_count) {
                devices_to_use.insert(id);
            }
            else {
                printf("Invalid device id %s\n", argv[i]);
            }
            continue;
        }

        // CPU worker thread count
        if ((s == "-t") && (i + 1 < argc)) {
            ++i;
            cpu_threads_req = atoi(argv[i]);
            continue;
        }

        // CPU memory budget in GiB
        if ((s == "-m") && (i + 1 < argc)) {
            ++i;
            cpu_mem_gb = atof(argv[i]);
            continue;
        }

        // output directory for generated hidden service folders
        if ((s == "--keys") && (i + 1 < argc)) {
            ++i;
            g_keys_root = argv[i];
            continue;
        }

        if (s.length() > PATTERN_SIZE) {
            s.resize(PATTERN_SIZE);
        }
        else {
            while (s.length() < PATTERN_SIZE) {
                s += '?';
            }
        }

        const char* abc = alphabet32;

        bool good = true;
        for (int j = 0; j < PATTERN_SIZE; ++j) {
            if (s[j] == '?') {
                continue;
            }
            bool found = false;
            for (int k = 0; k < 58; ++k) {
                if (s[j] == abc[k]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                good = false;
                break;
            }
        }
        if (good) {
            patterns_str += s;
            pattern_vec.push_back(s);
        }
        else {
            std::cout << "Invalid pattern \"" << argv[i] << "\"" << std::endl;
        }
    }

    if (patterns_str.empty()) {
        printf(
            "Usage:\n\n"
            "./vanity_torv3_cuda [-i] [-C] [-G] [-d N] [-t N] [-m GB] pattern1 [pattern_2] ... [pattern_n]\n\n"
            "-i         print the keygen rate every 20 seconds (million keys/second)\n\n"
            "-C         disable CPU workers (GPU only)\n\n"
            "-G         disable GPU workers (CPU only)\n\n"
            "-d N       use CUDA device with index N (repeatable, counting from 0)\n\n"
            "-t N       number of CPU worker threads (default: all cores)\n\n"
            "-m GB      CPU memory budget in GiB for candidate buffers (default: most of free RAM)\n\n"
            "GPU batch size is sized automatically to fill the free VRAM of any card.\n"
            "CPU workers run in parallel with the GPU by default.\n\n"
            "Each pattern can have \"?\" symbols which match any character.\nOnly these characters are allowed:\n\n"
            " abcdefghijklmnopqrstuvwxyz234567\n\n"
            "Example:\n\t./vanity_torv3_cuda -i P?XXXXX L23456 b55555\n\n"
            "Matches print the tor secret key (hex) as they are found.\n"
        );
        return 0;
    }

    // Make all uppercase
    for (int i = 0; patterns_str[i]!='\0'; i++) {
      if(patterns_str[i] >= 'a' && patterns_str[i] <= 'z') {
        patterns_str[i] = patterns_str[i] -32;
      }
    }
    for (auto& p : pattern_vec) {
      for (auto& c : p) if (c >= 'a' && c <= 'z') c = c - 32;
    }

    // Get some entropy from the random device
    std::random_device::result_type rnd_buf[256];
    std::random_device rd;
    for (int i = 0; i < 256; ++i) {
        rnd_buf[i] = rd();
    }

    std::atomic<uint64_t> keys_checked;
    std::vector<std::thread> threads;

    size_t total_gpu_batch = 0;

    const std::string pat0 = pattern_vec.empty() ? std::string() : pattern_vec[0];

    for (int i = 0; !no_gpu && i < device_count; ++i) {
        if (!devices_to_use.empty() && (devices_to_use.find(i) == devices_to_use.end())) {
            continue;
        }

        cudaDeviceProp prop;
        CHECKED_CALL(cudaGetDeviceProperties(&prop, i));
        CHECKED_CALL(cudaSetDevice(i));

        // Size the batch so the real working set fills the free VRAM of this card.
        size_t free_v = 0, total_v = 0;
        cudaMemGetInfo(&free_v, &total_v);

        const size_t bytes_per_key = 32 + 32 * EXPAND;      // data (32) + kdata (32*EXPAND)
        const size_t reserve = (size_t)256 * 1024 * 1024 + total_v / 16;
        size_t usable = (free_v > reserve) ? (free_v - reserve) : (free_v / 2);
        size_t batch = usable / bytes_per_key;
        batch = (batch / 32) * 32;
        if (batch < 8192) batch = 8192;

        total_gpu_batch += batch;

        {
            std::lock_guard<std::mutex> lk(g_out);
            std::cout << "Using CUDA device " << i << ": " << prop.name
                      << "  VRAM free " << (free_v / (1024*1024)) << " MiB / "
                      << (total_v / (1024*1024)) << " MiB -> batch " << batch
                      << " keys (" << (batch * bytes_per_key) / (1024*1024) << " MiB)" << std::endl;
        }

        threads.emplace_back([i, batch, &rnd_buf, &patterns_str, &keys_checked, pat0]() -> int
        {
            CHECKED_CALL(cudaSetDevice(i));

            CHECKED_CALL(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));

            // Mix entropy into 32-byte secret key template
            uint8_t tmp_buf[sizeof(rnd_buf)];
            memcpy(tmp_buf, rnd_buf, sizeof(rnd_buf));

            // Mix in thread number
            tmp_buf[0] ^= i;

            // Mix all bits of the random buffer into the key template
            uint8_t key_template[32];
            keccak(tmp_buf, sizeof(tmp_buf), key_template, sizeof(key_template), 24);

            uint8_t* input_buf;
            CHECKED_CALL(cudaMalloc((void**)&input_buf, 32));
            CHECKED_CALL(cudaMemcpy(input_buf, key_template, sizeof(key_template), cudaMemcpyHostToDevice));

            uint64_t* data;
            CHECKED_CALL(cudaMalloc((void**)&data, batch * 32));

            uint64_t* kdata;
            CHECKED_CALL(cudaMalloc((void**)&kdata, batch * 32 * EXPAND));

            uint8_t* patterns;
            CHECKED_CALL(cudaMalloc((void**)&patterns, patterns_str.length()));
            CHECKED_CALL(cudaMemcpy(patterns, patterns_str.data(), patterns_str.length(), cudaMemcpyHostToDevice));

            uint32_t* results_key;
            CHECKED_CALL(cudaMalloc((void**)&results_key, 256 * sizeof(uint32_t)));
            uint32_t* results_ctr;
            CHECKED_CALL(cudaMalloc((void**)&results_ctr, 256 * sizeof(uint32_t)));

            for (uint64_t offset = 0;; offset += batch) {
                CHECKED_CALL(cudaMemset(results_key, 0, sizeof(uint32_t)));

                gpu::keccak_12_rounds<<<batch, 32>>>(input_buf, 32, offset, data);
                CHECKED_CALL(cudaGetLastError());

                gpu::reduce<<<batch / 32, 32>>>(data);
                CHECKED_CALL(cudaGetLastError());

                gpu::gen_public_keys_primary<<<batch / 32, 32>>>(data, kdata);
                CHECKED_CALL(cudaGetLastError());

                gpu::prefix_scan<<<batch / 32, 32>>>(patterns, patterns_str.length() / PATTERN_SIZE, kdata, results_key, results_ctr);
                CHECKED_CALL(cudaGetLastError());

                CHECKED_CALL(cudaDeviceSynchronize());

                uint32_t results_key_host[256];
                CHECKED_CALL(cudaMemcpy(results_key_host, results_key, sizeof(results_key_host), cudaMemcpyDeviceToHost));
                uint32_t results_ctr_host[256];
                CHECKED_CALL(cudaMemcpy(results_ctr_host, results_ctr, sizeof(results_ctr_host), cudaMemcpyDeviceToHost));

                uint32_t counter = 0;
                for (uint32_t i = 1, n = std::min(255u, results_key_host[0]); i <= n; ++i) {
                    uint8_t buf[32];
                    counter = results_ctr_host[i];

                    *((uint64_t*)key_template) ^= offset + results_key_host[i];
                    keccak(key_template, 32, buf, 32, 12);
                    *((uint64_t*)key_template) ^= offset + results_key_host[i];

                    sc_reduce32(buf);

                    uint8_t tor_secret_key[32];
                    uint8_t tor_secret_key_[32];

                    memcpy(tor_secret_key, buf, 32);
                    uint8_t fixup[32];
                    memset(fixup, 0, 32);

                    uint32_t incr = (counter+1) * 8;
                    memcpy(fixup, &incr, sizeof(incr));

                    scalar_add(tor_secret_key_, tor_secret_key, fixup);

                    uint8_t encoded_tor_secret_key[65];
                    for (int j = 0; j < 32; ++j) {
                        encoded_tor_secret_key[j * 2    ] = "0123456789abcdef"[tor_secret_key_[j] >> 4];
                        encoded_tor_secret_key[j * 2 + 1] = "0123456789abcdef"[tor_secret_key_[j] & 15];
                    }
                    encoded_tor_secret_key[64] = '\0';

                    if(n == i) {
                      std::lock_guard<std::mutex> lk(g_out);
                      hs_save(g_keys_root, (const char*)encoded_tor_secret_key, pat0, true);
                    }

                }

                keys_checked += batch; // for every key we generate we expand it
            }
            return 0;
        });
    }

    // ---- CPU workers, running in parallel with the GPU ----
    int cpu_n = 0;
    if (!no_cpu) {
        int hw = (int)std::thread::hardware_concurrency();
        if (hw <= 0) hw = 1;
        cpu_n = (cpu_threads_req > 0) ? cpu_threads_req : hw;

        uint64_t free_ram = free_ram_bytes();
        uint64_t budget = 0;
        if (cpu_mem_gb > 0.0) {
            budget = (uint64_t)(cpu_mem_gb * (double)(1ull << 30));
        } else {
            const uint64_t reserve = 4ull << 30;
            budget = (free_ram > reserve) ? (free_ram - reserve) : (free_ram / 2);
        }
        if (cpu_n > 0 && budget < (uint64_t)cpu_n * (4096ull * 32 * (EXPAND + 1))) {
            budget = (uint64_t)cpu_n * (4096ull * 32 * (EXPAND + 1));
        }

        size_t per_thread = (cpu_n > 0) ? (size_t)(budget / (uint64_t)cpu_n) : 0;
        size_t bytes_per_key = 32 * (EXPAND + 1);
        size_t cap_keys = per_thread / bytes_per_key;
        if (cpu_n > 0 && cap_keys < 4096) cap_keys = 4096;

        {
            std::lock_guard<std::mutex> lk(g_out);
            std::cout << "CPU workers: " << cpu_n << " threads, memory budget "
                      << (budget >> 20) << " MiB ("
                      << (per_thread >> 20) << " MiB/thread, "
                      << cap_keys << " keys/buffer)  [free RAM "
                      << (free_ram >> 20) << " MiB]" << std::endl;
        }

        for (int t = 0; t < cpu_n; ++t) {
            threads.emplace_back([t, pattern_vec, rnd_buf, &keys_checked, cap_keys]() {
                cpu_worker(t, pattern_vec, rnd_buf, sizeof(rnd_buf), &keys_checked, cap_keys);
            });
        }
    }

    if (threads.empty()) {
        std::cerr << "No workers (no GPU selected and CPU disabled)." << std::endl;
        return 1;
    }

    auto t1 = high_resolution_clock::now();
    // Timing information in million keys generated per second.
    uint64_t prev_keys_checked = 0;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(20));

        const uint64_t cur_keys_checked = keys_checked;
        const auto t2 = high_resolution_clock::now();

        const double dt = duration_cast<nanoseconds>(t2 - t1).count() * 1e-9;
        if(rate_info)
          std::cout << "KEYRATE: " << (cur_keys_checked - prev_keys_checked) / dt * 1e-6 << " million keys/second" << std::endl;
        t1 = t2;
        prev_keys_checked = cur_keys_checked;
    }

    return 0;
}
