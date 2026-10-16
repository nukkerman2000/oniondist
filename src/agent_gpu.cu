// agent_gpu.cu -- distributed GPU agent for oniondist.
//
// Pulls counter ranges from the coordinator and searches them on the GPU using
// exactly the same kernels/algorithm as the local vanity_torv3_cuda tool.
//
//   ./vanity_gpu --server http://host:8080 --name rig-3090 [-d 0] [-i]
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <random>
#include <thread>
#include <chrono>

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

#include "search_common.h"
#include "hs_store.h"
#include "dist.h"

static const char* g_keys_root = "keys";

#define CHECKED_CALL(X) do { \
        const cudaError_t err = X; \
        if (err != cudaSuccess) { \
            std::fprintf(stderr, #X " (line %d) failed: %s\n", __LINE__, cudaGetErrorString(err)); \
            return 1; \
        } \
    } while(0)

int main(int argc, char** argv) {
    std::string server, name = "gpu";
    int dev = 0;
    bool rate_info = false;
    size_t batch_cap = 0;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc) { server = argv[++i]; continue; }
        if (a == "--name" && i + 1 < argc) { name = argv[++i]; continue; }
        if (a == "-d" && i + 1 < argc) { dev = atoi(argv[++i]); continue; }
        if (a == "-b" && i + 1 < argc) { batch_cap = strtoull(argv[++i], nullptr, 10); continue; }
        if (a == "--keys" && i + 1 < argc) { g_keys_root = argv[++i]; continue; }
        if (a == "-i") { rate_info = true; continue; }
        std::fprintf(stderr, "Unknown argument: %s\n", a.c_str());
    }
    if (server.empty()) {
        std::fprintf(stderr,
            "Usage: %s --server http://host:port [--name NAME] [-d 0] [-b MAXBATCH] [-i]\n",
            argv[0]);
        return 1;
    }

    dist::Coordinator coord;
    if (!dist::parse_url(server, coord.url)) {
        std::fprintf(stderr, "Bad --server URL: %s\n", server.c_str());
        return 1;
    }
    coord.name = name;
    coord.kind = "gpu";

    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count == 0) {
        std::fprintf(stderr, "No CUDA device available.\n");
        return 1;
    }
    CHECKED_CALL(cudaSetDevice(dev));
    cudaDeviceProp prop;
    CHECKED_CALL(cudaGetDeviceProperties(&prop, dev));
    CHECKED_CALL(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));

    size_t free_v = 0, total_v = 0;
    cudaMemGetInfo(&free_v, &total_v);
    const size_t bytes_per_key = 32 + 32 * EXPAND;
    const size_t reserve = (size_t)256 * 1024 * 1024 + total_v / 16;
    size_t usable = (free_v > reserve) ? (free_v - reserve) : (free_v / 2);
    size_t batch = usable / bytes_per_key;
    batch = (batch / 32) * 32;
    if (batch < 8192) batch = 8192;
    if (batch_cap && batch > batch_cap) batch = (batch_cap / 32) * 32;

    std::printf("agent_gpu [%s] on %s: VRAM %zu/%zu MiB -> batch %zu\n",
                name.c_str(), prop.name,
                free_v >> 20, total_v >> 20, batch);

    // Base key template
    std::random_device rd;
    uint32_t seed[256];
    for (auto& w : seed) w = rd();
    uint8_t key_template[32];
    keccak(seed, sizeof(seed), key_template, 32, 24);

    uint8_t* input_buf; CHECKED_CALL(cudaMalloc((void**)&input_buf, 32));
    CHECKED_CALL(cudaMemcpy(input_buf, key_template, 32, cudaMemcpyHostToDevice));
    uint64_t* data;  CHECKED_CALL(cudaMalloc((void**)&data, batch * 32));
    uint64_t* kdata; CHECKED_CALL(cudaMalloc((void**)&kdata, batch * 32 * EXPAND));
    uint8_t* patterns; CHECKED_CALL(cudaMalloc((void**)&patterns, PATTERN_SIZE));
    uint32_t* results_key; CHECKED_CALL(cudaMalloc((void**)&results_key, 256 * sizeof(uint32_t)));
    uint32_t* results_ctr; CHECKED_CALL(cudaMalloc((void**)&results_ctr, 256 * sizeof(uint32_t)));

    std::string last_pattern;
    uint64_t tested = 0, chunks = 0;
    auto t_report = std::chrono::high_resolution_clock::now();
    uint64_t tested_at_report = 0;

    for (;;) {
        dist::Work w = coord.get_work(batch);
        if (!w.valid) {
            std::fprintf(stderr, "No work, retrying...\n");
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }
        std::string pat = w.pattern;
        if (pat.size() > 32) pat.resize(32);
        while (pat.size() < 32) pat += '?';
        if (pat != last_pattern) {
            CHECKED_CALL(cudaMemcpy(patterns, pat.data(), 32, cudaMemcpyHostToDevice));
            last_pattern = pat;
        }

        const uint64_t chunk_end = w.start + w.count;
        for (uint64_t offset = w.start; offset < chunk_end; offset += batch) {
            uint64_t b = batch;
            if (offset + b > chunk_end) b = chunk_end - offset;
            if (b < 32) break;
            b = (b / 32) * 32;
            if (b == 0) break;

            CHECKED_CALL(cudaMemset(results_key, 0, sizeof(uint32_t)));

            gpu::keccak_12_rounds<<<b, 32>>>(input_buf, 32, offset, data);
            CHECKED_CALL(cudaGetLastError());
            gpu::reduce<<<(uint32_t)(b / 32), 32>>>(data);
            CHECKED_CALL(cudaGetLastError());
            gpu::gen_public_keys_primary<<<(uint32_t)(b / 32), 32>>>(data, kdata);
            CHECKED_CALL(cudaGetLastError());
            gpu::prefix_scan<<<(uint32_t)(b / 32), 32>>>(patterns, 1, kdata, results_key, results_ctr);
            CHECKED_CALL(cudaGetLastError());
            CHECKED_CALL(cudaDeviceSynchronize());

            uint32_t rk[256], rc[256];
            CHECKED_CALL(cudaMemcpy(rk, results_key, sizeof(rk), cudaMemcpyDeviceToHost));
            CHECKED_CALL(cudaMemcpy(rc, results_ctr, sizeof(rc), cudaMemcpyDeviceToHost));

            for (uint32_t i = 1, n = std::min(255u, rk[0]); i <= n; ++i) {
                uint8_t buf[32];
                *((uint64_t*)key_template) ^= offset + rk[i];
                keccak(key_template, 32, buf, 32, 12);
                *((uint64_t*)key_template) ^= offset + rk[i];
                sc_reduce32(buf);

                uint8_t fixup[32];
                memset(fixup, 0, 32);
                uint32_t incr = (rc[i] + 1) * 8;
                memcpy(fixup, &incr, sizeof(incr));
                uint8_t sk[32];
                scalar_add(sk, buf, fixup);
                char hx[65];
                hex32(sk, hx);

                hs_save(g_keys_root, hx, w.pattern, true);
                coord.found(hx, w.pattern, offset + rk[i]);
            }
            tested += b;
        }
        ++chunks;

        auto now = std::chrono::high_resolution_clock::now();
        double dt = std::chrono::duration_cast<std::chrono::nanoseconds>(now - t_report).count() * 1e-9;
        if (dt >= 10.0) {
            double r = (tested - tested_at_report) / dt;
            coord.report(tested, r, chunks);
            if (rate_info)
                std::printf("rate %.3f M keys/s  (chunk %llu, tested %llu)\n",
                            r * 1e-6, (unsigned long long)chunks, (unsigned long long)tested);
            std::fflush(stdout);
            t_report = now;
            tested_at_report = tested;
        }
    }
    return 0;
}
