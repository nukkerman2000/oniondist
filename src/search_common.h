// search_common.h -- shared CPU-side primitives for onion vanity search.
//
// A "counter" c produces a key:  key = keccak( key_template ^ c )  (12 rounds)
//   md = sc_reduce32(key)
//   P  = md * B
//   slot s (0..EXPAND-1): P += 8*B ; pubkey = tobytes(P)
//   secret for slot s = md + 8*(s+1)
// The GPU path uses identical semantics (counter == offset + blockIdx), so a
// counter range can be handed to either a GPU agent or a CPU agent unchanged.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <functional>
#include <atomic>

#include "keccak.h"
extern "C" {
#include "crypto-ops.h"
}

#ifndef EXPAND
#define EXPAND 10
#endif

static const char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Host copy of the base point multiplied by 8 (identical to ge_eightpoint in gpu_crypto.h).
static const ge_cached ge_eightpoint_host = {
  {48496028, -16430416, 15164263, 11885335, 60784617, -4866353, 46481863, -2771805, 9708580, 2387263},
  {-10173472, -5540046, 21277639, 4080693, 1932823, -14916249, -9515873, -21787995, -36575460, 29827857},
  {25143927, -10256223, -3515585, 5715072, 19432778, -14905909, 22462083, -8862871, 13226552, 743677},
  {-784818, -8208065, -28479270, 5551579, 15746872, 4911053, 19117091, 11267669, -24569594, 14624995}
};

// Base32 of the first 20 bytes of a 32-byte pubkey (tor .onion style), 32 chars.
static inline void b32_encode(const uint8_t* pub, char* out) {
  for (int j = 0; j < 4; ++j) {
    uint64_t t = 0;
    for (int x = 0, y = 4; x < 5; ++x, --y) t += (uint64_t)pub[x + j * 5] << (y * 8);
    for (int x = 0, y = 7; x < 8; ++x, --y) out[x + j * 8] = b32_alphabet[(t >> (y * 5)) & 0x1F];
  }
}

// Match a 32-char base32 string against patterns of 32 chars ('?' = wildcard).
// Returns the index of the first matching pattern, or -1.
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

static inline void hex32(const uint8_t* d, char* out) {
  for (int i = 0; i < 32; ++i) {
    out[i * 2]     = "0123456789abcdef"[d[i] >> 4];
    out[i * 2 + 1] = "0123456789abcdef"[d[i] & 15];
  }
  out[64] = '\0';
}

// Search a contiguous range of counters [start, start+count) on the CPU.
// on_found() receives the 64-char hex secret key and the matched pattern.
static inline void cpu_search_counters(const uint8_t base_in[32],
                                       uint64_t start, uint64_t count,
                                       const std::vector<std::string>& patterns,
                                       std::atomic<uint64_t>* tested,
                                       const std::function<void(const char*, const std::string&)>& on_found,
                                       const std::atomic<bool>* stop)
{
  const uint64_t end = start + count;
  char enc[33];
  enc[32] = '\0';
  for (uint64_t c = start; c < end; ++c) {
    if (stop && stop->load(std::memory_order_relaxed)) break;
    uint8_t in[32];
    memcpy(in, base_in, 32);
    *(uint64_t*)in ^= c;

    uint8_t md[32];
    keccak(in, 32, md, 32, 12);
    sc_reduce32(md);

    ge_p3 point;
    ge_scalarmult_base(&point, md);
    for (int s = 0; s < EXPAND; ++s) {
      ge_p1p1 sum;
      ge_add(&sum, &point, &ge_eightpoint_host);
      ge_p1p1_to_p3(&point, &sum);
      uint8_t pub[32];
      ge_p3_tobytes(pub, &point);
      b32_encode(pub, enc);
      int pi = pattern_match(enc, patterns);
      if (pi >= 0) {
        uint8_t fixup[32];
        memset(fixup, 0, 32);
        uint32_t incr = (uint32_t)((s + 1) * 8);
        memcpy(fixup, &incr, sizeof(incr));
        uint8_t out[32];
        scalar_add(out, md, fixup);
        char hx[65];
        hex32(out, hx);
        on_found(hx, patterns[pi]);
      }
    }
    if (tested) tested->fetch_add(1, std::memory_order_relaxed);
  }
}
