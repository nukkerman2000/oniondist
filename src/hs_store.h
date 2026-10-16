// hs_store.h -- turn a found tor v3 secret key into a ready-to-use hidden
// service directory, and render the full 56-char .onion address.
//
// Layout produced for every hit:
//
//     <root>/<pattern>/<onion>/hostname
//                              hs_ed25519_secret_key
//                              hs_ed25519_public_key
//
// Identical to upstream util/genpubs.py, so tor can host the result directly.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <random>

#ifdef _WIN32
#include <direct.h>
#define HS_MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define HS_MKDIR(p) mkdir(p, 0700)
#endif

extern "C" {
#include "crypto-ops.h"
}

void keccakf(uint64_t* st, int rounds);  // from keccak.cpp

static const char HS_B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ---- SHA3-256 (NIST padding 0x06, rate 136) built on the keccak-f[1600] perm ----
static inline void hs_sha3_256(const uint8_t* in, size_t inlen, uint8_t out[32]) {
  const int rsiz = 136;
  uint64_t st[25];
  memset(st, 0, sizeof(st));

  size_t i = 0;
  while (inlen - i >= (size_t)rsiz) {
    for (int w = 0; w < rsiz / 8; ++w) {
      uint64_t t;
      memcpy(&t, in + i + w * 8, 8);
      st[w] ^= t;
    }
    keccakf(st, 24);
    i += rsiz;
  }

  uint8_t temp[136];
  memset(temp, 0, rsiz);
  size_t rem = inlen - i;
  memcpy(temp, in + i, rem);
  temp[rem] = 0x06;
  temp[rsiz - 1] |= 0x80;
  for (int w = 0; w < rsiz / 8; ++w) {
    uint64_t t;
    memcpy(&t, temp + w * 8, 8);
    st[w] ^= t;
  }
  keccakf(st, 24);
  memcpy(out, st, 32);
}

// Base32 (RFC4648, no padding) of an arbitrary byte string.
static inline void hs_b32(const uint8_t* data, int n, char* out) {
  int bits = 0, j = 0;
  uint32_t acc = 0;
  for (int i = 0; i < n; ++i) {
    acc = (acc << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      out[j++] = HS_B32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out[j++] = HS_B32[(acc << (5 - bits)) & 31];
  out[j] = '\0';
}

// Full v3 .onion hostname (56 lowercase chars, no ".onion") from a 32-byte pubkey.
static inline void hs_onion_from_pub(const uint8_t pub[32], char out57[57]) {
  uint8_t msg[48];
  memcpy(msg, ".onion checksum", 15);
  memcpy(msg + 15, pub, 32);
  msg[47] = 0x03;

  uint8_t chk[32];
  hs_sha3_256(msg, sizeof(msg), chk);

  uint8_t buf[35];
  memcpy(buf, pub, 32);
  buf[32] = chk[0];
  buf[33] = chk[1];
  buf[34] = 0x03;

  char up[57];
  hs_b32(buf, 35, up);
  for (int i = 0; i < 56; ++i)
    out57[i] = (up[i] >= 'A' && up[i] <= 'Z') ? (char)(up[i] + 32) : up[i];
  out57[56] = '\0';
}

static inline void hs_mkdirs(const std::string& path) {
  std::string cur;
  for (size_t i = 0; i < path.size(); ++i) {
    cur += path[i];
    if (path[i] == '/' || path[i] == '\\') HS_MKDIR(cur.c_str());
  }
  HS_MKDIR(path.c_str());
}

// Folder name for a query: the fixed (non-'?') part, lower-cased.
static inline std::string hs_pattern_name(const std::string& pattern) {
  std::string p = pattern;
  size_t q = p.find('?');
  if (q != std::string::npos) p = p.substr(0, q);
  std::string o;
  for (size_t i = 0; i < p.size(); ++i) {
    char c = p[i];
    o += (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
  }
  return o.empty() ? std::string("any") : o;
}

static inline void hs_random(uint8_t* out, int n) {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  for (int i = 0; i < n; ++i) out[i] = (uint8_t)rng();
}

static inline bool hs_write(const std::string& path, const uint8_t* data, size_t n) {
  FILE* f = fopen(path.c_str(), "wb");
  if (!f) return false;
  size_t w = fwrite(data, 1, n, f);
  fclose(f);
  return w == n;
}

static inline int hs_hexval(char c) {
  return (c <= '9') ? (c - '0') : ((c | 32) - 'a' + 10);
}

// Writes <root>/<pattern>/<onion>/{hostname,hs_ed25519_secret_key,hs_ed25519_public_key}.
// Returns the onion hostname (no ".onion"). Prints "onion.onion  secret_hex" when print.
static inline std::string hs_save(const char* root, const char* secret_hex,
                                  const std::string& pattern, bool print) {
  uint8_t secret[32];
  for (int i = 0; i < 32; ++i)
    secret[i] = (uint8_t)((hs_hexval(secret_hex[i * 2]) << 4) | hs_hexval(secret_hex[i * 2 + 1]));

  ge_p3 P;
  ge_scalarmult_base(&P, secret);
  uint8_t pub[32];
  ge_p3_tobytes(pub, &P);

  char onion[57];
  hs_onion_from_pub(pub, onion);

  std::string dir = std::string(root) + "/" + hs_pattern_name(pattern) + "/" + onion;
  hs_mkdirs(dir);

  char host[80];
  snprintf(host, sizeof(host), "%s.onion\n", onion);
  hs_write(dir + "/hostname", (const uint8_t*)host, strlen(host));

  const char* shdr = "== ed25519v1-secret: type0 ==";
  const char* phdr = "== ed25519v1-public: type0 ==";
  const size_t sh = strlen(shdr), ph = strlen(phdr);

  uint8_t sk[128];
  memcpy(sk, shdr, sh);
  sk[sh] = 0; sk[sh + 1] = 0; sk[sh + 2] = 0;
  memcpy(sk + sh + 3, secret, 32);
  uint8_t rnd[32];
  hs_random(rnd, 32);
  memcpy(sk + sh + 3 + 32, rnd, 32);
  hs_write(dir + "/hs_ed25519_secret_key", sk, sh + 3 + 64);

  uint8_t pk[128];
  memcpy(pk, phdr, ph);
  pk[ph] = 0; pk[ph + 1] = 0; pk[ph + 2] = 0;
  memcpy(pk + ph + 3, pub, 32);
  hs_write(dir + "/hs_ed25519_public_key", pk, ph + 3 + 32);

  if (print) {
    std::printf("%s.onion  %s\n", onion, secret_hex);
    std::fflush(stdout);
  }
  return std::string(onion);
}
