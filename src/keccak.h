
#pragma once

#include <cstdint>

void keccak(const void* in, int inlen, uint8_t* md, int mdlen, int rounds);
