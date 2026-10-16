
#pragma once

namespace gpu {

__constant__ const char alphabetB32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

__global__ void prefix_scan(const uint8_t* patterns, size_t pattern_count, const void* kdata, uint32_t* results_key, uint32_t* results_ctr)
{
	const uint8_t* p = reinterpret_cast<const uint8_t*>(kdata);
	const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
	p += index * 32 * EXPAND; // keys at 32 bytes each

	int x, y, j;
	uint64_t k, t=0;
	const char* abc = alphabetB32;
	uint8_t encoded_data[33];
	for(uint32_t counter=0; counter < EXPAND; ++counter) {
	  p += counter*32;
	// BASE32
	// encode 4*5 bytes from data...
	#pragma unroll 4
	  for(j=0; j<4; ++j)
	  {
	    t=0;
	  #pragma unroll 5
	    for(x=0, y=4; x < 5; ++x, --y)
	    {
	      k = p[x+(j*5)];
	      t += k << ((+y)*8);
	    }
	  #pragma unroll 8
	    for(x=0, y=7; x < 8; ++x, --y)
	    {
	      encoded_data[x+(j*8)] = abc[((t >> ((+y)*5)) & 0x1F)];
	    }
	  }
	
	  for (const uint8_t* ptrn = patterns, *e = patterns + pattern_count * PATTERN_SIZE; ptrn < e; ptrn += PATTERN_SIZE)
	  {

#define CHECK(index_) { const uint8_t c = ptrn[index_]; if ((c != '?') && (c != encoded_data[index_])) continue; }
	    CHECK(0);
	    CHECK(1);
	    CHECK(2);
	    CHECK(3);
	    CHECK(4);
	    CHECK(5);
	    CHECK(6);
	    CHECK(7);
	    CHECK(8);
	    CHECK(9);
	    CHECK(10);
	    CHECK(11);
	    CHECK(12);
	    CHECK(13);
	    CHECK(14);
	    CHECK(15);
	    CHECK(16);
	    CHECK(17);
	    CHECK(18);
	    CHECK(19);
	    CHECK(20);
	    CHECK(21);
	    CHECK(22);
	    CHECK(23);
	    CHECK(24);
	    CHECK(25);
	    CHECK(26);
	    CHECK(27);
	    CHECK(28);
	    CHECK(29);
	    CHECK(30);
	    CHECK(31);
#undef CHECK

	    const uint32_t k = atomicAdd(results_key, 1) + 1;
	    if (k < 256)
	    {
	      results_key[k] = index;
	      results_ctr[k] = counter;
	      goto EIA;
	    }
	  }
	}
 EIA:
	return;
}

} // gpu
