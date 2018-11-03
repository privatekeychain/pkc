#ifndef INCLUDE_SIPHASHXN_H
#define INCLUDE_SIPHASHXN_H

#ifdef __AVX2__

#define ADD(a, b) _mm256_add_epi64(a, b)
#define XOR(a, b) _mm256_xor_si256(a, b)
#define ROTATE16 _mm256_set_epi64x(0x0D0C0B0A09080F0EULL,0x0504030201000706ULL, \
                                   0x0D0C0B0A09080F0EULL, 0x0504030201000706ULL)
#define ROT13(x) _mm256_or_si256(_mm256_slli_epi64(x,13),_mm256_srli_epi64(x,51))
#define ROT16(x) _mm256_shuffle_epi8((x), ROTATE16)
#define ROT17(x) _mm256_or_si256(_mm256_slli_epi64(x,17),_mm256_srli_epi64(x,47))
#define ROT21(x) _mm256_or_si256(_mm256_slli_epi64(x,21),_mm256_srli_epi64(x,43))
#define ROT32(x) _mm256_shuffle_epi32((x), _MM_SHUFFLE(2, 3, 0, 1))

#elif defined __SSE2__

#define ADD(a, b) _mm_add_epi64(a, b)
#define XOR(a, b) _mm_xor_si128(a, b)
#define ROT13(x) _mm_or_si128(_mm_slli_epi64(x,13),_mm_srli_epi64(x,51))
#define ROT16(x) _mm_shufflehi_epi16(_mm_shufflelo_epi16(x, _MM_SHUFFLE(2,1,0,3)), _MM_SHUFFLE(2,1,0,3))
#define ROT17(x) _mm_or_si128(_mm_slli_epi64(x,17),_mm_srli_epi64(x,47))
#define ROT21(x) _mm_or_si128(_mm_slli_epi64(x,21),_mm_srli_epi64(x,43))
#define ROT32(x) _mm_shuffle_epi32  (x, _MM_SHUFFLE(2,3,0,1))

#endif

#define SIPROUNDXN \
  do { \
    v0 = ADD(v0,v1); v2 = ADD(v2,v3); v1 = ROT13(v1); \
    v3 = ROT16(v3);  v1 = XOR(v1,v0); v3 = XOR(v3,v2); \
    v0 = ROT32(v0);  v2 = ADD(v2,v1); v0 = ADD(v0,v3); \
    v1 = ROT17(v1);                   v3 = ROT21(v3); \
    v1 = XOR(v1,v2); v3 = XOR(v3,v0); v2 = ROT32(v2); \
  } while(0)

#define SIPROUNDX2N \
  do { \
    v0 = ADD(v0,v1); v4 = ADD(v4,v5); \
    v2 = ADD(v2,v3); v6 = ADD(v6,v7); \
    v1 = ROT13(v1);  v5 = ROT13(v5); \
    v3 = ROT16(v3);  v7 = ROT16(v7); \
    v1 = XOR(v1,v0); v5 = XOR(v5,v4); \
    v3 = XOR(v3,v2); v7 = XOR(v7,v6); \
    v0 = ROT32(v0);  v4 = ROT32(v4); \
    v2 = ADD(v2,v1); v6 = ADD(v6,v5); \
    v0 = ADD(v0,v3); v4 = ADD(v4,v7); \
    v1 = ROT17(v1);  v5 = ROT17(v5); \
    v3 = ROT21(v3);  v7 = ROT21(v7); \
    v1 = XOR(v1,v2); v5 = XOR(v5,v6); \
    v3 = XOR(v3,v0); v7 = XOR(v7,v4); \
    v2 = ROT32(v2);  v6 = ROT32(v6); \
  } while(0)
 
#define SIPROUNDX4N \
  do { \
    v0 = ADD(v0,v1); v4 = ADD(v4,v5);  v8 = ADD(v8,v9); vC = ADD(vC,vD); \
    v2 = ADD(v2,v3); v6 = ADD(v6,v7);  vA = ADD(vA,vB); vE = ADD(vE,vF); \
    v1 = ROT13(v1);  v5 = ROT13(v5);   v9 = ROT13(v9);  vD = ROT13(vD); \
    v3 = ROT16(v3);  v7 = ROT16(v7);   vB = ROT16(vB);  vF = ROT16(vF); \
    v1 = XOR(v1,v0); v5 = XOR(v5,v4);  v9 = XOR(v9,v8); vD = XOR(vD,vC); \
    v3 = XOR(v3,v2); v7 = XOR(v7,v6);  vB = XOR(vB,vA); vF = XOR(vF,vE); \
    v0 = ROT32(v0);  v4 = ROT32(v4);   v8 = ROT32(v8);  vC = ROT32(vC); \
    v2 = ADD(v2,v1); v6 = ADD(v6,v5);  vA = ADD(vA,v9); vE = ADD(vE,vD); \
    v0 = ADD(v0,v3); v4 = ADD(v4,v7);  v8 = ADD(v8,vB); vC = ADD(vC,vF); \
    v1 = ROT17(v1);  v5 = ROT17(v5);   v9 = ROT17(v9);  vD = ROT17(vD); \
    v3 = ROT21(v3);  v7 = ROT21(v7);   vB = ROT21(vB);  vF = ROT21(vF); \
    v1 = XOR(v1,v2); v5 = XOR(v5,v6);  v9 = XOR(v9,vA); vD = XOR(vD,vE); \
    v3 = XOR(v3,v0); v7 = XOR(v7,v4);  vB = XOR(vB,v8); vF = XOR(vF,vC); \
    v2 = ROT32(v2);  v6 = ROT32(v6);   vA = ROT32(vA);  vE = ROT32(vE); \
  } while(0)

#ifdef __AVX2__

// 4-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x4(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes);

// 8-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x8(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes);

// 16-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x16(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes);
#elif defined __SSE2__

// 2-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x2(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes);

// 4-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x4(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes);
#endif

#ifndef NSIPHASH
// how many siphash24 to compute in parallel
// currently 1, 2, 4, 8 are supported, but
// more than 1 requires the use of sse2 or avx2
// more than 4 requires the use of avx2
#define NSIPHASH 1
#endif

void siphash24xN(const siphash_keys *keys, const uint64_t *indices, uint64_t * hashes);

#endif // ifdef INCLUDE_SIPHASHXN_H
