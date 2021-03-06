#include "siphashxN.h"


#ifdef __AVX2__

void siphash24x4(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
    const __m256i packet = _mm256_load_si256((__m256i *)indices);
    __m256i v0 = _mm256_set1_epi64x(keys->k0);
    __m256i v1 = _mm256_set1_epi64x(keys->k1);
    __m256i v2 = _mm256_set1_epi64x(keys->k2);
    __m256i v3 = _mm256_set1_epi64x(keys->k3);

    v3 = XOR(v3,packet);
    SIPROUNDXN; SIPROUNDXN;
    v0 = XOR(v0,packet);
    v2 = XOR(v2,_mm256_set1_epi64x(0xffLL));
    SIPROUNDXN; SIPROUNDXN; SIPROUNDXN; SIPROUNDXN;
    _mm256_store_si256((__m256i *)hashes, XOR(XOR(v0,v1),XOR(v2,v3)));
}

void siphash24x8(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
    const __m256i packet0 = _mm256_load_si256((__m256i *)indices);
    const __m256i packet4 = _mm256_load_si256((__m256i *)(indices+4));
    __m256i v0, v1, v2, v3, v4, v5, v6, v7;
    v7 = v3 = _mm256_set1_epi64x(keys->k3);
    v4 = v0 = _mm256_set1_epi64x(keys->k0);
    v5 = v1 = _mm256_set1_epi64x(keys->k1);
    v6 = v2 = _mm256_set1_epi64x(keys->k2);

    v3 = XOR(v3,packet0); v7 = XOR(v7,packet4);
    SIPROUNDX2N; SIPROUNDX2N;
    v0 = XOR(v0,packet0); v4 = XOR(v4,packet4);
    v2 = XOR(v2,_mm256_set1_epi64x(0xffLL));
    v6 = XOR(v6,_mm256_set1_epi64x(0xffLL));
    SIPROUNDX2N; SIPROUNDX2N; SIPROUNDX2N; SIPROUNDX2N;
    _mm256_store_si256((__m256i *)hashes, XOR(XOR(v0,v1),XOR(v2,v3)));
    _mm256_store_si256((__m256i *)(hashes+4), XOR(XOR(v4,v5),XOR(v6,v7)));
}

void siphash24x16(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
    const __m256i packet0 = _mm256_load_si256((__m256i *)indices);
    const __m256i packet4 = _mm256_load_si256((__m256i *)(indices+4));
    const __m256i packet8 = _mm256_load_si256((__m256i *)(indices+8));
    const __m256i packetC = _mm256_load_si256((__m256i *)(indices+12));
    __m256i v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, vA, vB, vC, vD, vE, vF;
    vF = vB = v7 = v3 = _mm256_set1_epi64x(keys->k3);
    vC = v8 = v4 = v0 = _mm256_set1_epi64x(keys->k0);
    vD = v9 = v5 = v1 = _mm256_set1_epi64x(keys->k1);
    vE = vA = v6 = v2 = _mm256_set1_epi64x(keys->k2);

    v3 = XOR(v3,packet0); v7 = XOR(v7,packet4); vB = XOR(vB,packet8); vF = XOR(vF,packetC);
    SIPROUNDX4N; SIPROUNDX4N;
    v0 = XOR(v0,packet0); v4 = XOR(v4,packet4); v8 = XOR(v8,packet8); vC = XOR(vC,packetC);
    v2 = XOR(v2,_mm256_set1_epi64x(0xffLL));
    v6 = XOR(v6,_mm256_set1_epi64x(0xffLL));
    vA = XOR(vA,_mm256_set1_epi64x(0xffLL));
    vE = XOR(vE,_mm256_set1_epi64x(0xffLL));
    SIPROUNDX4N; SIPROUNDX4N; SIPROUNDX4N; SIPROUNDX4N;
    _mm256_store_si256((__m256i *) hashes    , XOR(XOR(v0,v1),XOR(v2,v3)));
    _mm256_store_si256((__m256i *)(hashes+ 4), XOR(XOR(v4,v5),XOR(v6,v7)));
    _mm256_store_si256((__m256i *)(hashes+ 8), XOR(XOR(v8,v9),XOR(vA,vB)));
    _mm256_store_si256((__m256i *)(hashes+12), XOR(XOR(vC,vD),XOR(vE,vF)));
}

#elif defined __SSE2__

void siphash24x2(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
    __m128i v0, v1, v2, v3, mi;
    v0 = _mm_set1_epi64x(keys->k0);
    v1 = _mm_set1_epi64x(keys->k1);
    v2 = _mm_set1_epi64x(keys->k2);
    v3 = _mm_set1_epi64x(keys->k3);
    mi = _mm_load_si128((__m128i *)indices);

    v3 = XOR (v3, mi);
    SIPROUNDXN; SIPROUNDXN;
    v0 = XOR (v0, mi);

    v2 = XOR (v2, _mm_set1_epi64x(0xffLL));
    SIPROUNDXN; SIPROUNDXN; SIPROUNDXN; SIPROUNDXN;
    mi = XOR(XOR(v0,v1),XOR(v2,v3));

    _mm_store_si128((__m128i *)hashes, mi);
}

void siphash24x4(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
    __m128i v0, v1, v2, v3, mi, v4, v5, v6, v7, m2;
    v4 = v0 = _mm_set1_epi64x(keys->k0);
    v5 = v1 = _mm_set1_epi64x(keys->k1);
    v6 = v2 = _mm_set1_epi64x(keys->k2);
    v7 = v3 = _mm_set1_epi64x(keys->k3);

    mi = _mm_load_si128((__m128i *)indices);
    m2 = _mm_load_si128((__m128i *)(indices + 2));

    v3 = XOR (v3, mi);
    v7 = XOR (v7, m2);
    SIPROUNDX2N; SIPROUNDX2N;
    v0 = XOR (v0, mi);
    v4 = XOR (v4, m2);

    v2 = XOR (v2, _mm_set1_epi64x(0xffLL));
    v6 = XOR (v6, _mm_set1_epi64x(0xffLL));
    SIPROUNDX2N; SIPROUNDX2N; SIPROUNDX2N; SIPROUNDX2N;
    mi = XOR(XOR(v0,v1),XOR(v2,v3));
    m2 = XOR(XOR(v4,v5),XOR(v6,v7));

    _mm_store_si128((__m128i *)hashes,		mi);
    _mm_store_si128((__m128i *)(hashes + 2),m2);
}

#endif

void siphash24xN(const siphash_keys *keys, const uint64_t *indices, uint64_t * hashes) {
#if NSIPHASH == 1
    *hashes = siphash24(keys, *indices);
#elif NSIPHASH == 2
    siphash24x2(keys, indices, hashes);
#elif NSIPHASH == 4
  siphash24x4(keys, indices, hashes);
#elif NSIPHASH == 8
  siphash24x8(keys, indices, hashes);
#elif NSIPHASH == 16
  siphash24x16(keys, indices, hashes);
#else
#error not implemented
#endif
}
