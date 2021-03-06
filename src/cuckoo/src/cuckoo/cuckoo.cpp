#include "cuckoo.h"

word_t cuckooSipnode(siphash_keys *keys, word_t edge, u32 uorv) {
    return siphash24(keys, 2*edge + uorv) & EDGEMASK;
}

const char *errstr[] = { "OK", "wrong header length", "edge too big", "edges not ascending", "endpoints don't match up", "branch in cycle", "cycle dead ends", "cycle too short"};

int cuckooVerify(word_t edges[PROOFSIZE], siphash_keys *keys) {
    word_t uvs[2*PROOFSIZE];
    word_t xor0 = 0, xor1  =0;
    for (u32 n = 0; n < PROOFSIZE; n++) {
        if (edges[n] > EDGEMASK)
            return POW_TOO_BIG;
        if (n && edges[n] <= edges[n-1])
            return POW_TOO_SMALL;
        xor0 ^= uvs[2*n  ] = cuckooSipnode(keys, edges[n], 0);
        xor1 ^= uvs[2*n+1] = cuckooSipnode(keys, edges[n], 1);
    }
    if (xor0|xor1)              // optional check for obviously bad proofs
        return POW_NON_MATCHING;
    u32 n = 0, i = 0, j;
    do {                        // follow cycle
        for (u32 k = j = i; (k = (k+2) % (2*PROOFSIZE)) != i; ) {
            if (uvs[k] == uvs[i]) { // find other edge endpoint identical to one at i
                if (j != i)           // already found one before
                    return POW_BRANCH;
                j = k;
            }
        }
        if (j == i) return POW_DEAD_END;  // no matching endpoint
        i = j^1;
        n++;
    } while (i != 0);           // must cycle back to start or we would have found branch
    return n == PROOFSIZE ? POW_OK : POW_SHORT_CYCLE;
}


void cuckooSetheader(const char *header, const u32 headerlen, siphash_keys *keys) {
    char hdrkey[32];
    // SHA256((unsigned char *)header, headerlen, (unsigned char *)hdrkey);
    blake2b((void *)hdrkey, sizeof(hdrkey), (const void *)header, headerlen, 0, 0);
#ifdef SIPHASH_COMPAT
    u64 *k = (u64 *)hdrkey;
  u64 k0 = k[0];
  u64 k1 = k[1];
  printf("k0 k1 %lx %lx\n", k0, k1);
  k[0] = k0 ^ 0x736f6d6570736575ULL;
  k[1] = k1 ^ 0x646f72616e646f6dULL;
  k[2] = k0 ^ 0x6c7967656e657261ULL;
  k[3] = k1 ^ 0x7465646279746573ULL;
#endif
    cuckooSetkeys(keys, hdrkey);
}

word_t sipnode_(siphash_keys *keys, word_t edge, u32 uorv) {
    return cuckooSipnode(keys, edge, uorv) << 1 | uorv;
}

