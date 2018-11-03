#include "siphash.h"


void cuckooSetkeys(siphash_keys *keys, const char *keybuf) {
    keys->k0 = htole64(((uint64_t *)keybuf)[0]);
    keys->k1 = htole64(((uint64_t *)keybuf)[1]);
    keys->k2 = htole64(((uint64_t *)keybuf)[2]);
    keys->k3 = htole64(((uint64_t *)keybuf)[3]);
}

uint64_t siphash24(const siphash_keys *keys, const uint64_t nonce) {
    uint64_t v0 = keys->k0, v1 = keys->k1, v2 = keys->k2, v3 = keys->k3 ^ nonce;
    SIPROUND; SIPROUND;
    v0 ^= nonce;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return (v0 ^ v1) ^ (v2  ^ v3);
}
