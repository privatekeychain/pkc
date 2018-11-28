#ifndef INCLUDE_CUCKOO_H
#define INCLUDE_CUCKOO_H

// Cuckoo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2017 John Tromp

#include <stdint.h> // for types uint32_t,uint64_t
#include <string.h> // for functions strlen, memset
#include "../crypto/blake2.h"
#include "../crypto/siphash.h"

#ifdef SIPHASH_COMPAT
#include <stdio.h>
#endif

#define EDGEBITS 19

// proof-of-work parameters
#ifndef EDGEBITS
// the main parameter is the 2-log of the graph size,
// which is the size in bits of the node identifiers
#define EDGEBITS 29
#endif
#ifndef PROOFSIZE
// the next most important parameter is the (even) length
// of the cycle to be found. a minimum of 12 is recommended
#define PROOFSIZE 42
#endif

// save some keystrokes since i'm a lazy typer
typedef uint32_t u32;

#if EDGEBITS > 30
typedef uint64_t word_t;
#elif EDGEBITS > 14
typedef u32 word_t;
#else // if EDGEBITS <= 14
typedef uint16_t word_t;
#endif

// number of edges
#define NEDGES ((word_t)1 << EDGEBITS)
// used to mask siphash output
#define EDGEMASK ((word_t)NEDGES - 1)

// generate edge endpoint in cuckoo graph without partition bit
word_t cuckooSipnode(siphash_keys *keys, word_t edge, u32 uorv);

enum verify_code { POW_OK, POW_HEADER_LENGTH, POW_TOO_BIG, POW_TOO_SMALL, POW_NON_MATCHING, POW_BRANCH, POW_DEAD_END, POW_SHORT_CYCLE};

extern const char *errstr[];

// verify that edges are ascending and form a cycle in header-generated graph
int cuckooVerify(word_t edges[PROOFSIZE], siphash_keys *keys);

// convenience function for extracting siphash keys from header
void cuckooSetheader(const char *header, const u32 headerlen, siphash_keys *keys);

// edge endpoint in cuckoo graph with partition bit
word_t sipnode_(siphash_keys *keys, word_t edge, u32 uorv);

#endif // #ifndef INCLUDE_CUCKOO_H
