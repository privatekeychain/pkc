#include <stdexcept>
#include "lean.hpp"

void cuckoo_ctx::count_node_deg(const u32 id, const u32 uorv, const u32 part) {
    alignas(64) u64 indices[NSIPHASH];
    alignas(64) u64 hashes[NPREFETCH];

    memset(hashes, 0, NPREFETCH * sizeof(u64)); // allow many nonleaf->set(0) to reduce branching
    u32 nidx = 0;
    for (word_t block = id*64; block < NEDGES; block += nthreads*64) {
        u64 alive64 = alive->block(block);
        for (word_t nonce = block-1; alive64; ) { // -1 compensates for 1-based ffs
            u32 ffs = __builtin_ffsll(alive64);
            nonce += ffs; alive64 >>= ffs;
            indices[nidx++ % NSIPHASH] = 2*nonce + uorv;
            if (nidx % NSIPHASH == 0) {
                node_deg(hashes+nidx-NSIPHASH, NSIPHASH, part);
                siphash24xN(&sip_keys, indices, hashes+nidx-NSIPHASH);
                prefetch(hashes+nidx-NSIPHASH, part);
                nidx %= NPREFETCH;
            }
            if (ffs & 64) break; // can't shift by 64
        }
    }
    node_deg(hashes, NPREFETCH, part);
    if (nidx % NSIPHASH != 0) {
        siphash24xN(&sip_keys, indices, hashes+(nidx&-NSIPHASH));
        node_deg(hashes+(nidx&-NSIPHASH), nidx%NSIPHASH, part);
    }
}


void cuckoo_ctx::kill_leaf_edges(const u32 id, const u32 uorv, const u32 part) {
    alignas(64) u64 indices[NPREFETCH];
    alignas(64) u64 hashes[NPREFETCH];

    memset(hashes, 0, NPREFETCH * sizeof(u64)); // allow many nonleaf->test(0) to reduce branching
    u32 nidx = 0;
    for (word_t block = id*64; block < NEDGES; block += nthreads*64) {
        u64 alive64 = alive->block(block);
        for (word_t nonce = block-1; alive64; ) { // -1 compensates for 1-based ffs
            u32 ffs = __builtin_ffsll(alive64);
            nonce += ffs; alive64 >>= ffs;
            indices[nidx++] = 2*nonce + uorv;
            if (nidx % NSIPHASH == 0) {
                siphash24xN(&sip_keys, indices+nidx-NSIPHASH, hashes+nidx-NSIPHASH);
                prefetch(hashes+nidx-NSIPHASH, part);
                nidx %= NPREFETCH;
                kill(hashes+nidx, indices+nidx, NSIPHASH, part, id);
            }
            if (ffs & 64) break; // can't shift by 64
        }
    }
    const u32 pnsip = nidx & -NSIPHASH;
    if (pnsip != nidx) {
        siphash24xN(&sip_keys, indices+pnsip, hashes+pnsip);
    }
    kill(hashes, indices, nidx, part, id);
    const u32 nnsip = pnsip + NSIPHASH;
    kill(hashes+nnsip, indices+nnsip, NPREFETCH-nnsip, part, id);
}

u32 cuckooPath(cuckoo_hash &cuckoo, word_t u, word_t *us) {
    u32 nu;
    for (nu = 0; u; u = cuckoo[u]) {
        if (nu >= MAXPATHLEN) {
            while (nu-- && us[nu] != u) ;
//            if (!~nu)
//                printf("maximum path length exceeded\n");
//            else printf("illegal %4d-cycle\n", MAXPATHLEN-nu);
//            pthread_exit(NULL);
            if (!~nu) {
                throw std::runtime_error("cuckooPath err");
            }
        }
        us[nu++] = u;
    }
    return nu-1;
}

void *worker(void *vp) {
    thread_ctx *tp = (thread_ctx *)vp;
    cuckoo_ctx *ctx = tp->ctx;

    shrinkingset *alive = ctx->alive;
    if (tp->id == 0) {
        // printf("initial size %d\n", NEDGES);
    }
    for (u32 round=0; round < ctx->ntrims; round++) {
        if (tp->id == 0) {
            // printf("round %2d partition sizes", round);
        }

        for (u32 part = 0; part <= PART_MASK; part++) {
            if (tp->id == 0)
                ctx->nonleaf->clear(); // clear all counts
            ctx->barrier();
            ctx->count_node_deg(tp->id,round&1,part);
            ctx->barrier();
            ctx->kill_leaf_edges(tp->id,round&1,part);
            ctx->barrier();
            if (tp->id == 0) {
                // u32 size = alive->count();
                // printf(" %c%d %d", "UV"[round&1], part, size);
            }
        }
        if (tp->id == 0) {
            // printf("\n");
        }
    }
    if (tp->id == 0) {
        u32 load = (u32)(100LL * alive->count() / CUCKOO_SIZE);
        // printf("nonce %d: %d trims completed  final load %d%%\n", ctx->nonce, ctx->ntrims, load);
        if (load >= 90) {
//            printf("overloaded! exiting...");
//            pthread_exit(NULL);
            throw std::runtime_error("overloaded! exiting...");
        }
        ctx->cuckoo = new cuckoo_hash(ctx->nonleaf->bits);
    }
#ifdef SINGLECYCLING
    else pthread_exit(NULL);
#else
    ctx->barrier();
#endif
    cuckoo_hash &cuckoo = *ctx->cuckoo;
    word_t us[MAXPATHLEN], vs[MAXPATHLEN];
#ifdef SINGLECYCLING
    for (word_t block = 0; block < NEDGES; block += 64) {
#else
    for (word_t block = tp->id*64; block < NEDGES; block += ctx->nthreads*64) {
#endif
        u64 alive64 = alive->block(block);
        for (word_t nonce = block-1; alive64; ) { // -1 compensates for 1-based ffs
            u32 ffs = __builtin_ffsll(alive64);
            nonce += ffs; alive64 >>= ffs;
            word_t u0=sipnode_(&ctx->sip_keys, nonce, 0), v0=sipnode_(&ctx->sip_keys, nonce, 1);
            if (u0) {// ignore vertex 0 so it can be used as nil for cuckoo[]
                u32 nu = cuckooPath(cuckoo, u0, us), nv = cuckooPath(cuckoo, v0, vs);
                if (us[nu] == vs[nv]) {
                    u32 min = nu < nv ? nu : nv;
                    for (nu -= min, nv -= min; us[nu] != vs[nv]; nu++, nv++) ;
                    u32 len = nu + nv + 1;
                    // printf("%4d-cycle found at %d:%d%%\n", len, tp->id, (u32)(nonce*100LL/NEDGES));
                    if (len == PROOFSIZE && ctx->nsols < ctx->maxsols)
                        ctx->solution(us, nu, vs, nv);
                } else if (nu < nv) {
                    while (nu--)
                        cuckoo.set(us[nu+1], us[nu]);
                    cuckoo.set(u0, v0);
                } else {
                    while (nv--)
                        cuckoo.set(vs[nv+1], vs[nv]);
                    cuckoo.set(v0, u0);
                }
            }
            if (ffs & 64) break; // can't shift by 64
        }
    }
    // pthread_exit(NULL);
    return 0;
}