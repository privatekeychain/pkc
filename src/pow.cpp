// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <streams.h>
#include <hash.h>
#include <version.h>

#include <cuckoo/src/cuckoo/lean.hpp>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

//bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
//{
//    bool fNegative;
//    bool fOverflow;
//    arith_uint256 bnTarget;
//
//    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
//
//    // Check range
//    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
//        return false;
//
//    // Check proof of work matches claimed amount
//    if (UintToArith256(hash) > bnTarget)
//        return false;
//
//    return true;
//}

std::string GetHeaderHashFromBlock(const CBlockHeader &blockHeader)
{
    std::vector<unsigned char> serializedHeader;
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, serializedHeader, 0, blockHeader);
    serializedHeader.resize(84);

    unsigned char hash[32];
    CSHA256().Write(serializedHeader.data(), 84).Finalize(hash);
    return std::string((const char*)hash, 32);
}

std::string PlaceNonceAtEndOfHeaderHash(const std::string& headerHash, uint32_t cuckooNonce)
{
    size_t palceIdx = headerHash.length() / sizeof(uint32_t) - 1;

    if ((palceIdx + sizeof(uint32_t)) > headerHash.length()) {
        throw std::runtime_error("headerHash palceIdx err");
    }

    std::string tmp(headerHash);
    ((uint32_t*)tmp.data())[palceIdx] = cuckooNonce;
    return tmp;
}

bool CheckProofOfWorkCuckooCycleImpl(const std::string &headerHashWithCuckooNonce,
                                     const std::vector<word_t> &cuckooNonces)
{
    siphash_keys keys;
    cuckooSetheader(headerHashWithCuckooNonce.c_str(), headerHashWithCuckooNonce.size(), &keys);
    if (cuckooNonces.size() != PROOFSIZE) {
        return false;
    }
    word_t cuckooNoncesTmp[PROOFSIZE];
    for (size_t i = 0; i < cuckooNonces.size(); ++i) {
        cuckooNoncesTmp[i] = cuckooNonces[i];
    }
    int pow_rc = cuckooVerify(cuckooNoncesTmp, &keys);
    return pow_rc == POW_OK;
}

bool CheckProofOfWorkNew(const CBlockHeader &blockHeader)
{
    std::string headerHash = GetHeaderHashFromBlock(blockHeader);
    std::string headerHashWithCuckooNonce = PlaceNonceAtEndOfHeaderHash(headerHash, blockHeader.cuckooNonce);
    return CheckProofOfWorkCuckooCycleImpl(headerHashWithCuckooNonce, blockHeader.cuckooNonces);
}

void FindNewCycle(CBlockHeader *blockHeader)
{
    const int ntrims = 2 + (PART_BITS + 3) * (PART_BITS + 4);
    const int maxsols = 1;

    std::string header = GetHeaderHashFromBlock(*blockHeader);

    cuckoo_ctx ctx(1, ntrims, maxsols);
    ctx.setheadernonce((char*)header.c_str(), header.size(), blockHeader->cuckooNonce);
    ctx.barry.clear();

    thread_ctx thread;
    thread.id = 0;
    thread.ctx = &ctx;

    (*worker)((void *) &thread);

    if (ctx.nsols == 1) {
        for (int i = 0; i < PROOFSIZE; ++i)
        {
            blockHeader->cuckooNonces.push_back(ctx.sols[0][i]);
        }
    }
}
