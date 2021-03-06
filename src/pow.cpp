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
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->cuckooBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->cuckooBits;
            }
        }
        return pindexLast->cuckooBits;
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
        return pindexLast->cuckooBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->cuckooBits);

    arith_uint512 bnNew512;
    bnNew512.SetHex(bnNew.GetHex().c_str());

    arith_uint512 bnPowLimit512;
    bnPowLimit512.SetHex(bnPowLimit.GetHex().c_str());

    bnNew512 *= nActualTimespan;
    bnNew512 /= params.nPowTargetTimespan;

    if (bnNew512 > bnPowLimit512)
        return bnPowLimit.GetCompact();

    bnNew.SetHex(bnNew512.GetHex());

    // will not be executed
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}


bool CheckProofOfWorkCuckooCycleImpl(const std::vector<unsigned char> headerBytes, const std::vector<word_t> &cuckooNonces)
{
    siphash_keys keys;
    cuckooSetheader((const char*)headerBytes.data(), headerBytes.size(), &keys);
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

bool CheckProofOfWorkHashImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

std::vector<unsigned char> GetHeaderBytes(const CBlockHeader& blockHeader, size_t headerSize)
{
    std::vector<unsigned char> serializedHeader;
    CVectorWriter(SER_GETHASH, PROTOCOL_VERSION, serializedHeader, 0, blockHeader);
    serializedHeader.resize(headerSize);
    return serializedHeader;
}

uint256 GetHeaderHashFromBlockUint256(const CBlockHeader& blockHeader)
{
    size_t headerSize = 80;
    auto serializedHeader = GetHeaderBytes(blockHeader, headerSize);
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss.write((const char*)serializedHeader.data(), headerSize);
    return ss.GetHash();
}

bool CheckProofOfWorkNew(const CBlockHeader &blockHeader, const Consensus::Params& params)
{
    auto headerBytes = GetHeaderBytes(blockHeader, 80);
    bool cuckooFinded = CheckProofOfWorkCuckooCycleImpl(headerBytes, blockHeader.cuckooNonces);
    if (cuckooFinded) {
        auto hash = GetHeaderHashFromBlockUint256(blockHeader);
        return CheckProofOfWorkHashImpl(hash, blockHeader.cuckooBits, params);
    } else {
        return false;
    }
}

bool FindNewCycle(CBlockHeader *blockHeader)
{
    const int ntrims = 2 + (PART_BITS + 3) * (PART_BITS + 4);
    const int maxsols = 1;

    auto headerBytes = GetHeaderBytes(*blockHeader, 80);

    cuckoo_ctx ctx(1, ntrims, maxsols);
    ctx.setheadernonce((char*)headerBytes.data(), headerBytes.size(), blockHeader->cuckooNonce);
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
        return true;
    }

    return false;
}
