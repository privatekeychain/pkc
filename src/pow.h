// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <cuckoo/src/cuckoo/cuckoo.h>

#include <stdint.h>

#include <string>
#include <vector>

class CBlockHeader;
class CBlockIndex;
class uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

bool CheckProofOfWorkNew(const CBlockHeader &blockHeader, const Consensus::Params& params);

bool FindNewCycle(CBlockHeader *blockHeader);

std::vector<unsigned char> GetHeaderBytes(const CBlockHeader& blockHeader, size_t headerSize);

uint256 GetHeaderHashFromBlockUint256(const CBlockHeader& blockHeader);

#endif // BITCOIN_POW_H
