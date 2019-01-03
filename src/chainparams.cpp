// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

#include <pow.h>

#include <vector>




static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime,  uint32_t cuckooBits, int32_t nVersion, const CAmount& genesisReward,
                                 uint32_t cuckooNonce, const std::vector<word_t>& cuckooNonces)
{

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    genesis.cuckooBits = cuckooBits;
    genesis.cuckooNonce = cuckooNonce;
    genesis.cuckooNonces = cuckooNonces;

    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t cuckooBits, int32_t nVersion, const CAmount& genesisReward,
                                 uint32_t cuckooNonce, const std::vector<word_t>& cuckooNonces)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("03f44b1101ebe92c43dfcd28b45c8c937fa8bf6ecbdde90503202e40728f7a1429") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, cuckooBits, nVersion, genesisReward,
                              cuckooNonce, cuckooNonces);
}


static void PrintGenesisBlockProof(const std::string& prefix, uint32_t cuckooBits, int32_t nVersion, const CAmount& genesisRewardUse,
        const Consensus::Params& params) {
    bool finded = false;

    CBlock genesis;

    while(!finded) {
        uint32_t nTimeTmp = static_cast<uint32_t>(time(nullptr));
        uint32_t cuckooNonceTmp = 0;
        std::vector<word_t> cuckooNoncesTmp;

        genesis = CreateGenesisBlock(nTimeTmp, cuckooBits, nVersion, genesisRewardUse,
                                     cuckooNonceTmp, cuckooNoncesTmp);

        const int nInnerLoopCount = 0x10000;

        for ( ; genesis.cuckooNonce < nInnerLoopCount; )
        {
            if (FindNewCycle(&genesis) && CheckProofOfWorkNew(genesis, params))
            {
                break;
            }
            else
            {
                ++genesis.cuckooNonce;
                genesis.cuckooNonces.clear();
            }
        }

        if (genesis.cuckooNonce == nInnerLoopCount)
        {
            continue;
        }

        finded = true;
    }

    printf("%s\n", prefix.c_str());

    // nTime
    printf("const uint32_t nTimeGenesis = ");
    printf("%d;\n", genesis.nTime);

    // cuckooNonce
    printf("const uint32_t cuckooNonceGenesis = ");
    printf("%d;\n", genesis.cuckooNonce);

    // cuckooNonces
    printf("const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {");
    for (size_t i = 0; i < genesis.cuckooNonces.size(); ++i)
    {
        printf("%d", genesis.cuckooNonces[i]);
        if (i != genesis.cuckooNonces.size() - 1) {
            printf(", ");
        }
    }
    printf("};");
    printf("\n");

    // hashGenesisBlock
    printf("// consensus.hashGenesisBlock == ");
    printf("0x%s\n", genesis.GetHash().GetHex().c_str());

    // hashMerkleRoot
    printf("// genesis.hashMerkleRoot == ");
    printf("0x%s\n", BlockMerkleRoot(genesis).GetHex().c_str());
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525600;  // 减半周期(1年)
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan =  60 * 60 * 24; // 调整难度时间(1天)
        consensus.nPowTargetSpacing = 60; // 出块时间(1分)
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 19152; // 95% of 20160
        consensus.nMinerConfirmationWindow = 20160;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout =  Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =  Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout =  Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        // PKCTODO 最长链最小工作量累计
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8"); //534292

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 9333;
        nPruneAfterHeight = 100000;


        const uint32_t cuckooBits = 0x207fffff;
        const int32_t nVersion = 1;
        const CAmount genesisReward = 500000000 * COIN + 500 * COIN;


//        PrintGenesisBlockProof("1", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1546510626;
        const uint32_t cuckooNonceGenesis = 95;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {9308, 13410, 19936, 25233, 36405, 40766, 41653, 58015, 67731, 67954, 84952, 90469, 94157, 115893, 121134, 144877, 174768, 177389, 203481, 227682, 235996, 237453, 255357, 289909, 298683, 350815, 364575, 387678, 401276, 412566, 414856, 418343, 425533, 458872, 461022, 461379, 468875, 487650, 494539, 499829, 500939, 507169};
        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1411465213975a714e3f1016521d9ee1c8b009c88c2389944a835dff4528a9aa"));
        assert(genesis.hashMerkleRoot == uint256S("0x287e1eefaf08b141a070883511d3a3bf69e827b78f54674ab7a74d2898b0df62"));

        vSeeds.emplace_back("seed.pkc.ink");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8
            /* nTime    */ 1532884444,
            /* nTxCount */ 331282217,
            /* dTxRate  */ 2.4
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 525600; // 减半周期(1年)
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan =   60 * 60 * 24; // 调整难度时间(1天)
        consensus.nPowTargetSpacing = 60; // 出块时间(1分)
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 19152; // 95% of 20160
        consensus.nMinerConfirmationWindow = 20160;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout =  Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =  Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout =  Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        // PKCTODO 最长链最小工作量累计
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75"); //1354312

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 19333;
        nPruneAfterHeight = 1000;

        const uint32_t cuckooBits = 0x207fffff;
        const int32_t nVersion = 1;
        const CAmount genesisReward = 500000000 * COIN + 500 * COIN;

//       PrintGenesisBlockProof("2", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1546510634;
        const uint32_t cuckooNonceGenesis = 24;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {3406, 9830, 16650, 64174, 66628, 75869, 81993, 87682, 94993, 99979, 101598, 108217, 110114, 124574, 125519, 126521, 150267, 159433, 159733, 178792, 209180, 223384, 227773, 232350, 267742, 273092, 273806, 274076, 281137, 299300, 300851, 308925, 314035, 333190, 335836, 361252, 414015, 419014, 492573, 512376, 521182, 523941};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x7b126aa76a93648bccddad13b9e4f5dcaa58744d366179697b3d97010d1781e4"));
        assert(genesis.hashMerkleRoot == uint256S("0x287e1eefaf08b141a070883511d3a3bf69e827b78f54674ab7a74d2898b0df62"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("seed.pkc.ink");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 1531929919,
            /* nTxCount */ 19438708,
            /* dTxRate  */ 0.626
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 19444;
        nPruneAfterHeight = 1000;


        const uint32_t cuckooBits = 0x207fffff;
        const int32_t nVersion = 1;
        const CAmount genesisReward = 50 * COIN;

//        PrintGenesisBlockProof("3", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1546510637;
        const uint32_t cuckooNonceGenesis = 168;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {25240, 32864, 36169, 51452, 51944, 82873, 84548, 88685, 92754, 93550, 96909, 99727, 118188, 143795, 228952, 229438, 233742, 243235, 257101, 275277, 284322, 313723, 313986, 327737, 329757, 362382, 365348, 367570, 375398, 405642, 406022, 439039, 441869, 443010, 446587, 458764, 459625, 464192, 482473, 488806, 497199, 508362};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x445d08a6dbc4bb668b3dfb23241f67686cc6a18cd33e57df259aa909a2125507"));
        assert(genesis.hashMerkleRoot == uint256S("0x892aabb9cd8faaefb95746a6a2af5c76c8178d653c7838c2f8fa3ad3cdd0a083"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
