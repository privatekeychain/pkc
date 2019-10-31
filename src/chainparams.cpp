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
        const CAmount genesisReward = 500 * COIN;

//        PrintGenesisBlockProof("1", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1557884787;
        const uint32_t cuckooNonceGenesis = 85;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {20454, 22346, 48325, 76212, 91697, 104315, 111588, 111769, 113670, 127490, 134074, 139815, 142432, 144850, 145148, 196783, 246498, 249266, 274367, 290663, 308142, 334076, 335638, 341162, 354693, 358890, 370651, 379060, 391663, 399958, 406800, 411986, 421390, 429563, 429952, 456444, 456456, 480295, 482844, 494508, 517336, 522807};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x884f6e34c0be9c236842cb54006a18b28d3490dfcc6ee18a0717c06fa5fd7919"));
        assert(genesis.hashMerkleRoot == uint256S("0x9fe0b536754a727c4851a12b3f2d7132c60daea5cd5c13997b71b5f904e431b5"));

        vSeeds.emplace_back("seed.pkc.ink");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 55); // P
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);  // 3  // MAINTAIN 3
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128); // 5, K, L
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

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
        const CAmount genesisReward = 500 * COIN;

//        PrintGenesisBlockProof("2", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1557884803;
        const uint32_t cuckooNonceGenesis = 599;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {1403, 9057, 9528, 9584, 15699, 30265, 49053, 68679, 71338, 78164, 79023, 84556, 92248, 92295, 116575, 121399, 155069, 163952, 196404, 202460, 202874, 211745, 212841, 215246, 233813, 240314, 253989, 310037, 320607, 325189, 329630, 350469, 354850, 370220, 417241, 424197, 442562, 466617, 505801, 508878, 511483, 522448};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1a60793d5104be6f4e80435971623d97aa395633211a849d1ee2e1fb5c793e00"));
        assert(genesis.hashMerkleRoot == uint256S("0x9fe0b536754a727c4851a12b3f2d7132c60daea5cd5c13997b71b5f904e431b5"));

        vFixedSeeds.clear();
        vSeeds.clear();

//        vSeeds.emplace_back("seed.pkc.ink");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // m or n
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // 2
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239); // 9 c
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94}; // tprv

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
        const CAmount genesisReward = 500 * COIN;

//        PrintGenesisBlockProof("3", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1557884919;
        const uint32_t cuckooNonceGenesis = 24;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {49918, 56208, 62293, 92073, 96873, 116870, 144207, 150915, 157168, 161654, 168453, 186635, 192162, 208873, 213722, 220621, 222153, 244655, 249288, 251538, 266226, 268380, 268556, 272511, 359430, 359603, 360099, 381567, 385546, 388328, 393817, 396564, 404770, 411209, 448865, 449640, 466037, 473046, 480091, 493604, 499552, 519064};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x7ff70df37d88530548cb4c721f6b577c51012f3807f09afd0ed848e0d93f2cdc"));
        assert(genesis.hashMerkleRoot == uint256S("0x9fe0b536754a727c4851a12b3f2d7132c60daea5cd5c13997b71b5f904e431b5"));

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

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // m or n
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // 2
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239); // 9 c
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94}; // tprv

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
