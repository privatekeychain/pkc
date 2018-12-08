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
    const CScript genesisOutputScript = CScript() << ParseHex("040F40197F9F47753B7BFE821AC294207394148F0E166C4086ACA66A83517E60CCB5C2009DA84D9FE1A9B209F357AE69732F4DEAD9D5E4C254A7639C77C61BAA2B") << OP_CHECKSIG;
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
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan =  60 * 60 * 24; // 调整难度时间(1天)
        consensus.nPowTargetSpacing = 60; // 出块时间(1分)
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 19152; // 95% of 20160
        consensus.nMinerConfirmationWindow = 20160;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

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

        const uint32_t nTimeGenesis = 1544235533;
        const uint32_t cuckooNonceGenesis = 171;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {8552, 12136, 22761, 45106, 47418, 49006, 57479, 86352, 95447, 98337, 113135, 117431, 144618, 145839, 156539, 156924, 184360, 186917, 189324, 203853, 206723, 222950, 231140, 235246, 238331, 268915, 306029, 328259, 354134, 368147, 387939, 388351, 408159, 409908, 419655, 421861, 436381, 438574, 471602, 483882, 495151, 496393};
        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x286aa914aab3ad788587cffd7c8a39ec1e2a8bc7b0e078b16e120d6040616215"));
        assert(genesis.hashMerkleRoot == uint256S("0x406d256a92b7202d95783cdfcccbb3df8065cda17648f3a6daeabea7c19917c6"));

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
        consensus.BIP16Exception = uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan =   60 * 60 * 24; // 调整难度时间(1天)
        consensus.nPowTargetSpacing = 60; // 出块时间(1分)
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 19152; // 95% of 20160
        consensus.nMinerConfirmationWindow = 20160;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

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

        const uint32_t nTimeGenesis = 1544235550;
        const uint32_t cuckooNonceGenesis = 78;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {14069, 20233, 26673, 32903, 51434, 76260, 77520, 107002, 109580, 112713, 135373, 144763, 164527, 169552, 184380, 200597, 231062, 245711, 274966, 287032, 302009, 303549, 318519, 326259, 344971, 347507, 348162, 348400, 365453, 374957, 400699, 405316, 434954, 447855, 448416, 466938, 468006, 481517, 496007, 497176, 514044, 524237};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x084ada73e521365a08bc57714fa52b1fd025fc45cb00be1eb29665bb22635a20"));
        assert(genesis.hashMerkleRoot == uint256S("0x406d256a92b7202d95783cdfcccbb3df8065cda17648f3a6daeabea7c19917c6"));

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

        const uint32_t nTimeGenesis = 1544235557;
        const uint32_t cuckooNonceGenesis = 56;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {12279, 24580, 51085, 77180, 84477, 121320, 122282, 125417, 131292, 150894, 163089, 183729, 215161, 253285, 256887, 259986, 274369, 279100, 291173, 297294, 313768, 334913, 356187, 362581, 371579, 375066, 376705, 389416, 398915, 404207, 425539, 442754, 444897, 461661, 474456, 477069, 484359, 492093, 496413, 501242, 512048, 522012};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x7e3c86babaaa34eac5aa433d2b22aad6624cf40cf1827f79cd22b40ce92a98df"));
        assert(genesis.hashMerkleRoot == uint256S("0xa4209335a0d4858976fd7ed5e5d21637839eda083f1930e97223010bae3e2b1d"));

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
