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

        const uint32_t nTimeGenesis = 1550049163;
        const uint32_t cuckooNonceGenesis = 29;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {3154, 4417, 8595, 14075, 28411, 47067, 64777, 78822, 82289, 87662, 91933, 94487, 111721, 126103, 127222, 130566, 134010, 135428, 159152, 164146, 191110, 193847, 195837, 226205, 242993, 251202, 254405, 271363, 282005, 329389, 338900, 348545, 386684, 390397, 404470, 412034, 421995, 428645, 434367, 440977, 454774, 465766};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x49e9204ebe3c41ac0f2d5936b5d6ca39b17c72ea3bdd26d66d5131b19063e811"));
        assert(genesis.hashMerkleRoot == uint256S("0x9fe0b536754a727c4851a12b3f2d7132c60daea5cd5c13997b71b5f904e431b5"));

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
        const CAmount genesisReward = 500 * COIN;

//       PrintGenesisBlockProof("2", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1550049165;
        const uint32_t cuckooNonceGenesis = 114;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {22369, 27328, 27777, 60456, 87523, 88956, 119440, 121089, 147827, 155406, 161258, 167642, 186390, 188102, 191386, 200445, 204480, 218256, 230100, 258650, 286622, 309226, 309793, 330501, 332999, 343959, 349721, 357201, 383655, 397288, 401613, 411954, 412643, 426833, 444859, 452838, 461180, 464621, 491975, 498913, 503899, 505474};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x5a2e444f2838490791c4594c4b08c6d02b149bb9b8cc619546edb21863a825c6"));
        assert(genesis.hashMerkleRoot == uint256S("0x9fe0b536754a727c4851a12b3f2d7132c60daea5cd5c13997b71b5f904e431b5"));

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
        const CAmount genesisReward = 500 * COIN;

//        PrintGenesisBlockProof("3", cuckooBits, nVersion, genesisReward, consensus);

        const uint32_t nTimeGenesis = 1550049170;
        const uint32_t cuckooNonceGenesis = 13;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {31916, 32346, 47800, 59131, 80360, 81797, 114392, 141815, 155547, 160742, 178759, 186438, 192307, 197250, 222851, 225748, 236071, 255992, 300870, 311221, 314295, 323476, 338133, 338867, 340872, 341562, 344353, 348477, 366861, 376903, 416404, 420993, 453609, 456032, 469836, 481399, 487667, 500982, 502183, 510541, 521399, 521701};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x376a3698d64cab96e708b4114a542ce8541bbf53b1f3b308ebfacc26a2f6de96"));
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
