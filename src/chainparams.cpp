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

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t cuckooBits, int32_t nVersion, const CAmount& genesisReward,
                                 uint32_t cuckooNonce, const std::vector<word_t>& cuckooNonces)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, cuckooBits, nVersion, genesisReward,
                              cuckooNonce, cuckooNonces);
}

// 生成 1. nTime 2. cuckooNonce 3. cuckooNonces 4. hash
static void PrintGenesisBlockProof(uint32_t cuckooBits, int32_t nVersion, const CAmount& genesisRewardUse,
        uint32_t *nTimeOut, uint32_t *cuckooNonceOut, std::vector<word_t> *cuckooNoncesOut, std::string* hashOut,
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


    *nTimeOut = genesis.nTime;
    *cuckooNonceOut = genesis.cuckooNonce;
    *cuckooNoncesOut = genesis.cuckooNonces;
    *hashOut = std::string("0x") + genesis.GetHash().GetHex();
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
        consensus.powLimit = uint256S("0x1999999999999999999999999999999999999999999999999999999999999999");
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
//        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000028822fef1c230963535a90d");
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


        const uint32_t cuckooBits = 0x20199999;
        const int32_t nVersion = 1;
        const CAmount genesisReward = 1000 * COIN;

//        uint32_t nTimeGenesis = 0;
//        uint32_t cuckooNonceGenesis = 0;
//        std::vector<word_t> cuckooNoncesGenesis;
//        std::string hash;
//
//        PrintGenesisBlockProof(cuckooBits, nVersion, genesisReward, &nTimeGenesis, &cuckooNonceGenesis, &cuckooNoncesGenesis, &hash, consensus);

        const uint32_t nTimeGenesis = 1543926027;
        const uint32_t cuckooNonceGenesis = 7;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {2092, 20931, 30283, 45644, 62716, 72372, 73373, 78562, 115447, 120389, 125178, 129110, 141129, 153989, 158246, 162948, 183196, 197909, 215468, 219721, 228540, 247556, 292078, 293278, 299150, 308711, 311272, 312204, 319567, 322069, 337452, 371989, 376226, 377754, 406160, 410948, 416332, 440457, 447441, 453351, 476227, 481055};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        // hashMerkleRoot
//        printf("// genesis.hashMerkleRoot == ");
//        printf("0x%s\n", BlockMerkleRoot(genesis).GetHex().c_str());

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0b62cf2f917b2871c2e114640ad124557d875d5ff0d92679ec470e6d36a6c18f"));
        assert(genesis.hashMerkleRoot == uint256S("0x973218231afdfeb6d2911a8acb1216b3b425c414ddcf81dfb8042f7e52741a42"));


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
        consensus.powLimit = uint256S("0x1999999999999999999999999999999999999999999999999999999999999999");
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
        //consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000007dbe94253893cbd463");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75"); //1354312

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 19333;
        nPruneAfterHeight = 1000;

        const uint32_t cuckooBits = 0x20199999;
        const int32_t nVersion = 1;
        const CAmount genesisReward = 1000 * COIN;

//        uint32_t nTimeGenesis = 0;
//        uint32_t cuckooNonceGenesis = 0;
//        std::vector<word_t> cuckooNoncesGenesis;
//        std::string hash;
//
//        PrintGenesisBlockProof(cuckooBits, nVersion, genesisReward, &nTimeGenesis, &cuckooNonceGenesis, &cuckooNoncesGenesis, &hash, consensus);

        const uint32_t nTimeGenesis = 1543926029;
        const uint32_t cuckooNonceGenesis = 530;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {39343, 52809, 70088, 73914, 92843, 95949, 100620, 102527, 102882, 103828, 125432, 162797, 168370, 185000, 186013, 188657, 191336, 201976, 208643, 226465, 233390, 249844, 253189, 256676, 266113, 272401, 275255, 291808, 304435, 315584, 331716, 331920, 340191, 365454, 372499, 373888, 401576, 428140, 439330, 443849, 444668, 502016};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        // hashMerkleRoot
//        printf("// genesis.hashMerkleRoot == ");
//        printf("0x%s\n", BlockMerkleRoot(genesis).GetHex().c_str());

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1774c643d695ffab32dcdbf358b6c3e4f2cae8387e6b19359f0be5045af931db"));
        assert(genesis.hashMerkleRoot == uint256S("0x973218231afdfeb6d2911a8acb1216b3b425c414ddcf81dfb8042f7e52741a42"));

        vFixedSeeds.clear();
        vSeeds.clear();


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

//        uint32_t nTimeGenesis = 0;
//        uint32_t cuckooNonceGenesis = 0;
//        std::vector<word_t> cuckooNoncesGenesis;
//        std::string hash;

//        PrintGenesisBlockProof(cuckooBits, nVersion, genesisReward, &nTimeGenesis, &cuckooNonceGenesis, &cuckooNoncesGenesis, &hash, consensus);

        const uint32_t nTimeGenesis = 1543926127;
        const uint32_t cuckooNonceGenesis = 375;
        const std::vector<word_t> cuckooNoncesGenesis = std::vector<word_t> {9205, 17477, 24978, 35146, 45752, 48322, 55422, 58016, 91272, 92850, 94768, 96235, 107284, 129101, 142085, 146088, 150041, 161008, 196245, 202090, 220237, 226137, 238043, 240234, 291619, 300552, 323656, 370350, 372397, 374345, 387312, 390109, 404483, 409123, 429558, 433216, 445532, 453086, 480087, 505620, 508480, 509271};

        genesis = CreateGenesisBlock(nTimeGenesis, cuckooBits, nVersion, genesisReward, cuckooNonceGenesis, cuckooNoncesGenesis);

        // hashMerkleRoot
//        printf("// genesis.hashMerkleRoot == ");
//        printf("0x%s\n", BlockMerkleRoot(genesis).GetHex().c_str());

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0bc7f29c628a1a7847a3fadaba70c5a91129bf1636ea41b688bc5a8f114b9b1b"));
        assert(genesis.hashMerkleRoot == uint256S("0x973218231afdfeb6d2911a8acb1216b3b425c414ddcf81dfb8042f7e52741a42"));

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
