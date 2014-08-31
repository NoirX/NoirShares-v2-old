// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "kernel.h"
#include "zerocoin/Zerocoin.h"
#include "scrypt_mine.h"
#include "checkqueue.h"
#include "emessage.h"
#include "lottoshares.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include "momentum.h"
#include <map>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <stdio.h>
/*
#ifdef WIN32
    #include <windows.h>
#endif
*/
using namespace std;
using namespace boost;

//
// Global state
//

static const int64 TWOYEARS = 2 * 365 * 24 * 90;
static const int64 ONEYEAR =  365 * 24 * 90;
static const int64 FIFTYDAYS =  (18 * 24 * 24) + (32 * 24 * 90);
static const int64 MAXBALANCEGENESIS =  100 * COIN;



CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;
libzerocoin::Params* ZCParams;

uint256 hashGenesisBlock = hashGenesisBlockOfficial;
uint256 smallestInvalidHash = uint256("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000");
uint256 merkleRootGenesisBlock("0x4ed35a3349ab2f6adc0b710d6df899a0f7cdfaec49ef7515da9ea8a63eaf2218");
uint256 rseedGenesisBlock("0x2dcd1c9a6f9c79342224611cebc701eacc8a670086a4acd7cb7d3fea528d9693");
const int64 nChainStartTime = 1408563876; 
const unsigned long nChainStartNonce = 11;
const unsigned long nChainStartBirthdayA = 6715920;
const unsigned long nChainStartBirthdayB = 16567824;

static CBigNum bnProofOfWorkLimit(~uint256(0) >> 4);
static CBigNum bnProofOfStakeLimit(~uint256(0) >> 4);

static CBigNum bnProofOfWorkLimitTestNet(~uint256(0) >> 2);
static CBigNum bnProofOfStakeLimitTestNet(~uint256(0) >> 2);

unsigned int nStakeMinAge = 60 * 60 * 24 * 7;   // minimum age for coin age: 8h
unsigned int nStakeMaxAge = -1; // stake age of full weight: unlimited
unsigned int nStakeTargetSpacing = 60 * 2;          // 4 min block spacing
int nTargetSpacing = 60 *4;

int nCoinbaseMaturity = 150;
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
CBigNum bnBestChainTrust = 0;
CBigNum bnBestInvalidTrust = 0;
uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
int64 nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
bool fBenchmark = false;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;
map<uint256, uint256> mapProofOfStake;

map<uint256, CDataStream*> mapOrphanTransactions;
map<uint256, map<uint256, CDataStream*> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "NoirShares Signed Message:\n";

double dhashespermin;
int64 nHPSTimerStart;

// Settings
CCriticalSection grantdb;
int64 nTransactionFee = MIN_TX_FEE;
int64 nMinimumInputValue = MIN_TX_FEE;
std::map<int, std::string > awardWinners;
std::map<std::string,int64 > grantAwards;
std::map<std::string,int64>::iterator gait;

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets


void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

void UnregisterAllWallets()
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.clear();
    }
}

// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            if (pwallet->IsFromMe(tx))
                return true;
    }
    return false;
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            if (pwallet->GetTransaction(hashTx,wtx))
                return true;
        return false;
    }
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->EraseFromWallet(hash);
    }
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }

        {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
    }
}

// Add wallet transactions that aren't already in a block to mapTransactions
void ReacceptWalletTransactions()
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ReacceptWalletTransactions();
    }
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
   {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->SetBestChain(loc);
    }
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->UpdatedTransaction(hashTx);
    }
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->PrintWallet(block);
    }
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->Inventory(hash);
    }
}

// ask wallets to resend their transactions
void ResendWalletTransactions()
{
    {
        LOCK(cs_setpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
            pwallet->ResendWalletTransactions();
    }
}



//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    CDataStream* pvMsg = new CDataStream(vMsg);

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    if (pvMsg->size() > 5000)
    {
        printf("ignoring large orphan tx (size: %"PRIszu", hash: %s)\n", pvMsg->size(), hash.ToString().substr(0,10).c_str());
        delete pvMsg;
        return false;
    }

    mapOrphanTransactions[hash] = pvMsg;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(make_pair(hash, pvMsg));

    printf("stored orphan tx %s (mapsz %"PRIszu")\n", hash.ToString().substr(0,10).c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CDataStream*>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}



//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::IsStandard() const
{
    if (nVersion > CTransaction::CURRENT_VERSION)
        return false;

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
        // pay-to-script-hash, which is 3 ~80-byte signatures, 3
        // ~65-byte public keys, plus a few script ops.
        if (txin.scriptSig.size() > 500)
            return false;
        if (!txin.scriptSig.IsPushOnly())
            return false;
        if (!txin.scriptSig.HasCanonicalPushes()) {
            return false;
        }
    }
    BOOST_FOREACH(const CTxOut& txout, vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            return false;
        }
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else {
            if (txout.nValue == 0) {
                return false;
            }
            if (!txout.scriptPubKey.HasCanonicalPushes()) {
                return false;
            }
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        return false;
    }

    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(const MapPrevTx& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int
CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}




bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        const CTxOut& txout = vout[i];

        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
            return DoS(100, error("CTransaction::CheckTransaction() : txout empty for user transaction"));

       /*
        if ((!txout.IsEmpty()) && txout.nValue < MIN_TXOUT_AMOUNT)
           return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue below minimum"));
       */

        if (txout.nValue < 0)
           return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue negative"));

        if (txout.nValue > MAX_MONEY)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return DoS(100, error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    return true;
}


int64 CTransaction::GetMinFee(unsigned int nBlockSize, bool fAllowFree,
                              enum GetMinFee_mode mode, unsigned int nBytes) const
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
    int64 nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

    //unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes == 0) nBytes = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

    // To limit dust spam, require MIN_TX_FEE/MIN_RELAY_TX_FEE if any output is less than 0.01
    if (nMinFee < nBaseFee)
    {
        BOOST_FOREACH(const CTxOut& txout, vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;
    }

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;

    return nMinFee;
}


bool CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs,
                        bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction())
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !tx.IsStandard())
        return error("CTxMemPool::accept() : nonstandard transaction type");

    // Do we already have it?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
                return error("CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !fTestNet)
            return error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        int64 nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        //Check if tx contains checkpoint
        int64 theHeight, theTime; uint256 theHash;
        checkTransactionForCheckpoints(tx,GetBoolArg("-broadcastdraws"),GetBoolArg("-logblock"),theHeight,theTime,theHash);

        //update wallet trx -
        std::map<string, int64> pr;int64 ffp=0;int64 nffp=0;ofstream mynull;
        checkTransactionForPayoutsFromCheckpointTransaction(tx,pr,ffp,nffp,false,mynull);

        // Don't accept it if it can't get into a block
        int64 txMinFee = tx.GetMinFee(1000, false, GMF_RELAY, nSize);
        if (nFees < txMinFee)
            return error("CTxMemPool::accept() : not enough fees %s, %"PRI64d" < %"PRI64d,
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection cs;
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            {
                LOCK(cs);
                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;
                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !IsFromMe(tx))
                    return error("CTxMemPool::accept() : free transaction rejected by rate limiter");
                if (fDebug)
                    printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                dFreeCount += nSize;
            }
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false))
        {
            return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
        }
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    printf("CTxMemPool::accept() : accepted %s (poolsz %"PRIszu")\n",
           hash.ToString().substr(0,10).c_str(),
           mapTx.size());
     
    SyncWithWallets(tx, NULL, true);
     
    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    return mempool.accept(txdb, *this, fCheckInputs, pfMissingInputs);
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(CTransaction &tx)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}




int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetHeightInMainChain() const
{
    if (hashBlock == 0 || nIndex == -1)
        return -1;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return -1;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return -1;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return -1;
        fMerkleVerified = true;
    }

    return pindex->nHeight;
}

int getVestedSharesMaturityHeight(uint256 txhash){
    //printf("hash of vested transaction:%s\n",txhash.GetHex().c_str());
    uint64 theHash=txhash.Get64();
    theHash=theHash+hashGenesisBlock.Get64();
    return FIFTYDAYS + (theHash % ONEYEAR);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    //If in the genesis block, special rule for vested shares
    if(GetHeightInMainChain()==0){
        //Shares Claim Period Expired
        if(pindexBest->nHeight>TWOYEARS){
            return INT_MAX;
        }
        if(GetValueOut()>MAXBALANCEGENESIS){
            int maturationBlock = getVestedSharesMaturityHeight(this->GetHash());
            printf("maturation block:%d\n",maturationBlock);
            return maturationBlock-pindexBest->nHeight;
        }
    }
    return max(0, (nCoinbaseMaturity+1) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(txdb, false);
    }
    else
    {
        return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
    }
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{

    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
        return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                tx = mempool.lookup(hash);
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}








//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

int64 GetAverageProofOfWorkReward(int nHeight, int64 nFees)
{
	int64 nSubsidy = 10 * COIN;
	
	// Subsidy is reduced by 5% every 3000 blocks, 
    int exponent=(nHeight / 3000);
    for(int i=0;i<exponent;i++){
        nSubsidy=nSubsidy*19;
	nSubsidy=nSubsidy/20;
    }
       
    return nSubsidy +( nFees * 0);
}

int generateMTRandom(unsigned int s, int range)
{
    random::mt19937 gen(s);
    random::uniform_int_distribution<> dist(0, range);
    return dist(gen);
 }
int64 GetProofOfWorkReward(int nHeight, int64 nFees, uint256 randomSeed)
{
	// Assume zero fees and fact that randomSeed will not be used
	int64 averageSubsidy = GetAverageProofOfWorkReward(nHeight, 0);

	// Randomize
	int64 nSubsidy = averageSubsidy;

	uint64 randomNum = ((uint64*) randomSeed.begin())[0] % 100000ULL;
	if (randomNum < 9)
		nSubsidy *= 1000ULL;
	else if (randomNum < 99)
		nSubsidy *= 100ULL;
	else if (randomNum < 999)
		nSubsidy *= 10ULL;
	else if (randomNum < 9999)
		nSubsidy *= 1ULL;
	else
		nSubsidy /= 10ULL;

	// Add fees
	return ((nSubsidy) *(1/0.4500045)) + nFees;
}

int64 static GetBlockValue(int nHeight, int64 nFees)
{
    return GetProofOfWorkReward(nHeight, 0,0) + nFees ;
}

int64 static GetGrantValue(int64 nHeight)
{
	int64 grantaward=GetProofOfWorkReward(nHeight, 0, 0);
	return grantaward/5;
}


// miner's coin stake reward based on nBits and coin age spent (coin-days)
// simple algorithm, not depend on the diff
//const int YEARLY_BLOCKCOUNT = 2102400;	// 365 * 5760
int64 GetProofOfStakeReward(int64 nCoinAge, unsigned int nBits, unsigned int nTime, int nHeight)
{
    int64 nRewardCoinYear;
    nRewardCoinYear = MAX_MINT_PROOF_OF_STAKE;

    int64 nSubsidy = nRewardCoinYear * nCoinAge * 33 / (365 * 33 + 8);
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%"PRI64d" nBits=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge, nBits);
    return nSubsidy;
}

static const int64 nTargetTimespan = 5 * 60;  
static const int64 nTargetSpacingWorkMax = 1 * nStakeTargetSpacing; 

//
// maximum nBits value could possible be required nTime after
//
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64 nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 200% adjustment per day...
        bnResult *= 2;
        nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

//
// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime)
{
    return ComputeMaxBits(bnProofOfWorkLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, int64 nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(bnProofOfStakeLimit, nBase, nTime);
}


// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake) 
{
    CBigNum bnTargetLimit = bnProofOfWorkLimit;

    if(fProofOfStake)
    {
        // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
        bnTargetLimit = bnProofOfStakeLimit;
    }

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64 nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if(nActualSpacing < 0)
    {
        nActualSpacing = 1;
    }
    else if(nActualSpacing > nTargetTimespan)
    {
        nActualSpacing = nTargetTimespan;
    }

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    int64 nTargetSpacing = fProofOfStake? nStakeTargetSpacing : min(nTargetSpacingWorkMax, (int64) nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
    int64 nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;
    static int64 nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return (GetTime() - nLastUpdate < 10 &&
            pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->bnChainTrust > bnBestInvalidTrust)
    {
        bnBestInvalidTrust = pindexNew->bnChainTrust;
        CTxDB().WriteBestInvalidTrust(bnBestInvalidTrust);
        uiInterface.NotifyBlocksChanged();
    }

    printf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      pindexNew->bnChainTrust.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S",
      pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  trust=%s  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, bnBestChainTrust.ToString().c_str(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
}


void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}

 uint256 CBlock::GetHash() const
     {
 
 		// uint256 midHash = GetMidHash();
 		    
 		//printf("GetHash - MidHash %s\n", midHash.ToString().c_str());
 		//printf("GetHash - Birthday A %u hash \n", nBirthdayA);
 		//printf("GetHash - Birthday B %u hash \n", nBirthdayB);
		
		
		    uint256 r = Hash(BEGIN(nVersion), END(nBirthdayB));
 //    fprintf( stderr, "init hash %s\n", r.ToString().c_str() );
 
     return r; //Hash(BEGIN(nVersion), END(nBirthdayB));
 }

 uint256 CBlock::CalculateBestBirthdayHash() {
 				
		uint256 midHash = GetMidHash();		
 		std::vector< std::pair<uint32_t,uint32_t> > results =bts::momentum_search( midHash );
 		uint32_t candidateBirthdayA=0;
 		uint32_t candidateBirthdayB=0;
		uint256 smallestHashSoFar("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdddd");
		for (unsigned i=0; i < results.size(); i++) {
			nBirthdayA = results[i].first;
			nBirthdayB = results[i].second;
			uint256 fullHash = Hash(BEGIN(nVersion), END(nBirthdayB));
			if(fullHash<smallestHashSoFar){
				//if better, update candidate birthdays
				//printf("best hash so far for the nonce\n");
				smallestHashSoFar=fullHash;
				candidateBirthdayA=results[i].first;
				candidateBirthdayB=results[i].second;
			}
			nBirthdayA = candidateBirthdayA;
 			nBirthdayB = candidateBirthdayB;
 		}
 		
 		return GetHash();
 	}

bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}


bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                               bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;

    if (IsCoinBase())
        return true; // Coinbase transactions have no inputs to fetch.

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.hash))
            continue; // Got it already

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.hash].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.hash)->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }
        if (!fFound && (fBlock || fMiner))
            return fMiner ? false : error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            {
                LOCK(mempool.cs);
                if (!mempool.exists(prevout.hash))
                    return error("FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
                txPrev = mempool.lookup(prevout.hash);
            }
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            // Get prev tx from disk
            if (!txPrev.ReadFromDisk(txindex.pos))
                return error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const COutPoint prevout = vin[i].prevout;
        assert(inputsRet.count(prevout.hash) != 0);
        const CTxIndex& txindex = inputsRet[prevout.hash].first;
        const CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            return DoS(100, error("FetchInputs() : %s prevout.n out of range %d %"PRIszu" %"PRIszu" prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
        }
    }

    return true;
}

const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.n >= txPrev.vout.size())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.n];
}

int64 CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64 nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }
    return nResult;

}

unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

bool CScriptCheck::operator()() const {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
        return error("CScriptCheck() : %s VerifySignature failed", ptxTo->GetHash().ToString().substr(0,10).c_str());
    return true;
}

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

bool CTransaction::ConnectInputs(CTxDB& txdb, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
    const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks, unsigned int flags, std::vector<CScriptCheck> *pvChecks)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool

    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        int64 nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return DoS(100, error("ConnectInputs() : %s prevout.n out of range %d %"PRIszu" %"PRIszu" prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
			
		/*//mmaturity check	
		int nSpendHeight = nHeight + 1;
        int64 nValueIn = 0;
        int64 nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);

            // If prev is coinbase, check that it's matured
            if (coins.IsCoinBase()) {
                int inCMtu=nCoinbaseMaturity;
                if(nSpendHeight>=500){
                    
                }
                if (nSpendHeight - coins.nHeight < inCMtu)
                    return state.Invalid(error("CheckInputs() : tried to spend coinbase at depth %d", nSpendHeight - coins.nHeight));
                if (coins.nHeight==0){
                    if(nSpendHeight>TWOYEARS){
                        return state.Invalid(error("CheckInputs() : Trying to claim vested shares after expiry period. spend height=%d", nSpendHeight));
                    }
                    //printf("Coins Amount in Genesis Block:%d",coins.vout[prevout.n].nValue);
                    if(coins.vout[prevout.n].nValue>MAXBALANCEGENESIS){
                        int maturityHeight=getVestedSharesMaturityHeight(prevout.hash);
                        if(nSpendHeight<maturityHeight){
                            //Not matured yet
                            return state.Invalid(error("CheckInputs() : tried to spend before vested period. spend height=%d, maturity height=%d", nSpendHeight, maturityHeight));
                        }
                    }
                }
            }}*/
            
            //maturity check

			
			
			
			
			
            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
                for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < nCoinbaseMaturity; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - pindex->nHeight);

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return DoS(100, error("ConnectInputs() : txin values out of range"));

        }

        if (pvChecks)
            pvChecks->reserve(vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            if (fScriptChecks)
            {
                // Verify signature
                CScriptCheck check(txPrev, *this, i, flags, 0);
                if (pvChecks)
                {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                }
                else if (!check())
                {
                    if (flags & STRICT_FLAGS)
                    {
                        // Don't trigger DoS code in case of STRICT_FLAGS caused failure.
                        CScriptCheck check(txPrev, *this, i, flags & ~STRICT_FLAGS, 0);
                        if (check())
                            return error("ConnectInputs() : %s strict VerifySignature failed", GetHash().ToString().substr(0,10).c_str());
                    }
                    return DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (IsCoinStake())
        {
            // ppcoin: coin stake tx earns reward instead of paying fee
            uint64 nCoinAge;
            if (!GetCoinAge(txdb, nCoinAge))
                return error("ConnectInputs() : %s unable to get coin age for coinstake", GetHash().ToString().substr(0,10).c_str());
            int64 nStakeReward = GetValueOut() - nValueIn;
            if (nStakeReward > GetProofOfStakeReward(nCoinAge, pindexBlock->nBits, nTime, pindexBlock->nHeight) - GetMinFee() + MIN_TX_FEE)
                return DoS(100, error("ConnectInputs() : %s stake reward exceeded", GetHash().ToString().substr(0,10).c_str()));
        }
        else
        {
            if (nValueIn < GetValueOut())
                return DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            int64 nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0)
                return DoS(100, error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));
            // ppcoin: enforce transaction fees for every block
            if (nTxFee < GetMinFee())
                return fBlock? DoS(100, error("ConnectInputs() : %s not paying required fee=%s, paid=%s", GetHash().ToString().substr(0,10).c_str(), FormatMoney(GetMinFee()).c_str(), FormatMoney(nTxFee).c_str())) : false;

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return DoS(100, error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    {
        LOCK(mempool.cs);
        int64 nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mempool.exists(prevout.hash))
                return false;
            CTransaction& txPrev = mempool.lookup(prevout.hash);

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, 0))
                return error("ClientConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mempool.mapNextTx stuff,
            ///// not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;

            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return error("ClientConnectInputs() : txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}




bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
	
	if(GetArg("-authoritativechain",0)==1){
        return error("DisconnectBlock() : this chain is authoritative - once blocks are connected, they cannot be disconnected.");
    }
    
    
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck(void*) {
    vnThreadsRunning[THREAD_SCRIPTCHECK]++;
    RenameThread("NoirShares-scriptch");
    scriptcheckqueue.Thread();
    vnThreadsRunning[THREAD_SCRIPTCHECK]--;
}

void ThreadScriptCheckQuit() {
    scriptcheckqueue.Quit();
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck)
{
    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(!fJustCheck, !fJustCheck))
        return false;

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their
    // initial block download.
    bool fEnforceBIP30 = true; // Always active in NoirShares
    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);
	
	int64 nStart = GetTimeMicros();
    int64 nFees = 0;
    int64 nValueIn = 0;
    int64 nValueOut = 0;
    unsigned int nSigOps = 0;
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();

        if (fEnforceBIP30) {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld)) {
                BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                    if (pos.IsNull())
                        return false;
            }
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else
        {
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return DoS(100, error("ConnectBlock() : too many sigops"));

            int64 nTxValueIn = tx.GetValueIn(mapInputs);
            int64 nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (!tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;

            std::vector<CScriptCheck> vChecks;
            if (!tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fScriptChecks, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, nScriptCheckThreads ? &vChecks : NULL))
                return false;
            control.Add(vChecks);
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return error("Connect() : WriteBlockIndex for pindex failed");

    // ppcoin: fees are not collected by miners as in bitcoin
    // ppcoin: fees are destroyed to compensate the entire network
    if (fDebug && GetBoolArg("-printcreation"))
        printf("ConnectBlock() : destroy=%s nFees=%"PRI64d"\n", FormatMoney(nFees).c_str(), nFees);
	checkForCheckpoints(vtx,GetBoolArg("-broadcastdraws"),GetBoolArg("-logblock"));

    //Ensure if payout transaction(s) is/are included, all payouts are made and calculate commission allowed
    int64 commissionablePayout=0;
    int64 nonCommissionablePayout=0;
    if(!checkForPayouts(vtx,commissionablePayout,nonCommissionablePayout,false,false,pindex->nHeight)){
        return DoS(100, error("ConnectBlock() : coinbase not making payouts correctly.\n"));
    }
    nFees=nFees+commissionablePayout;
    nFees=nFees+nonCommissionablePayout;
    nFees=nFees+(commissionablePayout>>PRIZEPAYMENTCOMMISSIONS);

    if(pindex->nHeight<PRIZEPAYMENTHEIGHT){
        //Note this should be removed once checkpointed blocks stop accepting blocks with nc payouts
        nFees=nFees+(nonCommissionablePayout>>PRIZEPAYMENTCOMMISSIONS);
	
    }
	LOCK(grantdb);
    int64 grantAward=0;
	//Officer and Shareholder grant awards
    if(isGrantAwardBlock(pindex->nHeight)){
	if(!getGrantAwards(pindex->nHeight)){
		return DoS(100, error("ConnectBlock() : grant awards error"));
	}
			
	//Ensure fees are going to award winners
	printf("Check Grant Awards Are Being Added for block %d\n",pindex->nHeight);
	unsigned int awardFound=0;
	for(gait=grantAwards.begin(); gait!=grantAwards.end(); ++gait){
		grantAward=grantAward+gait->second;
	}
	for(gait=grantAwards.begin(); gait!=grantAwards.end(); ++gait){
		for (unsigned int j = 0; j <vtx[0].vout.size(); j++){
			CTxDestination address;
			ExtractDestination(vtx[0].vout[j].scriptPubKey,address);
			string receiveAddress=CBitcoinAddress(address).ToString().c_str();
			int64 theAmount=vtx[0].vout[j].nValue;
			//printf("Compare %llu, %llu\n",theAmount,gait->second);
			//printf("Compare %s, %s\n",receiveAddress.c_str(),gait->first.c_str());
		
			if(theAmount==gait->second && receiveAddress==gait->first){
				awardFound++;
				break;
			}
		}
	}
	
	//printf("Grant award in block %d, %d\n",awardFound,grantAwards.size());
	/*for(gait=grantAwards.begin(); gait!=grantAwards.end(); ++gait){
		printf("Grant award in block %s, %llu\n",gait->first.c_str(),gait->second);
	}*/			
	if (awardFound != grantAwards.size()){
		return DoS(100, error("ConnectBlock() : coinbase not paying grants to award winners "));
	}
    }
        
    //Check correct amount awarded in grants
    if(pindex->nHeight==1 && !fTestNet){
	if(vtx[0].GetValueOut()!=73366415666531){
		return DoS(100, error("ConnectBlock() : Block 1 coinbase pays too much (actual=%"PRI64d" vs limit=%"PRI64d")", vtx[0].GetValueOut(), GetBlockValue(pindex->nHeight, nFees+grantAward)));
	}
    }else if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees+grantAward)){
        return DoS(100, error("ConnectBlock() %d : coinbase pays too much (actual=%"PRI64d" vs limit=%"PRI64d")", pindex->nHeight, vtx[0].GetValueOut(), GetBlockValue(pindex->nHeight, nFees+grantAward)));
    }


    //1% commission
    nFees=nFees+(calculateTicketIncome(vtx)>>TICKETCOMMISSIONRATE);

    unsigned int theNBits=bnProofOfWorkLimit.GetCompact();
    if(pindex->nHeight>0){
        theNBits=pindex->pprev->nBits;
    }
    if (vtx[0].GetValueOut() > GetProofOfWorkReward(pindex->nHeight, nFees,theNBits))
        return DoS(100, error("ConnectBlock() : coinbase pays too much (actual=%"PRI64d" vs limit=%"PRI64d")", vtx[0].GetValueOut(), GetProofOfWorkReward(pindex->nHeight, nFees,theNBits)));

    if (!control.Wait())
        return DoS(100, false);
    int64 nTime2 = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Verify %lld txins: %.2fms (%.3fms/txin)\n", nValueIn - 1, 0.001 * nTime2, nValueIn <= 1 ? 0 : 0.001 * nTime2 / (nValueIn-1));

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

    uint256 prevHash = 0;
    if(pindex->pprev)
    {
        prevHash = pindex->pprev->GetBlockHash();
        // printf("==> Got prevHash = %s\n", prevHash.ToString().c_str());
    }

    if (vtx[0].GetValueOut() > GetProofOfWorkReward(pindex->nHeight, nFees, prevHash))
        return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);

    return true;
}

bool static Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    printf("REORGANIZE\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    printf("REORGANIZE: Disconnect %"PRIszu" blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    printf("REORGANIZE: Connect %"PRIszu" blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block
            return error("Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("Reorganize() : TxnCommit failed");

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete)
        mempool.remove(tx);

    printf("REORGANIZE: done\n");

    return true;
}


// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();
        InvalidChainFound(pindexNew);
        return false;
    }
    if (!txdb.TxnCommit())
        return error("SetBestChain() : TxnCommit failed");

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    BOOST_FOREACH(CTransaction& tx, vtx)
        mempool.remove(tx);

    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();

    if (!txdb.TxnBegin())
        return error("SetBestChain() : TxnBegin failed");

    if (pindexGenesisBlock == NULL && hash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
    {
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return error("SetBestChain() : TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(txdb, pindexNew))
            return error("SetBestChain() : SetBestChainInner failed");
    }
    else
    {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->bnChainTrust > pindexBest->bnChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
            printf("Postponing %"PRIszu" reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (!Reorganize(txdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return error("SetBestChain() : Reorganize failed");
        }

        // Connect further blocks
        BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex))
            {
                printf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (!txdb.TxnBegin()) {
                printf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }
            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(txdb, pindex))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    bnBestChainTrust = pindexNew->bnChainTrust;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;
    printf("SetBestChain: new best=%s  height=%d  trust=%s  date=%s\n",
      hashBestChain.ToString().c_str(), nBestHeight, bnBestChainTrust.ToString().c_str(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    printf("Stake checkpoint: %x\n", pindexBest->nStakeModifierChecksum);

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are 
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, uint64& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%"PRI64d" nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint64 nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%"PRI64d"\n", nCoinAge);
    return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    pindexNew->phashBlock = &hash;
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // ppcoin: compute chain trust score
    pindexNew->bnChainTrust = (pindexNew->pprev ? pindexNew->pprev->bnChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nHeight)))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // ppcoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake())
    {
        if (!mapProofOfStake.count(hash))
            return error("AddToBlockIndex() : hashProofOfStake not found in map");
        pindexNew->hashProofOfStake = mapProofOfStake[hash];
    }

    // ppcoin: compute stake modifier
    uint64 nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
        return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->nStakeModifierChecksum = GetStakeModifierChecksum(pindexNew);
    if (!CheckStakeModifierCheckpoints(pindexNew->nHeight, pindexNew->nStakeModifierChecksum))
        return error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016"PRI64x, pindexNew->nHeight, nStakeModifier);

    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;
    if (!txdb.TxnBegin())
        return false;
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    // New best
    if (pindexNew->bnChainTrust > bnBestChainTrust)
        if (!SetBestChain(txdb, pindexNew))
            return false;

    txdb.Close();

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    uiInterface.NotifyBlocksChanged();
    return true;
}




bool CBlock::CheckBlock(bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CheckBlock() : size limits failed"));

    // Check proof of work matches claimed amount
    //printf("block.nBits in CheckBlock Func is:%d\n", nBits);

    // Check timestamp
    if (GetBlockTime() > GetAdjustedTime() + nMaxClockDrift)
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return DoS(100, error("CheckBlock() : first tx is not coinbase"));
    for (unsigned int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return DoS(100, error("CheckBlock() : more than one coinbase"));

    // Validate last stage of PoW only
    if (fCheckPOW && IsProofOfWork() && !CheckProofOfWork(GetHash(), nBits))
        return DoS(50, error("CheckBlock() : proof of work failed"));

    // Verify momentum and rseed
    if (fCheckPOW && IsProofOfWork() && !VerifyRandomSeed())
        return DoS(50, error("CheckBlock() : rseed validation failed"));

    
	if (IsProofOfStake())
    {
    // ppcoin: coinbase output should be empty if proof-of-stake block
    if  (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty())
        return error("CheckBlock() : coinbase output not empty for proof-of-stake block");
	// Check coinstake timestamp
    if (!CheckCoinStakeTimestamp(GetBlockTime(), (int64)vtx[1].nTime))
        return DoS(50, error("CheckBlock() : coinstake timestamp violation nTimeBlock=%"PRI64d" nTimeTx=%u", GetBlockTime(), vtx[1].nTime));
	// ppcoin: only the second transaction can be the optional coinstake
    for (unsigned int i = 2; i < vtx.size(); i++)
        if (vtx[i].IsCoinStake())
            return DoS(100, error("CheckBlock() : coinstake in wrong position"));
     }
    // Check coinbase timestamp
     if (GetBlockTime() > (int64)vtx[0].nTime + nMaxClockDrift)
        return DoS(50, error("CheckBlock() : coinbase timestamp is too early"));

    

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        if (!tx.CheckTransaction())
            return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64)tx.nTime)
            return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uniqueTx.insert(tx.GetHash());
    }
    if (uniqueTx.size() != vtx.size())
        return DoS(100, error("CheckBlock() : duplicate transaction"));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        nSigOps += tx.GetLegacySigOpCount();
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));

    /* ppcoin: check block signature
    if (!CheckBlockSignature())
        return DoS(100, error("CheckBlock() : bad block signature"));*/

    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock() : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;

    if (IsProofOfWork() && nHeight > LAST_POW_BLOCK)
        return DoS(100, error("AcceptBlock() : reject proof-of-work at height %d", nHeight));

    // Check proof-of-work or proof-of-stake
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()))
        return DoS(100, error("AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast() || GetBlockTime() + nMaxClockDrift < pindexPrev->GetBlockTime())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    // ppcoin: check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(hash, pindexPrev))
    {
        if(!GetBoolArg("-nosynccheckpoints", false))
        {
            return error("AcceptBlock() : rejected by synchronized checkpoint");
        }
        else
        {
            strMiscWarning = _("WARNING: syncronized checkpoint violation detected, but skipped!");
        }
    }

    // Reject block.nVersion < 3 blocks since 95% threshold on mainNet and always on testNet:
    if (nVersion < 3 && ((!fTestNet && nHeight > 14060) || (fTestNet && nHeight > 0)))
        return error("CheckBlock() : rejected nVersion < 3 block");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    // ppcoin: check pending sync-checkpoint
    Checkpoints::AcceptPendingSyncCheckpoint();

    return true;
}


CBigNum CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0)
        return 0;

    if (IsProofOfStake())
    {
        // Return trust score as usual
        return (CBigNum(1)<<256) / (bnTarget+1);
    }
    else
    {
        // Calculate work amount for block
        CBigNum bnPoWTrust = (bnProofOfWorkLimit / (bnTarget+1));
        return bnPoWTrust > 1 ? bnPoWTrust : 1;
    }
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (hash >= smallestInvalidHash)
        return error("ProcessBlock() : invalid hash presented %s", hash.ToString().c_str());
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,20).c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
        return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());

    // Preliminary checks
    if (!pblock->CheckBlock())
        return error("ProcessBlock() : CheckBlock FAILED");

    // ppcoin: verify hash target and signature of coinstake tx
    if (pblock->IsProofOfStake())
    {
        uint256 hashProofOfStake = 0;
        if (!CheckProofOfStake(pblock->vtx[1], pblock->nBits, hashProofOfStake))
        {
            printf("WARNING: ProcessBlock(): check proof-of-stake failed for block %s\n", hash.ToString().c_str());
            return false; // do not error here as we expect this during initial block download
        }
        if (!mapProofOfStake.count(hash)) // add to mapProofOfStake
            mapProofOfStake.insert(make_pair(hash, hashProofOfStake));
    }

    CBlockIndex* pcheckpoint = Checkpoints::GetLastSyncCheckpoint();
    if (pcheckpoint && pblock->hashPrevBlock != hashBestChain && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;

        if (pblock->IsProofOfStake())
            bnRequired.SetCompact(ComputeMinStake(GetLastBlockIndex(pcheckpoint, true)->nBits, deltaTime, pblock->nTime));
        else
            bnRequired.SetCompact(ComputeMinWork(GetLastBlockIndex(pcheckpoint, false)->nBits, deltaTime));

        if (bnNewBlock > bnRequired)
        {
            if (pfrom)
                pfrom->Misbehaving(100);
            return error("ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // ppcoin: ask for pending sync-checkpoint if any
    if (!IsInitialBlockDownload())
        Checkpoints::AskForPendingSyncCheckpoint(pfrom);

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
        CBlock* pblock2 = new CBlock(*pblock);
        // ppcoin: check proof-of-stake
        if (pblock2->IsProofOfStake())
        {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if (setStakeSeenOrphan.count(pblock2->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
                return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock2->GetProofOfStake().first.ToString().c_str(), pblock2->GetProofOfStake().second, hash.ToString().c_str());
            else
                setStakeSeenOrphan.insert(pblock2->GetProofOfStake());
        }
        mapOrphanBlocks.insert(make_pair(hash, pblock2));
        mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
        return error("ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED\n");

    // ppcoin: if responsible for sync-checkpoint send it
    if (pfrom && !CSyncCheckpoint::strMasterPrivKey.empty())
        Checkpoints::SendSyncCheckpoint(Checkpoints::AutoSelectSyncCheckpoint());

    return true;
}

// ppcoin: sign block
bool CBlock::SignBlock(const CKeyStore& keystore)
{
    vector<valtype> vSolutions;
    txnouttype whichType;

    if(!IsProofOfStake())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                valtype& vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                    continue;
                if (key.GetPubKey() != vchPubKey)
                    continue;
                if(!key.Sign(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    else
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;

            return key.Sign(GetHash(), vchBlockSig);
        }
    }

    printf("Sign failed\n");
    return false;
}

// ppcoin: check block signature
bool CBlock::CheckBlockSignature() const
{
    if (GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
        return vchBlockSig.empty();

    vector<valtype> vSolutions;
    txnouttype whichType;

    if(IsProofOfStake())
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;
        if (whichType == TX_PUBKEY)
        {
            valtype& vchPubKey = vSolutions[0];
            CKey key;
            if (!key.SetPubKey(vchPubKey))
                return false;
            if (vchBlockSig.empty())
                return false;
            return key.Verify(GetHash(), vchBlockSig);
        }
    }
    else
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;

            if (whichType == TX_PUBKEY)
            {
                // Verify
                valtype& vchPubKey = vSolutions[0];
                CKey key;
                if (!key.SetPubKey(vchPubKey))
                    continue;
                if (vchBlockSig.empty())
                    continue;
                if(!key.Verify(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    return false;
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "NoirShares", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool CBlock::VerifyRandomSeed() const
{
	// 1. Serialize current block
	CDataStream ssOriginalBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssOriginalBlock << *this;

	// 2. Deserialize block to create completely detached clone
printf("Ver Blk Data A: %s\n", HexStr(ssOriginalBlock.begin(), ssOriginalBlock.end()).c_str());
	CDataStream ssOriginalBlockData(ssOriginalBlock.begin(), ssOriginalBlock.end(), SER_NETWORK, PROTOCOL_VERSION);
	CBlock blankedBlock;
	try {
		ssOriginalBlockData >> blankedBlock;
	}
	catch (std::exception &e) {
		// TODO Properly handle development exception - normally it shall be core dumped
		return error("VerifyRandomSeed() : can not deserialize just serialized block");
//		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
	}

	// 3. Blank block data fields not involved in Random Seed calculation
	blankedBlock.hashMerkleRoot = 0;
	blankedBlock.hashRandomSeed = 0;
	blankedBlock.nBirthdayA   = 0;
	blankedBlock.nBirthdayB   = 0;
	// 3a. Blank amounts in coinbase outputs
	for (size_t i = 0; i < blankedBlock.vtx[0].vout.size(); i++)
	{
		blankedBlock.vtx[0].vout[i].nValue = 0;
	}

	// 4. Serialize blanked block
	CDataStream ssBlankedBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssBlankedBlock << blankedBlock;

	// 5. Generate midhash for momentum
printf("Ver Mid Hash A: %s\n", HexStr(ssBlankedBlock.begin(), ssBlankedBlock.end()).c_str());
	uint256 midHash = Hash(ssBlankedBlock.begin(), ssBlankedBlock.end());
printf("Ver Mid Hash B: %s\n", midHash.ToString().c_str());

	// 6. Verify momentum
printf("Ver Mid Hash C: %d %d\n", nBirthdayA, nBirthdayB);
	if (!bts::momentum_verify( midHash, nBirthdayA, nBirthdayB ))
	{
		return error("VerifyRandomSeed() : can not verify momentum solution");
	}
	// 6a. Copy momentum solution from original block to blanked because of it is valid and shall be used for random seed generation
	blankedBlock.nBirthdayA = nBirthdayA;
	blankedBlock.nBirthdayB = nBirthdayB;

	// 7. Serialize blanked block with filled momentum solution
	CDataStream ssPhase2BlankedBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssPhase2BlankedBlock << blankedBlock;

	// 8. Hash phase 2 block data to generate random seed
	// TODO Replace hash with CN
printf("Ver Rng Hash A: %s\n", HexStr(ssPhase2BlankedBlock.begin(), ssPhase2BlankedBlock.end()).c_str());
	uint256 seedHash = Hash(ssPhase2BlankedBlock.begin(), ssPhase2BlankedBlock.end());
printf("Ver Rng Hash B: %s\n", seedHash.ToString().c_str());

	// 9. Verify if seedHash is the same as stored in original block
	if (seedHash == hashRandomSeed)
		return true;
	else
	{
		return error("VerifyRandomSeed() : can not verify random seed");
	}
}

// Generate random seed and store it in block header alone with momentum solution
bool CBlock::GenerateRandomSeed()
{
	// 1. Serialize current block
	CDataStream ssOriginalBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssOriginalBlock << *this;

	// 2. Deserialize block to create completely detached clone
	CDataStream ssOriginalBlockData(ssOriginalBlock.begin(), ssOriginalBlock.end(), SER_NETWORK, PROTOCOL_VERSION);
	CBlock blankedBlock;
	try {
		ssOriginalBlockData >> blankedBlock;
	}
	catch (std::exception &e) {
		// TODO Properly handle development exception - normally it shall be core dumped
		return error("CalculateRandomSeed() : can not deserialize just serialized block");
//		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
	}

	// 3. Blank block data fields not involved in Random Seed calculation
	blankedBlock.hashMerkleRoot = 0;
	blankedBlock.hashRandomSeed = 0;
	blankedBlock.nBirthdayA   = 0;
	blankedBlock.nBirthdayB   = 0;
	// 3a. Blank amounts in coinbase outputs
	for (size_t i = 0; i < blankedBlock.vtx[0].vout.size(); i++)
	{
		blankedBlock.vtx[0].vout[i].nValue = 0;
	}

	// 4. Serialize blanked block
	CDataStream ssBlankedBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssBlankedBlock << blankedBlock;

	// 5. Generate midhash for momentum
printf("Gen Mid Hash A: %s\n", HexStr(ssBlankedBlock.begin(), ssBlankedBlock.end()).c_str());
	uint256 midHash = Hash(ssBlankedBlock.begin(), ssBlankedBlock.end());
printf("Gen Mid Hash B: %s\n", midHash.ToString().c_str());

	// 6. Solve momentum
	std::vector< std::pair<uint32_t,uint32_t> > results =bts::momentum_search( midHash );
	if (results.size() == 0)
	{
		// No momentum solution found - can not solve current block
		return false;
	}
	// 6a. TODO Currently it takes only one solution from momentum, while mining can be more efficient if all variations of momentum solutions taken 
	uint32_t candidateBirthdayA=results[0].first;
	uint32_t candidateBirthdayB=results[0].second;
	blankedBlock.nBirthdayA = candidateBirthdayA;
	blankedBlock.nBirthdayB = candidateBirthdayB;
printf("Gen Mid Hash C: %d %d\n", candidateBirthdayA, candidateBirthdayB);

	// 7. Serialize blanked block with filled momentum solution
	CDataStream ssPhase2BlankedBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssPhase2BlankedBlock << blankedBlock;

	// 8. Hash phase 2 block data to generate random seed
	// TODO Replace hash with CN
printf("Gen Rng Hash A: %s\n", HexStr(ssPhase2BlankedBlock.begin(), ssPhase2BlankedBlock.end()).c_str());
	uint256 seedHash = Hash(ssPhase2BlankedBlock.begin(), ssPhase2BlankedBlock.end());
printf("Gen Rng Hash B: %s\n", seedHash.ToString().c_str());

	// 9. Move generated data to original block, including blanking coinbase outputs
	BOOST_FOREACH(CTxOut txout, vtx[0].vout)
	{
		txout.nValue = 0;
	}
	hashMerkleRoot = 0;
	hashRandomSeed = seedHash;
	nBirthdayA   = candidateBirthdayA;
	nBirthdayB   = candidateBirthdayB;

	return true;
}

bool LoadBlockIndex(bool fAllowNew)
{
    CBigNum bnTrustedModulus;

    if (fTestNet)
    {
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf3;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;

        bnProofOfStakeLimit = bnProofOfStakeLimitTestNet; // 0x00000fff PoS base target is fixed in testnet
        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 0x0000ffff PoW base target is fixed in testnet
        bnTrustedModulus.SetHex("f0d14cf72623dacfe738d0892b599be0f31052239cddd95a3f25101c801dc990453b38c9434efe3f372db39a32c2bb44cbaea72d62c8931fa785b0ec44531308df3e46069be5573e49bb29f4d479bfc3d162f57a5965db03810be7636da265bfced9c01a6b0296c77910ebdc8016f70174f0f18a57b3b971ac43a934c6aedbc5c866764a3622b5b7e3f9832b8b3f133c849dbcc0396588abcd1e41048555746e4823fb8aba5b3d23692c6857fccce733d6bb6ec1d5ea0afafecea14a0f6f798b6b27f77dc989c557795cc39a0940ef6bb29a7fc84135193a55bcfc2f01dd73efad1b69f45a55198bd0e6bef4d338e452f6a420f1ae2b1167b923f76633ab6e55");
        nStakeMinAge = 20 * 60; // test net min age is 20 min
        nStakeMaxAge = 60 * 60; // test net min age is 60 min
        nModifierInterval = 60; // test modifier interval is 2 minutes
        nCoinbaseMaturity = 10; // test maturity is 10 blocks
        nStakeTargetSpacing = 3 * 60; // test block spacing is 3 minutes
    }
	
	{
        bnTrustedModulus.SetHex("d02f952e1090a5a72a3eda261083256596ccc192935ae1454c2bafd03b09e6ed11811be9f3a69f5783bbbced8c6a0c56621f42c2d19087416facf2f13cc7ed7159d1c5253119612b8449f0c7f54248e382d30ecab1928dbf075c5425dcaee1a819aa13550e0f3227b8c685b14e0eae094d65d8a610a6f49fff8145259d1187e4c6a472fa5868b2b67f957cb74b787f4311dbc13c97a2ca13acdb876ff506ebecbb904548c267d68868e07a32cd9ed461fbc2f920e9940e7788fed2e4817f274df5839c2196c80abe5c486df39795186d7bc86314ae1e8342f3c884b158b4b05b4302754bf351477d35370bad6639b2195d30006b77bf3dbb28b848fd9ecff5662bf39dde0c974e83af51b0d3d642d43834827b8c3b189065514636b8f2a59c42ba9b4fc4975d4827a5d89617a3873e4b377b4d559ad165748632bd928439cfbc5a8ef49bc2220e0b15fb0aa302367d5e99e379a961c1bc8cf89825da5525e3c8f14d7d8acca2fa9c133a2176ae69874d8b1d38b26b9c694e211018005a97b40848681b9dd38feb2de141626fb82591aad20dc629b2b6421cef1227809551a0e4e943ab99841939877f18f2d9c0addc93cf672e26b02ed94da3e6d329e8ac8f3736eebbf37bb1a21e5aadf04ee8e3b542f876aa88b2adf2608bd86329b7f7a56fd0dc1c40b48188731d11082aea360c62a0840c2db3dad7178fd7e359317ae081");
    }
    
    // Set up the Zerocoin Params object
    ZCParams = new libzerocoin::Params(bnTrustedModulus);

    //
    // Load block index
    //
    CTxDB txdb("cr");
    if (!txdb.LoadBlockIndex())
        return false;
    txdb.Close();

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;

        // Genesis block
        const char* pszTimestamp = "NoirBits - Future in hand.";
        CTransaction txNew;
        txNew.nTime = nChainStartTime;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = nChainStartTime;
        block.nBits    = bnProofOfWorkLimit.GetCompact();
        block.nNonce   = nChainStartNonce;
        block.hashRandomSeed = rseedGenesisBlock;
        block.nBirthdayA   = nChainStartBirthdayA;
        block.nBirthdayB   = nChainStartBirthdayB;
        
        //// debug print
        uint256 hash = block.GetHash();
        printf("block.nBits = %u \n", block.nBits);
        printf("Hash: %s\n", hash.ToString().c_str());
        printf("block.nTime = %u \n", block.nTime);
        printf("Genesis: %s\n", hashGenesisBlock.ToString().c_str());
        printf("MROOT: %s\n", block.hashMerkleRoot.ToString().c_str());
        printf("coinnNonce=%d;\n",block.nNonce);
        printf("RSEED: %s\n", block.hashRandomSeed.ToString().c_str());
		printf("birthdayA=%u;\n",block.nBirthdayA);
		printf("birthdayB=%u;\n",block.nBirthdayB);
        block.print();



      /* {
		printf("Generating new genesis block...\n");
		uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
		uint256 testHash;
		block.nNonce = 0;
		for (;;)
		{
			block.nNonce=block.nNonce+1;
			while (!block.GenerateRandomSeed()) 
			{
				block.nNonce=block.nNonce+1;
			}
			// Amount calculation not needed for genesis block - all outputs are zero
			//block.hashMerkleRoot = block.BuildMerkleTree();
			block.hashMerkleRoot = merkleRootGenesisBlock;
			testHash=block.GetHash();
			printf("testHash %s\n", testHash.ToString().c_str());
			printf("Hash Target %s\n", hashTarget.ToString().c_str());
			if(testHash<hashTarget){
				printf("Found Genesis Block Hash: %s\n", testHash.ToString().c_str());
				printf("Found Genesis Block Merkle Root: %s\n", block.hashMerkleRoot.ToString().c_str());
				printf("Found Genesis Block nNonce: %d\n", block.nNonce);
				printf("Found Genesis Block nTime: %d\n", block.nTime);
				printf("Found Genesis Block RSEED: %s\n", block.hashRandomSeed.ToString().c_str());
				printf("Found Genesis Block nBirthdayA: %d\n", block.nBirthdayA);
				printf("Found Genesis Block nBirthdayB: %d\n", block.nBirthdayB);
				break;
			}
		}
	}*/

        assert(block.hashMerkleRoot == merkleRootGenesisBlock);
        block.print();
        assert(hash == hashGenesisBlock);
        assert(block.CheckBlock());

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(nFile, nBlockPos))
            return error("LoadBlockIndex() : genesis block not accepted");

        // ppcoin: initialize synchronized checkpoint
        if (!Checkpoints::WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
            return error("LoadBlockIndex() : failed to init sync checkpoint");
    }

    // ppcoin: if checkpoint master key changed must reset sync-checkpoint
    {
        CTxDB txdb;
        string strPubKey = "";
        if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
        {
            // write checkpoint master key to db
            txdb.TxnBegin();
            if (!txdb.WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
                return error("LoadBlockIndex() : failed to write new checkpoint master key to db");
            if (!txdb.TxnCommit())
                return error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
            if ((!fTestNet) && !Checkpoints::ResetSyncCheckpoint())
                return error("LoadBlockIndex() : failed to reset sync-checkpoint");
        }
        txdb.Close();
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %"PRIszu"",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn)
{
    int64 nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != (unsigned int)-1 && blkdat.good() && !fRequestShutdown)
            {
                unsigned char pchData[65536];
                do {
                    fseek(blkdat, nPos, SEEK_SET);
                    int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = (unsigned int)-1;
                        break;
                    }
                    void* nFind = memchr(pchData, pchMessageStart[0], nRead+1-sizeof(pchMessageStart));
                    if (nFind)
                    {
                        if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
                } while(!fRequestShutdown);
                if (nPos == (unsigned int)-1)
                    break;
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;
                    if (ProcessBlock(NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) {
            printf("%s() : Deserialize or I/O error caught during load\n",
                   __PRETTY_FUNCTION__);
        }
    }
    printf("Loaded %i blocks from external file in %"PRI64d"ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

static string strMintMessage = "Info: Minting suspended due to locked wallet.";
static string strMintWarning;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // ppcoin: wallet lock warning for minting
    if (strMintWarning != "")
    {
        nPriority = 0;
        strStatusBar = strMintWarning;
    }

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // ppcoin: should not enter safe mode for longer invalid chain
    // ppcoin: if sync-checkpoint is too old do not enter safe mode
    if (Checkpoints::IsSyncCheckpointTooOld(60 * 60 * 24 * 365) && !fTestNet && !IsInitialBlockDownload())
    {
        nPriority = 100;
        strStatusBar = "WARNING: Checkpoint is too old. Wait for block chain to download, or notify developers.";
    }

    // ppcoin: if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        nPriority = 3000;
        strStatusBar = strRPC = "WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.";
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;  // ppcoin: safe mode for high alert
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
            {
            LOCK(mempool.cs);
            txInMap = (mempool.exists(inv.hash));
            }
        return txInMap ||
               mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xcd, 0xf1, 0xe2, 0xb1 };

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static map<CService, CPubKey> mapReuseKey;
    RandAddSeedPerfmon();
    if (fDebug)
        printf("received: %s (%"PRIszu" bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1);
            return false;
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PROTO_VERSION)
        {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

       /* if (pfrom->nVersion < 60010)
        {
            printf("partner %s using a buggy client %d, disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return true;
        }*/

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Ask the first connected node for block updates
        static int nAskedForBlocks = 0;
        if (!pfrom->fClient && !pfrom->fOneShot &&
            (pfrom->nStartingHeight > (nBestHeight - 144)) &&
            (pfrom->nVersion < NOBLKS_VERSION_START ||
             pfrom->nVersion >= NOBLKS_VERSION_END) &&
             (nAskedForBlocks < 1 || vNodes.size() <= 1))
        {
            nAskedForBlocks++;
            pfrom->PushGetBlocks(pindexBest, uint256(0));
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (!IsInitialBlockDownload())
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20);
            return error("message addr size() = %"PRIszu"", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64 hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message inv size() = %"PRIszu"", vInv.size());
        }

        // find last block in inv vector
        unsigned int nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }
        CTxDB txdb("r");
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            if (fDebug)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
                if (fDebug)
                    printf("force request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message getdata size() = %"PRIszu"", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))
            printf("received getdata (%"PRIszu" invsz)\n", vInv.size());

        BOOST_FOREACH(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            if (fDebugNet || (vInv.size() == 1))
                printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake 
                        // block might be rejected by stake connection check)
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, GetLastBlockIndex(pindexBest, false)->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    LOCK(mempool.cs);
                    if (mempool.exists(inv.hash)) {
                        CTransaction tx = mempool.lookup(inv.hash);
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                    }
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 500;
        printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != hashBestChain && pindex->GetBlockTime() + nStakeMinAge > pindexBest->GetBlockTime())
                    pfrom->PushInventory(CInv(MSG_BLOCK, hashBestChain));
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }
    else if (strCommand == "checkpoint")
    {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom))
        {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
    }

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CDataStream vMsg(vRecv);
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);
		
		 // Truncate messages to the size of the tx in them
        unsigned int nSize = ::GetSerializeSize(tx,SER_NETWORK, PROTOCOL_VERSION);
        if (nSize < vMsg.size()){
            vMsg.resize(nSize);
        }
		
        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs))
        {
            SyncWithWallets(tx, NULL, true);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (map<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());
                    bool fMissingInputs2 = false;

                    if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0,10).c_str());
                        SyncWithWallets(tx, NULL, true);
                        RelayMessage(inv, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                        vEraseQueue.push_back(inv.hash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(inv.hash);
                        printf("   removed invalid orphan tx %s\n", inv.hash.ToString().substr(0,10).c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(vMsg);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        if (tx.nDoS) pfrom->Misbehaving(tx.nDoS);
    }


    else if (strCommand == "block")
    {
        CBlock block;
        vRecv >> block;

        printf("received block %s\n", block.GetHash().ToString().substr(0,20).c_str());
        // block.print();

        CInv inv(MSG_BLOCK, block.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (ProcessBlock(pfrom, &block))
            mapAlreadyAskedFor.erase(inv);
        if (block.nDoS) pfrom->Misbehaving(block.nDoS);
        
        if (fSecMsgEnabled)
            SecureMsgScanBlock(block);
    }


    else if (strCommand == "getaddr")
    {
		// Don't return addresses older than nCutOff timestamp
        int64 nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); i++) {
            CInv inv(MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64 nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }


    else
    {
        if (fSecMsgEnabled)
            SecureMsgReceiveData(pfrom, strCommand, vRecv);
        
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    //if (fDebug)
    //    printf("ProcessMessages(%u bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //

    while (true)
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= SendBufferSize())
            break;

        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
        if (vRecv.end() - pstart < nHeaderSize)
        {
            if ((int)vRecv.size() > nHeaderSize)
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            printf("\n\nPROCESSMESSAGE SKIPPED %"PRIpdd" BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE)
        {
            printf("ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            {
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            }
            if (fShutdown)
                return true;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return true;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSend.empty()) {
            uint64 nonce = 0;
            if (pto->nVersion > BIP0031_VERSION)
                pto->PushMessage("ping", nonce);
            else
                pto->PushMessage("ping");
        }

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);
        
        if (fSecMsgEnabled)
            SecureMsgSendData(pto, fSendTrickle); // should be in cs_main?
    }
    
    
    
    return true;
}





//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};


uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;
int64 nLastCoinStakeSearchInterval = 0;
 
// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

std::map<std::string,int64> getGenesisBalances(){
	std::map<std::string,int64> genesisBalances;
	// NRS + GF shares
	ifstream myfile ("genesisbalances.txt");
	char * pEnd;
	std::string line;
	if (myfile.is_open()){
		while ( myfile.good() ){
			getline (myfile,line);
			std::vector<std::string> strs;
			boost::split(strs, line, boost::is_any_of(","));
			genesisBalances[strs[0]]=strtoll(strs[1].c_str(),&pEnd,10);
		}
		myfile.close();
	}	
	return genesisBalances;
}

// CreateNewBlock:
//   fProofOfStake: try (best effort) to make a proof-of-stake block
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake)
{
    CReserveKey reservekey(pwallet);

    // Create new block
    auto_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
        return NULL;

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    printf("Create Block, %d\n",pindexBest->nHeight+1); 
    
    if(pindexBest->nHeight+1==25){
	//Block 25 - add balances for Shareholders and NRS 
    	std::map<std::string,int64> genesisBalances= getGenesisBalances();
	std::map<std::string,int64>::iterator balit;
	int i=1;
	int64 total=0;
	txNew.vout.resize(genesisBalances.size()+1);
	for(balit=genesisBalances.begin(); balit!=genesisBalances.end(); ++balit){
		//printf("gb:%s,%llu",balit->first.c_str(),balit->second);
		CBitcoinAddress address(balit->first);
		txNew.vout[i].scriptPubKey.SetDestination( address.Get() );
		txNew.vout[i].nValue = balit->second;
		total=total+balit->second;
		i++;
	}
	printf("Total ...%llu\n",total);  
	} 
	{
    LOCK(grantdb);
    //For grant award block, add grants to coinbase
    if(isGrantAwardBlock(pindexBest->nHeight+1)){
		if(!getGrantAwards(pindexBest->nHeight+1)){
			 throw std::runtime_error("ConnectBlock() : ConnectBlock grant awards error");
		}
	printf("Got grant awards, now to add - Block %d\n", pindexBest->nHeight+1);
	txNew.vout.resize(1+grantAwards.size());
		    
	int i=0;
	for(gait=grantAwards.begin(); gait!=grantAwards.end(); ++gait){
		printf("Add %s %llu\n",gait->first.c_str(),gait->second);
	
		CBitcoinAddress address(gait->first);
		txNew.vout[i+1].scriptPubKey.SetDestination( address.Get() );
		txNew.vout[i+1].nValue = gait->second;
		i++;		
	}
    }
    }
    
    printf("After grant ...\n");
	
    txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64 nMinTxFee = MIN_TX_FEE;
    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    // ppcoin: if coinstake available add coinstake tx
    static int64 nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
    CBlockIndex* pindexPrev = pindexBest;

    if (fProofOfStake)  // attempt to find a coinstake
    {
        pblock->nBits = GetNextTargetRequired(pindexPrev, true);
        CTransaction txCoinStake;
        int64 nSearchTime = txCoinStake.nTime; // search to current time
        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            // printf(">>> OK1\n");
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake))
            {
                if (txCoinStake.nTime >= max(pindexPrev->GetMedianTimePast()+1, pindexPrev->GetBlockTime() - nMaxClockDrift))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    pblock->vtx[0].vout[0].SetEmpty();
                    pblock->vtx[0].nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(txCoinStake);
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
    }

    pblock->nBits = GetNextTargetRequired(pindexPrev, pblock->IsProofOfStake());

    // Collect memory pool transactions into the block
    int64 nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = pindexBest;
        CTxDB txdb("r");

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64 nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                CTransaction txPrev;
                CTxIndex txindex;
                if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = txindex.GetDepthInMainChain();
                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        map<uint256, CTxIndex> mapTestPool;
        uint64 nBlockSize = 1000;
        uint64 nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime() || (pblock->IsProofOfStake() && tx.nTime > pblock->vtx[1].nTime))
                continue;

            // ppcoin: simplify transaction fee - allow free = false
            int64 nMinFee = tx.GetMinFee(nBlockSize, false, GMF_BLOCK);

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // Connecting shouldn't fail due to dependency on other memory pool transactions
            // because we're already processing them in order of dependency
            map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
            MapPrevTx mapInputs;
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
                continue;

            int64 nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
            if (nTxFees < nMinFee)
                continue;

            nTxSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            if (!tx.ConnectInputs(txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true))
                continue;
            mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fDebug && GetBoolArg("-printpriority"))
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }


        int64 feesFromPayout=0;
        int64 ncfeesFromPayout=0;

        //This adds the required payouts if the block includes a payout transaction
        checkForPayouts(pblock->vtx,feesFromPayout,ncfeesFromPayout,true,false,pindexPrev->nHeight+1);

        nFees=nFees+(feesFromPayout>>PRIZEPAYMENTCOMMISSIONS);

        nFees=nFees+(calculateTicketIncome(pblock->vtx)>>TICKETCOMMISSIONRATE);

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        if (fDebug && GetBoolArg("-printpriority"))
            printf("CreateNewBlock(): total size %"PRI64u"\n", nBlockSize);

	// coinbase output value will be determined randomized way during mining, so store only nFees to be added to randomized amount
        if (pblock->IsProofOfWork())
//            pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pindexPrev->nHeight+1, nFees, pindexPrev->GetBlockHash());
            pblock->vtx[0].vout[0].nValue = nFees;


        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        if (pblock->IsProofOfStake())
            pblock->nTime      = pblock->vtx[1].nTime; //same as coinstake timestamp
        pblock->nTime          = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
        pblock->nTime          = max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
        if (pblock->IsProofOfWork())
            pblock->UpdateTime(pindexPrev);
        pblock->nNonce         = 0;
    }

    return pblock.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
            uint256 hashRandomSeed;
            unsigned int nBirthdayA;
            unsigned int nBirthdayB;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;
    tmp.block.hashRandomSeed = pblock->hashRandomSeed;
    tmp.block.nBirthdayA     = pblock->nBirthdayA;
    tmp.block.nBirthdayB     = pblock->nBirthdayB;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    //FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    //for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
      //  ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    //SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
   // memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
//    uint256 hash = pblock->GetVerifiedHash();
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();


    if (hash > hashTarget)
    {
         fprintf( stderr, "hash %s > %s\n", hash.ToString().c_str(), hashTarget.ToString().c_str() );
          return false;
     }
     fprintf( stderr, "hash %s < %s\n", hash.ToString().c_str(), hashTarget.ToString().c_str() );
     
    //// debug print
    printf("BitcoinMiner:\n");
    printf("new block found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("BitcoinMiner : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("BitcoinMiner : ProcessBlock, block not accepted");
    }

    return true;
}

void static ThreadBitcoinMiner(void* parg);

static bool fGenerateBitcoins = false;
static bool fLimitProcessors = false;
static int nLimitProcessors = -1;

void BitcoinMiner(CWallet *pwallet, bool fProofOfStake)
{
    
    printf("CPUMiner started for proof-of-%s\n", fProofOfStake? "stake" : "work");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("bitcoin-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    while (fGenerateBitcoins || fProofOfStake)
    {
        if (fShutdown)
            return;
        while (vNodes.empty() || IsInitialBlockDownload())
        {
            Sleep(1000);
            if (fShutdown)
                return;
            if ((!fGenerateBitcoins) && !fProofOfStake)
                return;
        }

        while (pwallet->IsLocked())
        {
            strMintWarning = strMintMessage;
            Sleep(1000);
        }
        strMintWarning = "";

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;

        auto_ptr<CBlock> pblock(CreateNewBlock(pwallet, fProofOfStake));
        if (!pblock.get())
            return;
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

        if (fProofOfStake)
        {
            // ppcoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                if (!pblock->SignBlock(*pwalletMain))
                {
                    strMintWarning = strMintMessage;
                    continue;
                }
                strMintWarning = "";
                printf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str()); 
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                CheckWork(pblock.get(), *pwalletMain, reservekey);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
            }
            Sleep(500);
            continue;
        }

        printf("Running BitcoinMiner with %"PRIszu" transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock.get(), pmidstate, pdata, phash1);

        unsigned int& nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);


        //
        // Search
        //
        int64 nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        //uint256 hashbuf[2];
        //uint256& hash = *alignup<16>(hashbuf);
        uint256 testHash;
	int64 nFees = pblock->vtx[0].vout[0].nValue;
        for (;;)
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound = (unsigned int) -1;

		pblock->nNonce=pblock->nNonce+1;
		while (!pblock->GenerateRandomSeed()) 
		{
			pblock->nNonce=pblock->nNonce+1;
		}
		// Amount calculation
		pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pindexPrev->nHeight+1, nFees, pblock->hashRandomSeed);
printf("Gen Amt Rewd A: %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());
		// Rebuild merkle tree
		pblock->hashMerkleRoot = pblock->BuildMerkleTree();
		// Generate final stage hash
		testHash=pblock->GetHash();
		nHashesDone++;
		printf("testHash %s\n", testHash.ToString().c_str());
		printf("Hash Target %s\n", hashTarget.ToString().c_str());
		// Check final stage hash against target
		if(testHash<hashTarget){
			nNonceFound=pblock->nNonce;
			printf("Found Hash %s\n", testHash.ToString().c_str());
		}

            // Check if something found
            if (nNonceFound != (unsigned int) -1)
            {
                //for (unsigned int i = 0; i < sizeof(hash)/4; i++)
               //((unsigned int*)&hash)[i] = ByteReverse(((unsigned int*)&hash)[i]);

                if (testHash <= hashTarget)
                {
                    // Found a solution
                    //pblock->nNonce = ByteReverse(nNonceFound);
                    printf("hash %s\n", testHash.ToString().c_str());
					printf("hash2 %s\n", pblock->GetHash().ToString().c_str());
                    assert(testHash == pblock->GetHash());

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock.get(), *pwalletMain, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
                }
            }

            // Meter hashes/sec
            static int64 nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000*60)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000*60)
                    {
                        dhashespermin = 1000.0 * nHashCounter*60 / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64 nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            printf("hashmeter %3d CPUs %6.0f khash/s\n", vnThreadsRunning[THREAD_MINER], dhashespermin/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
            if (fLimitProcessors && vnThreadsRunning[THREAD_MINER] > nLimitProcessors)
                return;
            if (vNodes.empty())
                break;
            if (nBlockNonce >= 0xffff0000)
                break;
            if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pindexBest)
                break;

            // Update nTime every few seconds
            pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
            pblock->UpdateTime(pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);

            if (pblock->GetBlockTime() >= (int64)pblock->vtx[0].nTime + nMaxClockDrift)
                break;  // need to update coinbase timestamp
        }
    }
}

void static ThreadBitcoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        vnThreadsRunning[THREAD_MINER]++;
        BitcoinMiner(pwallet, false);
        vnThreadsRunning[THREAD_MINER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_MINER]--;
        PrintException(&e, "ThreadBitcoinMiner()");
    } catch (...) {
        vnThreadsRunning[THREAD_MINER]--;
        PrintException(NULL, "ThreadBitcoinMiner()");
    }
    nHPSTimerStart = 0;
    if (vnThreadsRunning[THREAD_MINER] == 0)
        dhashespermin = 0;
    printf("ThreadNoirMiner exiting, %d threads remaining\n", vnThreadsRunning[THREAD_MINER]);
}


void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    fGenerateBitcoins = fGenerate;
    nLimitProcessors = GetArg("-genproclimit", -1);
    if (nLimitProcessors == 0)
        fGenerateBitcoins = false;
    fLimitProcessors = (nLimitProcessors != -1);

    if (fGenerate)
    {
        int nProcessors = boost::thread::hardware_concurrency();
        printf("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (fLimitProcessors && nProcessors > nLimitProcessors)
            nProcessors = nLimitProcessors;
        int nAddThreads = nProcessors - vnThreadsRunning[THREAD_MINER];
        printf("Starting %d BitcoinMiner threads\n", nAddThreads);
        for (int i = 0; i < nAddThreads; i++)
        {
            if (!NewThread(ThreadBitcoinMiner, pwallet))
                printf("Error: NewThread(ThreadBitcoinMiner) failed\n");
            Sleep(10);
        }
	}
}
//Grant every 4 hours
static const int64 GRANTBLOCKINTERVAL = (4*60*60)/nTargetSpacing;
static string GRANTPREFIX ="NGO";


static int numberOfOffices = 6;
string electedOffices[7];
//= {"ceo","cdo","cfo","cmo","coo","cbf","XFT"};
//= Current Shareholders 
//Chief Executive Officer
//Chief Development Officer
//Chief Operations Officer
//Chief Marketing Officer
//Chief Finance Officer
//Charitable Donation


//Implement in memory for now - this will cause slow startup as recalculation of all votes takes place every startup. 
//These should be persisted in a database or on disk
int64 grantDatabaseBlockHeight=-1; //How many blocks processed for grant allocation purposes
std::map<std::string,int64> balances; //Balances as at grant allocation block point
std::map<std::string,std::map<int64,std::string> > votingPreferences[7]; //Voting prefs as at grant allocation block point



//These do not need to persist. They are necessarily rebuilt when required
CBlockIndex* gdBlockPointer = NULL;
std::map<std::string,std::map<int64, std::string> >::iterator ballotit;
std::map<std::string,std::map<int64, std::string> > ballots;
//std::map<std::string,std::map<int64, std::string> > newBallotObject;
std::map<std::string,int64 > ballotBalances;
std::map<std::string,double > ballotWeights;
std::map<int64, std::string>::iterator svpit;
ofstream grantAwardsOutput;
bool debugVote = false;
bool debugVoteExtra = false;
std::map<std::string, int64>::iterator svpit3;
std::map<int64, std::string>::iterator svpit4;
std::map<std::string,int64>::iterator it;
std::map<int64,std::string>::iterator it2;

std::map<std::string,std::map<int64,std::string> >::iterator vpit;

std::map<std::string,int64 > wastedVotes; //Report on Votes that were wasted
std::map<std::string,std::map<int64,std::string> > electedVotes; //Report on where votes went 
std::map<std::string,std::map<int64,std::string> > supportVotes; //Report on support for candidates

int64 getNUMBEROFAWARDS(int64 blockNumber){
		return 1;
}

bool isGrantAwardBlock(int64 nHeight){
	if(nHeight%GRANTBLOCKINTERVAL ==0 && nHeight!=0 && nHeight!=GRANTBLOCKINTERVAL){
		return true;
	}
	return false;	
}


void serializeGrantDB(string filename){
		printf("Serialize Grant Info Database %llu\n",grantDatabaseBlockHeight);
		ofstream grantdb;
		grantdb.open (filename.c_str(), ios::trunc);
		
		//grantDatabaseBlockHeight
		grantdb << grantDatabaseBlockHeight << "\n";
		
		//Balances
		grantdb << balances.size()<< "\n";
		for(it=balances.begin(); it!=balances.end(); ++it){
			grantdb << it->first << "\n" << it->second<< "\n";
		}
		
		//votingPreferences
        for(int i=0;i<numberOfOffices;i++){
            grantdb << votingPreferences[i].size()<< "\n";
            for(vpit=votingPreferences[i].begin(); vpit!=votingPreferences[i].end(); ++vpit){
                grantdb << vpit->first << "\n";
                grantdb << vpit->second.size() << "\n";
                for(it2=vpit->second.begin();it2!=vpit->second.end();++it2){
                    grantdb << it2->first << "\n" << it2->second<< "\n";
                }
            }
        }

		grantdb.flush();
		grantdb.close();
}

bool deSerializeGrantDB(string filename, int64 maxWanted){

	printf("DeSerialize Grant Info Database\n");
	
	std::string line;
	std::string line2;
	ifstream myfile;
	
	myfile.open (filename.c_str());	
	//ifstream myfile ("grantsdb.dat");
	if (myfile.is_open()){
		getline (myfile,line);
		grantDatabaseBlockHeight=atoi64(line.c_str());
		printf("Deserialize Grant Info Database Found Height %llu\n",grantDatabaseBlockHeight);
		
        if(grantDatabaseBlockHeight>maxWanted){
            //vote database later than required - don't load
            grantDatabaseBlockHeight=-1;
            myfile.close();
            return false;
        }

		//Balances
		balances.clear();
		getline (myfile,line);
		int64 balancesSize=atoi64(line.c_str());
		for(int i=0;i<balancesSize;i++){
			getline (myfile,line);
			getline (myfile,line2);
			balances[line]=atoi64(line2.c_str());
		}
		
		//votingPreferences
        for(int i=0;i<numberOfOffices;i++){
            votingPreferences[i].clear();
            getline (myfile,line);
            int64 votingPreferencesSize=atoi64(line.c_str());
            for(int k=0;k<votingPreferencesSize;k++){
                getline (myfile,line);
                std::string vpAddress=line;
                getline (myfile,line);
                int64 vpAddressSize=atoi64(line.c_str());
			
                for(int j=0;j<vpAddressSize;j++){
                    getline (myfile,line);
                    getline (myfile,line2);
                    votingPreferences[i][vpAddress][atoi64(line.c_str())]=line2;
                }
		
            }
        }
				
		myfile.close();
		
		//Set the pointer to next block to process
		gdBlockPointer=pindexGenesisBlock;
		for(int i=0;i<grantDatabaseBlockHeight;i++){
            if(gdBlockPointer->pnext==NULL){
                printf("Insufficent number of blocks loaded %s\n",filename.c_str());
                return false;
            }
			gdBlockPointer=gdBlockPointer->pnext;
		}
		return true;
	}else{
		printf("Could not load Grant Info Database from %s\n",filename.c_str());
		return false;
	}

}


bool getGrantAwards(int64 nHeight){
	//nHeight is the current block height
	if(!isGrantAwardBlock(nHeight)){
		printf("Error - calling getgrantawards for non grant award block");
		return false;
	}
	return ensureGrantDatabaseUptoDate(nHeight);
}

bool ensureGrantDatabaseUptoDate(int64 nHeight){

    //This should always be true on startup
    if(getGrantDatabaseBlockHeight()==-1){
        string newCV="xxx";
        //Only count custom vote if re-indexing
        if(GetBoolArg("-reindex"),false){
            newCV=GetArg("-customvoteprefix",newCV);
            printf("customvoteprefix:%s\n",newCV.c_str());
        }
        electedOffices[0]="ceo";
        electedOffices[1]="cdo";
        electedOffices[2]="cfo";
        electedOffices[3]="cmo";
        electedOffices[4]="coo";
        electedOffices[5]="cbf";
        electedOffices[6]=newCV;
    }

    //nHeight is the current block height
    //requiredgrantdatabaseheight is 20 less than the current block
    int64 requiredGrantDatabaseHeight=nHeight-GRANTBLOCKINTERVAL;
    printf("Ensure grant database up to date %llu\n",requiredGrantDatabaseHeight);

    //Maybe we don't have to count votes from the start - let's check if there's a recent vote database stored
    if(getGrantDatabaseBlockHeight()==-1){
        deSerializeGrantDB((GetDataDir() / "blocks/grantdb.dat").string().c_str(),requiredGrantDatabaseHeight);
        //printf("deserialized vote database:\n");
    }

    /*
    if(getGrantDatabaseBlockHeight()>requiredGrantDatabaseHeight){
        printf("Grant database has processed too many blocks. Needs to be rebuilt. %llu",nHeight);
        balances.clear();
        for(int i=0;i<numberOfOffices+1;i++){
            votingPreferences[i].clear();
        }
        gdBlockPointer=pindexGenesisBlock;
        grantDatabaseBlockHeight=-1;
    }*/
	
    while(getGrantDatabaseBlockHeight()<requiredGrantDatabaseHeight){
        processNextBlockIntoGrantDatabase();
    }
    return true;
		
}





int64 getGrantDatabaseBlockHeight(){
	return grantDatabaseBlockHeight;
}


int getOfficeNumberFromAddress(string grantVoteAddress, int64 nHeight){
	if (!startsWith(grantVoteAddress.c_str(),GRANTPREFIX.c_str())){
		return -1;
	}
    for(int i=0;i<numberOfOffices+1;i++){
		//printf("substring %s\n",grantVoteAddress.substr(4,3).c_str());
		if(grantVoteAddress.substr(4,3)==electedOffices[i]){
			return i;
		}
	}
	return -1;
}

void printVotingPrefs(std::string address){
    //I don't know why, this is compiling, but crashing
    /*std::map<int64, std::string> thisBallot=ballots.find(address)->second;
    if(thisBallot.begin()==thisBallot.end()){
        printf("No Voting Preferences\n");
        return;
    }
    int pref=1;
    for(svpit4=thisBallot.begin();svpit4!=thisBallot.end();++svpit4){
        printf("Preference: (%d) %llu %s \n",pref, svpit4->first/COIN,svpit4->second.c_str());
        pref++;
    }*/

    //This is slow and iterates too much, but on the plus side it doesn't crash the program.
    //This crash probably caused by eliminate candidate corrupting the ballot structure.
    //Should be safe to use more efficient code after fork
    int pref=1;
    for(ballotit=ballots.begin(); ballotit!=ballots.end(); ++ballotit){
        if(address==ballotit->first){
            for(svpit4=ballotit->second.begin();svpit4!=ballotit->second.end();++svpit4){
                grantAwardsOutput<<"--Preference "<<pref<<" "<<svpit4->first<<" "<<svpit4->second.c_str()<<" \n";
                pref++;
            }
        }
    }

}

void processNextBlockIntoGrantDatabase(){

	//printf("processNextBlockIntoGrantDatabase %d\n",grantDatabaseBlockHeight+1);
	
	CBlock block;
	
	//If it's the first block, we'll start with the Genesis Block
	if(gdBlockPointer==NULL){
		gdBlockPointer=pindexGenesisBlock;
	}else{
		gdBlockPointer=gdBlockPointer->pnext;
	}
	block.ReadFromDisk(gdBlockPointer);
	//ReadBlockFromDisk(block, gdBlockPointer);
        //block.ReadFromDisk(gdBlockPointer,true); //Litecoin codebase method
	
	
	//Look at all transactions in the block to update balances and see if they contain voting preferences
	for (unsigned int i = 0; i <block.vtx.size(); i++){
		
		std::map<std::string,int64 > votes;
		std::map<std::string,int64 >::iterator votesit;
		
		//Deal with outputs first - increase balances and note what the votes are
		for (unsigned int j = 0; j <block.vtx[i].vout.size(); j++){
			CTxDestination address;
			ExtractDestination(block.vtx[i].vout[j].scriptPubKey,address);
			
			string receiveAddress=CBitcoinAddress(address).ToString().c_str();
			int64 theAmount=block.vtx[i].vout[j].nValue;
			
			//Update balance - if no previous balance, should start at 0
			balances[receiveAddress]=balances[receiveAddress]+theAmount;				
			
			//Note any voting preferences made in the outputs
			if(startsWith(receiveAddress.c_str(),(GRANTPREFIX).c_str()) && theAmount<10 && theAmount>0){
				//printf("Vote found Amount: %llu\n",theAmount);
				//Voting output - if the same address is voted a number of times in the same transaction, only the last one is counted
				votes[receiveAddress]=theAmount;
			}			
		}
		
		//Deal with the inputs - reduce balances and apply voting preferences noted in the outputs
		for (unsigned int j = 0; j <block.vtx[i].vin.size(); j++){
			if(block.vtx[i].IsCoinBase()){
				//This is a coinbase transaction, there is no input to reduce
			}else{
				CTransaction txPrev;
				uint256 hashBlock;
				GetTransaction(block.vtx[i].vin[j].prevout.hash,txPrev,hashBlock);
				CTxDestination source;
				ExtractDestination(txPrev.vout[block.vtx[i].vin[j].prevout.n].scriptPubKey,source);			
				string spendAddress=CBitcoinAddress(source).ToString().c_str();
				int64 theAmount=txPrev.vout[block.vtx[i].vin[j].prevout.n].nValue;
				
				//Reduce balance
				balances[spendAddress]=balances[spendAddress]-theAmount;
	
				//If any of the outputs were votes
				for(votesit=votes.begin(); votesit!=votes.end(); ++votesit){
                    printf("Vote found: %s, %llu\n",votesit->first.c_str(),votesit->second);
					string grantVoteAddress=(votesit->first);
					int electedOfficeNumber = getOfficeNumberFromAddress(grantVoteAddress, gdBlockPointer->nHeight);
					if(electedOfficeNumber>-1){
                        printf("Vote added: %d %s, %llu\n",electedOfficeNumber,votesit->first.c_str(),votesit->second);
                        votingPreferences[electedOfficeNumber][spendAddress][votesit->second] = grantVoteAddress;
                        printf("Size: %lu \n",votingPreferences[electedOfficeNumber].size());
                    }
				}
	
			}
		}
	}
	
	grantDatabaseBlockHeight++;
	
	if(isGrantAwardBlock(grantDatabaseBlockHeight+GRANTBLOCKINTERVAL)){
		getGrantAwardsFromDatabaseForBlock(grantDatabaseBlockHeight+GRANTBLOCKINTERVAL);
		//Save the grant database to disk - these need to be persisted
        serializeGrantDB((GetDataDir() / "blocks/grantdb.dat").string().c_str());

        //check deserialization is working
        //deSerializeGrantDB((GetDataDir() / "blocks/grantdb.dat").string().c_str());
		//printf("2 current block on:%llu\n",gdBlockPointer->GetBlockHash());
		
	}
}


void printCandidateSupport(){
	std::map<int64,std::string>::reverse_iterator itpv2;
	
	grantAwardsOutput<<"\nWinner Support: \n";
		
	for(ballotit=supportVotes.begin(); ballotit!=supportVotes.end(); ++ballotit){
		grantAwardsOutput<<"\n--"<<ballotit->first<<" \n";
		for(itpv2=ballotit->second.rbegin();itpv2!=ballotit->second.rend();++itpv2){
            grantAwardsOutput<<"-->("<< itpv2->first/COIN <<"/"<<balances[itpv2->second.c_str()]/COIN <<") "<<itpv2->second.c_str()<<" \n";
		}		
	}
}

void printBalances(int64 howMany, bool printVoting, bool printWasted){
	grantAwardsOutput<<"---Current Balances------\n";
	std::multimap<int64, std::string > sortByBalance;
	
	std::map<std::string,int64>::iterator itpv;
	std::map<int64,std::string>::reverse_iterator itpv2;
	
	for(itpv=balances.begin(); itpv!=balances.end(); ++itpv){
		//int amt=(it->second)/COIN;
		//sortByBalance[it->second]=it->first;
		if(itpv->second>COIN){
			sortByBalance.insert(pair<int64, std::string>(itpv->second,itpv->first));
		}
	}
	
	//printf("%d addresses with balances. Printing Top %d\n",balances.size(),howMany);
	
	std::multimap<int64, std::string >::reverse_iterator sbbit;
	int64 count=0;
	for (sbbit =  sortByBalance.rbegin(); sbbit !=  sortByBalance.rend();++sbbit){
		if(howMany>count){
			grantAwardsOutput<<"\n->Balance:"<<sbbit->first/COIN<<" - "<<sbbit->second.c_str()<<"\n";
			if(printWasted){
				for(itpv2=electedVotes[sbbit->second.c_str()].rbegin(); itpv2!=electedVotes[sbbit->second.c_str()].rend(); ++itpv2){
					grantAwardsOutput << "---->" << itpv2->first/COIN << " supported " << itpv2->second << "\n";		
				}
				if(wastedVotes[sbbit->second.c_str()]/COIN>0){
					grantAwardsOutput<<"---->"<<wastedVotes[sbbit->second.c_str()]/COIN<<"  wasted (Add More Preferences)\n";
				}
				if(votingPreferences[0].find(sbbit->second.c_str())==votingPreferences[0].end()){
					grantAwardsOutput<<"---->No Vote: (Add Some Voting Preferences)\n";
				}
			}
			
			if(printVoting){
				try{
					printVotingPrefs(sbbit->second);
				}catch (std::exception &e) {
					grantAwardsOutput<<"Print Voting Prefs Exception\n";
				}
			}
			count++;
		}
	}
	grantAwardsOutput<<"---End Balances------\n";
}


bool getGrantAwardsFromDatabaseForBlock(int64 nHeight){
	
    printf("getGrantAwardsFromDatabase %llu\n",nHeight);
	if(grantDatabaseBlockHeight!=nHeight-GRANTBLOCKINTERVAL){
        printf("getGrantAwardsFromDatabase is being call when no awards are due. %llu %llu\n",grantDatabaseBlockHeight,nHeight);
		return false;
	}
	
	debugVote = GetBoolArg("-debugvote", false);
	if(debugVote){
		std::stringstream sstm;
		sstm << "award" << setw(8) << std::setfill('0') << nHeight << ".txt";
		string filename = sstm.str();
		//printf("%s\n",filename.c_str());
		//mkdir((GetDataDir() / "grantawards").string().c_str());
		mkdir((GetDataDir() / "grantawards").string().c_str()
#ifndef _WIN32
		,S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
#endif
		);
		grantAwardsOutput.open ((GetDataDir() / "grantawards" / filename).string().c_str(), ios::trunc);}
	//save to disk
	
	if(debugVote)grantAwardsOutput << "-------------:\nElection Count:\n-------------:\n\n";
	
	//Clear from last time, ensure nothing left over

	awardWinners.clear();
	grantAwards.clear();

		
for(int i=0;i<numberOfOffices+1;i++){
	ballots.clear();
	ballotBalances.clear();
	ballotWeights.clear();
	wastedVotes.clear();
	electedVotes.clear();
	supportVotes.clear();
	
	//Iterate through every vote
	for(vpit=votingPreferences[i].begin(); vpit!=votingPreferences[i].end(); ++vpit){
		int64 voterBalance=balances[vpit->first];
		//Ignore balances of 0 - they play no part.
		if(voterBalance>0){
			ballotBalances[vpit->first]=voterBalance;
			ballotWeights[vpit->first]=1.0;
			
			//Order preferences by coins sent - lowest number of coins has top preference
			for(it2=vpit->second.begin(); it2!=vpit->second.end(); ++it2){
				//Where a voter has voted for more than one preference with the same amount, only the last one (alphabetically) will be valid. The others are discarded.
				ballots[vpit->first][it2->first]=it2->second;
			}
		}else if (voterBalance<0){
			printf("Something wrong here - balance is less than zero - this should never occur\n");
			printf("Voter: %s %llu\n",vpit->first.c_str(),voterBalance);
		}
	}

    //if(debugVote)printBalances(100,true,false);
	getWinnersFromBallots(nHeight,i);

	//At this point, we know the vote winners - now to see if grants are to be awarded - note nheight is the current blockheight
    if(i<numberOfOffices){
        for(int i=0;i<getNUMBEROFAWARDS(nHeight);i++){
            grantAwards[awardWinners[i]]=grantAwards[awardWinners[i]]+GetGrantValue(nHeight);
            if(debugVote)grantAwardsOutput << "Add grant award to Block "<<awardWinners[i].c_str()<<" ("<<GetGrantValue(nHeight)/COIN<<")\n";
        }
    }
	if(debugVote)printCandidateSupport();
	
}	


	//if(debugVote)printBalances(100,false,true);
	if(debugVote){grantAwardsOutput.close();}
	return true;
}

void getWinnersFromBallots(int64 nHeight, int officeNumber){

	if(debugVote)grantAwardsOutput <<"\n\n\n--------"<< electedOffices[officeNumber]<<"--------\n";
	
	
	if(debugVoteExtra)printBallots();
	
	//Calculate Total in all balances
	int64 tally=0;
	for(it=balances.begin(); it!=balances.end(); ++it){
		tally=tally+it->second;
	}
	if(debugVote)grantAwardsOutput <<"Total coin issued: " << tally/COIN <<"\n";

	//Calculate Total of balances of voters
	int64 totalOfVoterBalances=0;
	for(it=ballotBalances.begin(); it!=ballotBalances.end(); ++it){
		totalOfVoterBalances=totalOfVoterBalances+it->second;
	}
	if(debugVote)grantAwardsOutput <<"Total of Voters' Balances: "<<totalOfVoterBalances/COIN<<"\n";
	
	//Turnout
	if(debugVote)grantAwardsOutput <<"Percentage of total issued coin voting: "<<(totalOfVoterBalances*100)/tally<<" percent\n";
	
	//Calculate Droop Quota
	int64 droopQuota = (totalOfVoterBalances/(getNUMBEROFAWARDS(nHeight)+1))+1;
	if(debugVote)grantAwardsOutput <<"Droop Quota: "<<droopQuota/COIN<<"\n";
	
	
	
	//Conduct voting rounds until all grants are awarded
	for(int i=getNUMBEROFAWARDS(nHeight);i>0;i--){
		string electedCandidate;
		int voteRoundNumber=0;
		if(debugVote)grantAwardsOutput <<"-------------:\nRound:"<<getNUMBEROFAWARDS(nHeight)-i<<"\n";
		if(debugVoteExtra)printBallots();
		do{
			//if(debugVote)grantAwardsOutput <<"-------------:\nElimination Round:%d\n",voteRoundNumber);
			electedCandidate=electOrEliminate(droopQuota, i);
			voteRoundNumber++;
		}while(electedCandidate=="");
		awardWinners[(i-getNUMBEROFAWARDS(nHeight))*-1]=electedCandidate;
	}
	//if(debugVote)grantAwardsOutput <<"--------End Grant Voting--------\n";
	
}

//Sum total of first preferences
std::map<std::string,int64 > preferenceCount;
int64 numberCandidatesEliminated=0;	
		
string	electOrEliminate(int64 droopQuota, unsigned int requiredCandidates){

	std::map<std::string,int64 >::iterator tpcit;
	
	
	
	//Recalculate the preferences each time as winners and losers are removed from ballots.
	preferenceCount.clear();
	
	//Calculate support for each candidate. The balance X the weighting for each voter is applied to the total for the candidate currently at the top of the voter's ballot  
	for(ballotit=ballots.begin(); ballotit!=ballots.end(); ++ballotit){
		//Check: Multiplying int64 by double here, and representing answer as int64.
		preferenceCount[ballotit->second.begin()->second]+=(ballotBalances[ballotit->first]*ballotWeights[ballotit->first]);
	}
	
	//if(debugVote)grantAwardsOutput <<"Number of Remaining Candidates: %d\n",preferenceCount.size());
	
	//Find out which remaining candidate has the greatest and least support
	string topOfThePoll;
	int64 topOfThePollAmount=0;	
	string bottomOfThePoll;
	int64 bottomOfThePollAmount=9223372036854775807;

		
	for(tpcit=preferenceCount.begin(); tpcit!=preferenceCount.end(); ++tpcit){
		//Check:When competing candidates have equal votes, the first (sorted by Map) will be chosen for top and bottom of the poll.
		if(tpcit->second>topOfThePollAmount){
			topOfThePollAmount=tpcit->second;
			topOfThePoll=tpcit->first;
		}
		if(tpcit->second<bottomOfThePollAmount){
			bottomOfThePollAmount=tpcit->second;
			bottomOfThePoll=tpcit->first;
		}
		//if(tpcit->second>droopQuota/10){
		//	if(debugVote)grantAwardsOutput <<"Support: "<<tpcit->first<<"("<<tpcit->second/COIN<<")\n";
		//}
		
	}
	
	//Purely for debugging/information
	if(topOfThePollAmount>=droopQuota || requiredCandidates>=preferenceCount.size() ||bottomOfThePollAmount>droopQuota/10){
		if(debugVote)grantAwardsOutput <<"Candidates with votes equalling more than 10% of Droop quota\n";
		for(tpcit=preferenceCount.begin(); tpcit!=preferenceCount.end(); ++tpcit){
			if(tpcit->second>droopQuota/10){
				if(debugVote)grantAwardsOutput <<"Support: "<<tpcit->first<<" ("<<tpcit->second/COIN<<")\n";
			}
		
		}
	}
	
	//if(debugVote)grantAwardsOutput <<"Bottom Preference Votes: %s %llu\n",bottomOfThePoll.c_str(),bottomOfThePollAmount/COIN);
	
	if(topOfThePollAmount==0){
		//No ballots left -end - 
		if(debugVote)grantAwardsOutput <<"No Candidates with support remaining. Grant awarded to unspendable address MVTEceo1111111111111111111111TvNrt\n";
		return "MVTEceo1111111111111111111111TvNrt";
	}
	
	if(topOfThePollAmount>=droopQuota || requiredCandidates>=preferenceCount.size()){
		
		//Note: This is a simplified Gregory Transfer Value - ignoring ballots where there are no other hopefuls.
		double gregorySurplusTransferValue=((double)topOfThePollAmount-(double)droopQuota)/(double)topOfThePollAmount;
		
		//Don't want this value to be negative when candidates are elected with less than a quota
		if(gregorySurplusTransferValue<0){gregorySurplusTransferValue=0;}
		
		electCandidate(topOfThePoll,gregorySurplusTransferValue,(requiredCandidates==1));
		//if(debugVote)grantAwardsOutput <<"Top Preference Votes: %s %llu\n",topOfThePoll.c_str(),topOfThePollAmount/COIN);	
		if(debugVote){
			if(numberCandidatesEliminated>0){
				grantAwardsOutput <<"Candidates Eliminated ("<<numberCandidatesEliminated<<")\n\n";
				numberCandidatesEliminated=0;
			}
			grantAwardsOutput <<"Candidate Elected: "<<topOfThePoll.c_str()<<" ("<<topOfThePollAmount/COIN<<")\n";
			grantAwardsOutput <<"Surplus Transfer Value: "<<gregorySurplusTransferValue<<"\n";				
		}
		return topOfThePoll;
		
	}else{
		eliminateCandidate(bottomOfThePoll,false);
		if(debugVote){
			if(bottomOfThePollAmount>droopQuota/10){
				if(numberCandidatesEliminated>0){
					grantAwardsOutput <<"Candidates Eliminated ("<<numberCandidatesEliminated<<")\n";
					numberCandidatesEliminated=0;
				}
				grantAwardsOutput <<"Candidate Eliminated: "<<bottomOfThePoll.c_str()<<" ("<<bottomOfThePollAmount/COIN<<")\n\n";
			}else{
				numberCandidatesEliminated++;
			}
		
		}
		return "";
	}	
	
	
}

std::map<int64, std::string>::iterator svpit2;

void electCandidate(string topOfThePoll, double gregorySurplusTransferValue,bool isLastCandidate){
	
	//Apply fraction to weights where the candidate was top of the preference list
	for(ballotit=ballots.begin(); ballotit!=ballots.end(); ++ballotit){
		svpit2=ballotit->second.begin();
		if(svpit2->second==topOfThePoll){
			//Record how many votes went towards electing this candidate for each user
			electedVotes[ballotit->first][balances[ballotit->first]*(ballotWeights[ballotit->first]*(1-gregorySurplusTransferValue))]=svpit2->second;
			//Record the support for each candidate elected
			supportVotes[topOfThePoll][balances[ballotit->first]*(ballotWeights[ballotit->first]*(1-gregorySurplusTransferValue))]=ballotit->first;
			
			//This voter had the elected candidate at the top of the ballot. Adjust weight for future preferences.
			ballotWeights[ballotit->first]=ballotWeights[ballotit->first]*gregorySurplusTransferValue;
		}
	}
	
	//Remove candidate from all ballots - this includes where he may be far down the list of preferences
	eliminateCandidate(topOfThePoll,isLastCandidate);
}

void eliminateCandidate(string removeid,bool isLastCandidate){
	
	
	std::map<std::string, int64> ballotsToRemove;
	std::map<std::string, int64>::iterator btrit;
	
	//Remove candidate from all ballots - note the candidate may be way down the preference list
	for(ballotit=ballots.begin(); ballotit!=ballots.end(); ++ballotit){
		int64 markForRemoval=0;
			
		for(svpit2=ballotit->second.begin();svpit2!=ballotit->second.end();++svpit2){
			if(svpit2->second==removeid){
				//if(debugVote)grantAwardsOutput <<"1. Mark for Removal From Ballot: %s %d \n",removeid.c_str(),svpit2->first);
				markForRemoval=svpit2->first;
			}
		}
		
		if(markForRemoval!=0){
			ballotit->second.erase(markForRemoval);
		}
		
		//Make a note of ballot to remove
		if(ballotit->second.size()==0){
			if(!isLastCandidate){
				wastedVotes[ballotit->first]=(ballotBalances[ballotit->first]*ballotWeights[ballotit->first]);
			}
			ballotsToRemove[ballotit->first]=1;
		}
	}	
	
	for(btrit=ballotsToRemove.begin(); btrit!=ballotsToRemove.end(); ++btrit){
		ballots.erase(btrit->first);
	}
	
}



void printBallots(){

	printf("Current Ballot State\n");
	int cutOff=0;
	for(ballotit=ballots.begin(); ballotit!=ballots.end(); ++ballotit){
		//if(cutOff<10){
			printf("Voter: %s Balance: %llu Weight: %f Total: %f\n",ballotit->first.c_str(),ballotBalances[ballotit->first]/COIN,ballotWeights[ballotit->first],(ballotBalances[ballotit->first]/COIN)*ballotWeights[ballotit->first]);
			int cutOff2=0;
			//if(cutOff2<5){
				for(svpit2=ballotit->second.begin();svpit2!=ballotit->second.end();++svpit2){
					printf("Preference: (%d) %llu %s \n",cutOff2, svpit2->first,svpit2->second.c_str());
				}
			//}
			cutOff2++;
		//}
		cutOff++;
	}
	
	
}


bool startsWith(const char *str, const char *pre)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

string getDefaultWalletAddress(){
    return pwalletMain->getDefaultWalletAddress();
}
