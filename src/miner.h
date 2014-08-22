// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NOVACOIN_MINER_H
#define NOVACOIN_MINER_H

#include "main.h"
#include "wallet.h"

//Generate NoirShares (PoW)
void GenerateBitcoins(bool fGenerate, CWallet* pwallet);
/** Generate a new block */
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake=false);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
/** Do mining precalculation */
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
/** Check Work */
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);
/** Check mined proof-of-work block */
void BitcoinMiner(CWallet *pwallet, bool fProofOfStake);

#endif // NOVACOIN_MINER_H
