#ifndef LOTTO_H
#define LOTTO_H

#include "main.h"
#include "bignum.h"
#include <stdio.h>
#include <string>


using namespace std;
using namespace boost;

class NoirShares
{
public:
    NoirShares();
};

extern int runningTotalCoins; 

void checkForCheckpoints(std::vector<CTransaction> vtx, bool makeFileQueue, bool logBlock);

bool checkForPayouts(std::vector<CTransaction> &vtx, int64 &feesFromPayout, int64 &ncfeesFromPayout, bool addTransactions, bool logBlock, int blockNumber);

int64 calculateTicketIncome(std::vector<CTransaction> vtx);

void addShareDrops(CBlock &block);

void writeLogInfoForBlock(uint256 logBlockHash);

uint256 checkTransactionForCheckpoints(CTransaction tx, bool makeFileQueue, bool logBlock, int64 &theHeight, int64 &theTime, uint256 &theHash);

void randomTickets(int64 amount, int64 interval);

void checkTransactionForPayoutsFromCheckpointTransaction(CTransaction vtx,std::map<string, int64> &payoutRequirements,int64 &feesFromPayout, int64 &ncfeesFromPayout, bool logTickets, ofstream &myfile);

string getLotteryResult(int64 blockHeight, std::set<int> ticketNumbers);

#endif // LOTTO_H
