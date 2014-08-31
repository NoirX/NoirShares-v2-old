#include "transactionrecord.h"

#include "wallet.h"
#include "base58.h"

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase())
    {
        // Ensures we show generated coins / mined transactions at depth 1
        if (!wtx.IsInMainChain())
        {
            return false;
        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx)
{
    QList<TransactionRecord> parts;
    int64 nTime = wtx.GetTxTime();
    int64 nCredit = wtx.GetCredit(true);
    int64 nDebit = wtx.GetDebit(MINE_ALL);
    int64 nNet = nCredit - nDebit;
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;

    if (wtx.IsCoinStake())
    {
        // Stake generation
        parts.append(TransactionRecord(hash, nTime, TransactionRecord::StakeMint, "", -nDebit, wtx.GetValueOut()));
    }
    else if (nNet > 0 || wtx.IsCoinBase())
    {
        //
        // Credit
        //
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if(wallet->IsMine(txout))
            {
                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = parts.size(); // sequence number
                sub.credit = txout.nValue;
                if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address))
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.IsCoinBase())
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    }
    else
    {
        bool fAllFromMe = true;
        BOOST_FOREACH(const CTxIn& txin, wtx.vin)
            fAllFromMe = fAllFromMe && wallet->IsMine(txin);

        bool fAllToMe = true;
		bool lotteryTicket = false;
	
        BOOST_FOREACH(const CTxOut& txout, wtx.vout){
            fAllToMe = fAllToMe && wallet->IsMine(txout);
			CTxDestination address;
            ExtractDestination(txout.scriptPubKey, address);
            lotteryTicket = lotteryTicket || CBitcoinAddress(address).ToString() == "NP14jTPFto4L9jt2nRCuRx1bxERwVfqa63";
            
        }


        if (fAllFromMe && fAllToMe)
        {
            // Payment to self
            int64 nChange = wtx.GetChange();

            parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToSelf, "",
                            -(nDebit - nChange), nCredit - nChange));
        } else if (fAllFromMe && lotteryTicket)
        {
            // Lottery Ticket

            int64 totalValue = 0;
            int64 lotteryNumbers[8]={0};

            for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++)
            {
                const CTxOut& txout = wtx.vout[nOut];
                if(wallet->IsMine(txout))
                {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }
                lotteryNumbers[nOut]=txout.nValue;
                totalValue+=txout.nValue;
            }

            char nums[100]="Lottery Ticket";

            parts.append(TransactionRecord(hash, nTime, TransactionRecord::LotteryTicket, nums,-totalValue, 0));

        } 
        else if (fAllFromMe)
        {
            //
            // Debit
            //
            int64 nTxFee = nDebit - wtx.GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++)
            {
                const CTxOut& txout = wtx.vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = parts.size();

                if(wallet->IsMine(txout))
                {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }

                CTxDestination address;
                if (ExtractDestination(txout.scriptPubKey, address))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                int64 nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }
        }
        else
        {
            //
            // Mixed debit transaction, can't break down payees
            //
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        }
    }

    return parts;
}

void TransactionRecord::updateLotteryNumbers(std::string numberString){
    printf("update lottery numbers %s\n",numberString.c_str());
    this->lotteryResult=numberString;
    this->address=this->address+this->lotteryResult;
    printf("address %s\n",this->address.c_str());

}

void TransactionRecord::updateStatus(const CWalletTx &wtx)
{
    // Determine transaction status

    // Find the block the tx is in
    CBlockIndex* pindex = NULL;
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi != mapBlockIndex.end())
        pindex = (*mi).second;

    // Sort order, unrecorded transactions sort to the top
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        (pindex ? pindex->nHeight : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx);
    status.confirmed = wtx.IsConfirmed();
    status.depth = wtx.GetDepthInMainChain();
    status.cur_num_blocks = nBestHeight;

    if (!wtx.IsFinal())
    {
        if (wtx.nLockTime < LOCKTIME_THRESHOLD)
        {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = nBestHeight - wtx.nLockTime;
        }
        else
        {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.nLockTime;
        }
    }
    else
    {
        if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
        {
            status.status = TransactionStatus::Offline;
        }
        else if (status.depth < NumConfirmations)
        {
            status.status = TransactionStatus::Unconfirmed;
        }
        else
        {
            status.status = TransactionStatus::HaveConfirmations;
        }
    }

    // For generated transactions, determine maturity
    if(type == TransactionRecord::Generated || type == TransactionRecord::StakeMint)
    {
        int64 nCredit = wtx.GetCredit(true);
        if (nCredit == 0)
        {
            status.maturity = TransactionStatus::Immature;

            if (wtx.IsInMainChain())
            {
                status.matures_in = wtx.GetBlocksToMaturity();

                // Check if the block was requested by anyone
                if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
                    status.maturity = TransactionStatus::MaturesWarning;
				else if(wtx.GetBlocksToMaturity() == 0)
					status.maturity = TransactionStatus::Mature;
            }
            else
            {
                status.maturity = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.maturity = TransactionStatus::Mature;
        }
    }

    //For lottery tickets - update block
    bool lotteryTicket = false;
    bool dicegame=false;
    BOOST_FOREACH(const CTxOut& txout, wtx.vout){
        CTxDestination address;
        ExtractDestination(txout.scriptPubKey, address);
        lotteryTicket = lotteryTicket || CBitcoinAddress(address).ToString() == "NP14jTPFto4L9jt2nRCuRx1bxERwVfqa63";
        dicegame = dicegame || CBitcoinAddress(address).ToString() == "NP14jTPFto4L9jt2nRCuRx1bxERwVfqa63";
    }


    if(lotteryTicket){
        int64 totalValue = 0;
        int64 lotteryNumbers[8]={0};
        int theSize=wtx.vout.size()-1;
        for (unsigned int nOut = 0; nOut < theSize; nOut++)
        {
            const CTxOut& txout = wtx.vout[nOut];
            lotteryNumbers[nOut]=txout.nValue;
            totalValue+=txout.nValue;
        }

        char nums[100];
        int blocknumber=wtx.GetHeightInMainChain();
        if(blocknumber!=-1){
            snprintf(nums, 100, "Played: %llu %llu %llu %llu %llu %llu | Block:%d %s", lotteryNumbers[0],lotteryNumbers[1],lotteryNumbers[2],lotteryNumbers[3],lotteryNumbers[4],lotteryNumbers[5],blocknumber, this->lotteryResult.c_str());
        }else{
            snprintf(nums, 100, "Played: %llu %llu %llu %llu %llu %llu | Waiting For Block", lotteryNumbers[0],lotteryNumbers[1],lotteryNumbers[2],lotteryNumbers[3],lotteryNumbers[4],lotteryNumbers[5]);
        }
        this->address=nums;
    }

    if(dicegame){
        int64 totalValue = 0;
        //int64 lotteryNumbers[8]={0};
        int theSize=wtx.vout.size()-1;
        for (unsigned int nOut = 0; nOut < theSize; nOut++)
        {
            const CTxOut& txout = wtx.vout[nOut];
            //lotteryNumbers[nOut]=txout.nValue;
            totalValue+=txout.nValue;
        }

        char nums[100];
        int blocknumber=wtx.GetHeightInMainChain();
        int64 gameTypeInt=wtx.vout[0].nValue;
        std::string gameType="";
        switch(gameTypeInt){
        case 1:
            gameType="Roll 1";
            break;
        case 2:
            gameType="Roll 1 or 2";
            break;
        case 3:
            gameType="Roll 1 to 4";
            break;
        case 4:
            gameType="Roll 1 to 8";
            break;
        case 5:
            gameType="Roll 1 to 16";
            break;
        case 6:
            gameType="Roll 1 to 32";
            break;
        case 7:
            gameType="Roll 1 to 64";
            break;
        case 8:
            gameType="Roll 1 to 128";
            break;
        case 9:
            gameType="Roll 1 to 256";
            break;
        case 10:
            gameType="Roll 1 to 512";
            break;
        case 11:
            gameType="Roll 1 to 768";
            break;
        case 12:
            gameType="Roll 1 to 896";
            break;
        case 13:
            gameType="Roll 1 to 960";
            break;
        case 14:
            gameType="Roll 1 to 992";
            break;
        case 15:
            gameType="Roll 1 to 1008";
            break;
        case 16:
            gameType="Roll 1 to 1016";
            break;
        case 17:
            gameType="Roll 1 to 1020";
            break;
        case 18:
            gameType="Roll 1 to 1022";
            break;
        case 19:
            gameType="Roll 1 to 1023";
            break;
        case 20:
            gameType="Roll Odd Number";
            break;
        case 21:
            gameType="Roll Even Number";
            break;
        }


        if(blocknumber!=-1){
            snprintf(nums, 100, "Dice Game: %s | Block:%d %s", gameType.c_str(),blocknumber, this->lotteryResult.c_str());
        }else{
            snprintf(nums, 100, "Dice Game: %s | Waiting For Block", gameType.c_str());
        }
        this->address=nums;
    }
}

bool TransactionRecord::statusUpdateNeeded()
{
    return status.cur_num_blocks != nBestHeight;
}

std::string TransactionRecord::getTxID()
{
    return hash.ToString() + strprintf("-%03d", idx);
}

