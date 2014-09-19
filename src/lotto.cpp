#include "main.h"
#include "lotto.h"
#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "base58.h"
#include "ui_interface.h"
#include "checkqueue.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>


using namespace std;
using namespace boost;
#include <stdio.h>
#include <string>
#ifdef MAC_OSX
#include <CoreFoundation/CoreFoundation.h>
#endif

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

string TIMEKEEPERSIGNINGADDRESS     ="NbatKXvxs7BcStvWSRe1mMbkAdX6VXjC2u";
string TIMEKEEPERBROADCASTADDRESS   ="Na8E4ZVGqahjFzJgZNCqMLy8w9W1aQ9Fou";
string DRAWMANAGERSIGNINGADDRESS    ="NbE5Gv9xVKT3UfVzEoXeB5tDtUgsej8Khn";
string DRAWMANAGERBROADCASTADDRESS  ="NSVhD9xJXRH3hppcYhF54TftyVrEMAhMrV";
string TICKETADDRESS                ="NbUs6cqeo8CiUfAyz7yaRc3WWiFUK58F3Q";


char* mPUBKey="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1blo14f8xTPJUlfo0YVy\nLcixUMVfbbtoa6QCdLOaW27rlnm4zOjuFXCpFpUw3I8GvVkvqLev0Y5wE4SySUZ8\n4q3Y4YQv/7QPl9GK3jGw99c9NHnTR01xaSqymYfocgxH0OEQ2NS15E9hS6pPkRQT\nlm0k4sYr3sKHBKe+DPKBACo7az6QvpXwncFiUW7yGEZPwhzcbVAQo8E6609B00nB\nfkBrzYc6u5/IcbRV+gygYbN0EjiV9AHQtMSzkMHsA3X0T5IGRZPWOtfnfmpxzaiO\nWWXJ6nfABZXE4fqnfBcISdo2Hp701t86FnSRuuIpFGFrfKueQwEaeJps9RFyAMhA\nuwIDAQAB\n-----END PUBLIC KEY-----";
string TIMEKEEPERRSABROADCASTADDRESS ="NR1YPBEq5SQFpBcjWpK6UmauTvqQZk6Zq5";

lottoshares::lottoshares()
{
}

bool verifymessage(string strAddress, string strMessage, vector<unsigned char> vchSig)
{
    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        return false;

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        return false;

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;
	CPubKey pubkey;
    return (pubkey.GetID() == keyID);
}

std::set<int> generateDrawNumbersFromString(uint256 seedhash){

    //Hash seedString 6 times in a row
    std::set<int> drawnNumbers;
    uint256 hash2=seedhash;

    do{
        for(int i=0;i<4;i++){
            SHA256((unsigned char*)&hash2, sizeof(hash2), (unsigned char*)&hash2);
        }
        if(hash2.Get64(2)<ULLONG_MAX-21){ //ensure small numbers not slightly favoured
            int proposedNumber=(hash2.Get64(2)%42)+1;
            if(drawnNumbers.find(proposedNumber)==drawnNumbers.end()){
                drawnNumbers.insert(proposedNumber);
            }
        }
    }while(drawnNumbers.size()<6);

    std::set<int>::iterator it;
    for (it=drawnNumbers.begin(); it!=drawnNumbers.end(); ++it){
        printf(" %d",*it);
    }
    printf("\n");

    return drawnNumbers;
}

int getDiceRoll(uint256 transactionHash, uint256 seedHash){
    uint64 xorred = transactionHash.Get64(2) ^ seedHash.Get64(2);
    return (xorred%1024)+1;
}

int countMatches(std::set<int> ticketNumbers, std::set<int> drawNumbers){
    int count=0;
    for (std::set<int>::iterator it=drawNumbers.begin(); it!=drawNumbers.end(); ++it){
        //int theNum=(int)*it;
        if (ticketNumbers.find(*it)!=ticketNumbers.end()){
            count++;
        }
    }
    return count;
}

int powerPositiveIntegers (int number, int index) {
    if (index == 0) {
        return 1;
    }
    int num = number;
    for (int i = 1; i < index; i++) {
        number = number * num;
    }
    return number;
}

void calculatePayoutRequirements(std::map<string, int64> &payoutRequirements, int64 &feesFromPayout, int64 &ncfeesFromPayout, uint256 theTicketBlockHash, std::set<int> drawNumbers, bool logTickets, uint256 seedHash){

    ofstream myfile;
    if(logTickets){
        if(drawNumbers.size()==6){
            myfile.open ((GetDataDir() / "log-latestwinningtickets.txt").string().c_str(), ios::app);
        }else{
            myfile.open ((GetDataDir() / "log-latestconfirmedtickets.txt").string().c_str(), ios::app);
        }
    }

    printf("Calculate Payout Requirements\n");
    //Get the block
    CBlockIndex* ticketBlockHeader = pindexBest;
    while(ticketBlockHeader->GetBlockHash()!=theTicketBlockHash){
        ticketBlockHeader=ticketBlockHeader->pprev;
        //printf("Looking For Matching Header, %s, %s\n",theTicketBlockHash.GetHex().c_str(),ticketBlockHeader->GetBlockHash().GetHex().c_str());
        if(ticketBlockHeader==NULL){
            printf("Warning: This shouldn't happen! Can't find the ticket block when looking to calculate amount for prize payouts.\n");
            return;
        }
    }
    printf("Found Matching Header, %s, %s\n",theTicketBlockHash.GetHex().c_str(),ticketBlockHeader->GetBlockHash().GetHex().c_str());

    if(logTickets){
        myfile << "--------------------------------------------------" <<"\n";
        myfile << "Block ID:" << ticketBlockHeader->nHeight << " - Block Hash:" << ticketBlockHeader->GetBlockHash().GetHex() <<"\n";
        if(drawNumbers.size()==6){
            std::set<int>::iterator it;
            myfile << "Draw Numbers: ";
            for (it=drawNumbers.begin(); it!=drawNumbers.end(); ++it){
                myfile << *it << " ";
            }
            myfile << "\n";
        }
    }



    CBlock ticketBlock;
    ticketBlock.ReadFromDisk(ticketBlockHeader);

    int64 totalTicketStake=0;
    int64 totalPrizes=0;

    //check for tickets
    for (unsigned int i=0; i<ticketBlock.vtx.size(); i++){
        //check each included transaction to see if it is a lottery ticket
        //myfile << "Transaction ID: " << ticketBlock.vtx[i].GetHash().GetHex() << ticketBlock.vtx[i].vout.size() << "\n";

        if(ticketBlock.vtx[i].IsCoinBase()){
            //myfile << "Skipping Coinbase\n";
            //This is a coinbase transaction, it can't be a lottery ticket, skip
        }else{
            if(ticketBlockHeader->nHeight>FORKHEIGHT && ticketBlock.vtx[i].vout.size()==3){
                //Dice plays always have 3 outputs

                //First 2 outputs must have ticket address
                bool validOutAddresses=true;
                int64 stake=0;
                for(int j=0;j<2;j++){
                    CTxDestination address;
                    ExtractDestination(ticketBlock.vtx[i].vout[j].scriptPubKey,address);
                    std::string outAddress=CBitcoinAddress(address).ToString().c_str();
                    stake=stake+ticketBlock.vtx[i].vout[j].nValue;
                    
                }

                if(!validOutAddresses){
                    //This is not a ticket
                    printf("Skipping - not using ticket addres\n");
                    continue;
                }

                printf("Dice Trx ID: %s\n",ticketBlock.vtx[i].GetHash().GetHex().c_str());

                int64 gameNumber64=ticketBlock.vtx[i].vout[0].nValue;
                printf("Game: %llu\n",gameNumber64);
                if(gameNumber64>21){
                    continue;
                }
                int gameNumber=gameNumber64;

                int diceRoll=getDiceRoll(ticketBlock.vtx[i].GetHash(),seedHash);
                printf("Roll: %d\n",diceRoll);

                if(gameNumber<22){

                    printf("Valid Dice Roll\n");
                    totalTicketStake+=stake;

                    int64 prize=0;
                    if(gameNumber>0 && gameNumber<11){
                        int threshold=(powerPositiveIntegers(2,gameNumber-1))+1;
                        int64 winAmount=stake*(powerPositiveIntegers(2,11-gameNumber));
                        printf("Test Less Than: %d for prize %llu\n",threshold,winAmount);
                        if(diceRoll<threshold){
                            prize=winAmount;
                        }
                    }else if(gameNumber>10 && gameNumber<20){
                        int threshold=1025-(powerPositiveIntegers(2,(gameNumber-19)*-1));
                        //int64 winAmount=stake+(stake>>(gameNumber-10));
                        int64 winAmount=stake+(stake/(powerPositiveIntegers(2,(gameNumber-9))-1));
                        printf("Test Less Than: %d for prize %llu\n",threshold,winAmount);
                        if(diceRoll<threshold){
                            prize=winAmount;
                        }
                    }else if(gameNumber==20){
                        printf("Test Odd\n");
                        if(diceRoll%2==1){
                            prize=stake*2;
                        }
                    }else if(gameNumber==21){
                        printf("Test Even\n");
                        if(diceRoll%2==0){
                            prize=stake*2;
                        }
                    }

                    printf("Prize %llu\n",prize);

                    if(prize>0){
                        CTxDestination address;
                        ExtractDestination(ticketBlock.vtx[i].vout[2].scriptPubKey,address);
                        std::string payoutAddress=CBitcoinAddress(address).ToString().c_str();
                        printf("Payout Address %s\n",payoutAddress.c_str());
                        payoutRequirements[payoutAddress]=payoutRequirements[payoutAddress]+prize;
                        ncfeesFromPayout=ncfeesFromPayout+prize;
                        totalPrizes+=prize;
                        
                    }
                    //Update wallet with info
                    char str[15];
                    sprintf(str, "| Rolled: %d", diceRoll);
                    std::string myNumbers=str;
                    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered){
                        printf("lotto.cpp addlnitim\n");
                        pwallet->AddLotteryNumbersIfTransactionInvolvingMe(ticketBlock.vtx[i].GetHash(), ticketBlock.vtx[i], myNumbers);
                    }

                }


            }else if(ticketBlock.vtx[i].vout.size()==8){
                //Lottery tickets always have 8 outputs
                //printf("Transaction - Has 8 Outputs\n");

                //First 7 outputs must have ticket address
                bool validOutAddresses=true;
                int64 stake=0;
                for(int j=0;j<7;j++){
                    CTxDestination address;
                    ExtractDestination(ticketBlock.vtx[i].vout[j].scriptPubKey,address);
                    std::string outAddress=CBitcoinAddress(address).ToString().c_str();
                    stake=stake+ticketBlock.vtx[i].vout[j].nValue;
                    if(outAddress!=TICKETADDRESS){
                        //if(logTickets){
                        //    myfile << "Not using ticket addresss" << " " << j << " " << outAddress << "\n";
                        //}
                        validOutAddresses=false;
                        break;
                    }
                }

                if(!validOutAddresses){
                    //This is not a ticket
                    printf("Skipping - not using ticket addres\n");
                    continue;
                }

                printf("Ticket Trx ID: %s\n",ticketBlock.vtx[i].GetHash().GetHex().c_str());

                printf("Ticket Numbers: ");
                std::set<int> ticketNumbers;
                for(int j=0;j<6;j++){
                    int64 ballNumber=ticketBlock.vtx[i].vout[j].nValue;
                    printf(" %llu",ballNumber);

                    if(ballNumber>0 && ballNumber<43){
                        ticketNumbers.insert(ballNumber);
                    }
                }
                printf("\n");

                std::set<int>::iterator it;
                printf("Draw Numbers: ");
                for (it=drawNumbers.begin(); it!=drawNumbers.end(); ++it){
                    printf(" %d",*it);
                }
                printf("\n");




                if(ticketNumbers.size()==6){
                    printf("Valid Ticket\n");
                    totalTicketStake+=stake;

                    //Valid ticket
                    //check if tickets have won
                    //if so, add to payoutReqs
                    int matchingNumber=countMatches(ticketNumbers,drawNumbers);
                    printf("Matching Number %d\n",matchingNumber);

                    int64 prize=0;
                    /*if(matchingNumber==0){
                        prize=stake/10;
                    }else if(matchingNumber==1){
                        prize=stake/100;
                    }else if(matchingNumber==2){
                        prize=stake*1;
                    }else*/
                    if(matchingNumber==3){
                        prize=stake/10;
                    }else if(matchingNumber==4){
                        prize=stake*10;
                    }else if(matchingNumber==5){
                        prize=stake*100;
                    }else if(matchingNumber==6){
                        prize=stake*5000;
                    }

                    printf("Prize %llu\n",prize);

                    if(logTickets && (drawNumbers.size()==0 || prize>0)){
                        myfile << "Ticket Transaction ID:" << ticketBlock.vtx[i].GetHash().GetHex() <<":";
                        myfile << "Numbers:";
                        std::set<int>::iterator itt;
                        for (itt=ticketNumbers.begin(); itt!=ticketNumbers.end(); ++itt){
                            myfile << " " << *itt;
                        }
                        myfile << ":Stake:" << stake << ":";
                        CTxDestination address;
                        ExtractDestination(ticketBlock.vtx[i].vout[7].scriptPubKey,address);
                        std::string payoutAddress=CBitcoinAddress(address).ToString().c_str();
                        myfile << ":Payout Address:" << payoutAddress <<"\n";

                    }

                    if(prize>0){
                        CTxDestination address;
                        ExtractDestination(ticketBlock.vtx[i].vout[7].scriptPubKey,address);
                        std::string payoutAddress=CBitcoinAddress(address).ToString().c_str();
                        printf("Payout Address %s\n",payoutAddress.c_str());
                        payoutRequirements[payoutAddress]=payoutRequirements[payoutAddress]+prize;
                        feesFromPayout=feesFromPayout+prize;
                        totalPrizes+=prize;
                        if(logTickets && drawNumbers.size()==6){
                            myfile << "Matching Numbers: " << matchingNumber << " Prize:" << prize <<"\n";
                        }
                    }
                    //Update wallet with info
                    std::set<int>::iterator itt;
                    std::string myNumbers="| Draw: ";
                    for (itt=drawNumbers.begin(); itt!=drawNumbers.end(); ++itt){
                        int myNum=*itt;
                        char str[15];
                        sprintf(str, "%d", myNum);
                        myNumbers=myNumbers+str;
                        myNumbers=myNumbers+" ";
                    }
                    char str[15];
                    sprintf(str, "| Match: %d", matchingNumber);
                    myNumbers=myNumbers+str;
                    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered){
                        printf("lotto.cpp addlnitim\n");

                        pwallet->AddLotteryNumbersIfTransactionInvolvingMe(ticketBlock.vtx[i].GetHash(), ticketBlock.vtx[i], myNumbers);
                    }

                }
            }else{
                printf("Skipping Transaction - Not 3 or 8 Outputs\n");
            }
        }
    }

    if(logTickets){
        if(drawNumbers.size()==6){
            myfile << "Total Prizes: " << totalPrizes << "\n";
        }else{
            myfile << "Tickets Total Stake: " << totalTicketStake << "\n";
        }
        myfile.close();
    }
}

void checkTransactionForPayoutsFromCheckpointTransaction(CTransaction vtx,std::map<string, int64> &payoutRequirements,int64 &feesFromPayout, int64 &ncfeesFromPayout, bool logTickets, ofstream &myfile){

    int64 theHeight;
    int64 theTime;
    uint256 theHashNew;
    uint256 seedHash = checkTransactionForCheckpoints(vtx, false, false, theHeight, theTime, theHashNew);

    if(seedHash!=NULL){
        std::set<int> drawNumbers;
        drawNumbers = generateDrawNumbersFromString(seedHash);

        if(logTickets){
            myfile << "------------------------------------------\n";
            myfile << "Block: " << theHeight << "\n";
            myfile << "Checkpointed Time: " << theTime << "\n";
            myfile << "Numbers:";
            std::set<int>::iterator itt;
            for (itt=drawNumbers.begin(); itt!=drawNumbers.end(); ++itt){
                myfile << " " << *itt;
            }
            myfile << "\n";
            myfile << "Random Seed String:" << seedHash.GetHex() << "\n";
        }
        //Note - the block may contain multiple draw results
        calculatePayoutRequirements(payoutRequirements,feesFromPayout,ncfeesFromPayout,theHashNew,drawNumbers,logTickets,seedHash);
    }
}

uint256 checkTransactionForCheckpoints(CTransaction tx, bool makeFileQueue, bool logBlock, int64 &theHeight, int64 &theTime, uint256 &theHash){
    if(tx.IsCoinBase()){
        //This is a coinbase transaction, it can't be a checkpoint, skip
        return NULL;
    }
    if(tx.vout.size()==18 &&
            tx.vout[0].nValue==1 &&
            tx.vout[1].nValue==1 &&
            tx.vout[2].nValue==1 &&
            tx.vout[3].nValue==1 &&
            tx.vout[4].nValue==1 &&
            tx.vout[5].nValue==1 &&
            tx.vout[6].nValue==1 &&
            tx.vout[7].nValue==1 &&
            tx.vout[8].nValue==1 &&
            tx.vout[9].nValue==1 &&
            tx.vout[10].nValue==1 &&
            tx.vout[11].nValue==1 &&
            tx.vout[12].nValue==1 &&
            tx.vout[13].nValue==1 &&
            tx.vout[14].nValue==1 &&
            tx.vout[15].nValue==1 &&
            tx.vout[16].nValue==1
            ){

        printf("length 18 with all outputs 1 \n");
        CTxDestination address;
        ExtractDestination(tx.vout[0].scriptPubKey,address);
        std::string firstAddress=CBitcoinAddress(address).ToString().c_str();

        if(firstAddress==TIMEKEEPERRSABROADCASTADDRESS){
            //Basic checks passed - extract checkpoint
            printf("basic checks passed \n");
            vector<unsigned char> v;
            vector<unsigned char> signature;
            for(int k=1;k<17;k++){
                ExtractDestination(tx.vout[k].scriptPubKey,address);
                std::string outputAddress=CBitcoinAddress(address).ToString().c_str();
                std::vector<unsigned char> vchRet;
                DecodeBase58Check(outputAddress, vchRet);
                for(int j=1;j<21;j++){
                    if(signature.size()<256){
                        signature.push_back(vchRet[j]);
                    }else{
                        v.push_back(vchRet[j]);
                    }
                }
            }

            theHeight = *(int64*)&v[0];
            theTime = *(int64*)&v[8];
            theHash = *(uint256*)&v[16];

            char messageToSign[100];
            snprintf(messageToSign, 100, "%llu:%llu:%s", theHeight, theTime, theHash.ToString().c_str());

            BIO* bo = BIO_new( BIO_s_mem() );
            BIO_write( bo, mPUBKey,strlen(mPUBKey));
            EVP_PKEY* pkey = 0;
            PEM_read_bio_PUBKEY( bo, &pkey, 0, 0 );
            BIO_free(bo);
            RSA* pubkey = EVP_PKEY_get1_RSA( pkey );

            unsigned char hash[SHA256_DIGEST_LENGTH];
            unsigned int signLen=256;
            unsigned char sign[256];
            for(unsigned int i=0;i<signLen;i++){
                sign[i]=signature[i];
            }
            SHA256((unsigned char*)messageToSign, strlen(messageToSign), hash);
            if(RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, pubkey)){
                uint256 signatureHash;
                SHA256((unsigned char*)sign, 256, (unsigned char*)&signatureHash);
                
                return signatureHash;
            }



        }
    }
    return NULL;
}

void checkForCheckpoints(std::vector<CTransaction> vtx, bool makeFileQueue, bool logBlock){
    for (unsigned int i=0; i<vtx.size(); i++){
        //check each included transaction to see if it is a checkpoint
        int64 theHeight, theTime; uint256 theHash;
        checkTransactionForCheckpoints(vtx[i],makeFileQueue, logBlock, theHeight, theTime, theHash);
    }
}

void checkTransactionForPayoutsFromDrawTransaction(CTransaction vtx,std::map<string, int64> &payoutRequirements,int64 &feesFromPayout,int64 &ncfeesFromPayout, bool logTickets, ofstream &myfile){
    if(vtx.vout.size()==9 &&
        vtx.vout[0].nValue==1 &&
        vtx.vout[1].nValue==1 &&
        vtx.vout[2].nValue==1 &&
        vtx.vout[3].nValue==1 &&
        vtx.vout[4].nValue==1 &&
        vtx.vout[5].nValue==1 &&
        vtx.vout[6].nValue==1 &&
        vtx.vout[7].nValue==1){

        CTxDestination address;
        ExtractDestination(vtx.vout[0].scriptPubKey,address);
        std::string firstAddress=CBitcoinAddress(address).ToString().c_str();

        if(firstAddress==DRAWMANAGERBROADCASTADDRESS){
            //Basic checks passed - extract checkpoint
            vector<unsigned char> v;
            vector<unsigned char> signature;
            for(int k=1;k<8;k++){
                ExtractDestination(vtx.vout[k].scriptPubKey,address);
                std::string outputAddress=CBitcoinAddress(address).ToString().c_str();
                std::vector<unsigned char> vchRet;
                DecodeBase58Check(outputAddress, vchRet);
                for(int j=1;j<21;j++){
                    if(signature.size()<65){
                        signature.push_back(vchRet[j]);
                    }else{
                        v.push_back(vchRet[j]);
                    }
                }
            }



            int64 theHeight = *(int64*)&v[0];
            int64 theTime = *(int64*)&v[8];
            uint256 theHashNew = *(uint256*)&v[16];

            char cN[20]={0};
            for(int i=0;i<20;i++){
                cN[i]=*(char*)&v[48+i];
            }
            char commaedNumbers[100];

            sprintf(commaedNumbers, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
                    cN[0],cN[1],cN[2],cN[3],cN[4],cN[5],cN[6],cN[7],cN[8],cN[9],
                    cN[10],cN[11],cN[12],cN[13],cN[14],cN[15],cN[16],cN[17],cN[18],cN[19]
                    );

            char messageToSign[200];
            sprintf(messageToSign, "%s:%llu:%llu:%s", commaedNumbers, theHeight, theTime, theHashNew.ToString().c_str());
            printf("Message To Verify, %s %s",messageToSign, DRAWMANAGERSIGNINGADDRESS.c_str());
            if(verifymessage(DRAWMANAGERSIGNINGADDRESS,messageToSign,signature)){
                char randSeedString[300];
                //string strSig=EncodeBase64(&signature[0], signature.size());
                sprintf(randSeedString, "%s:%llu:%llu:%s", commaedNumbers, theHeight, theTime, theHashNew.ToString().c_str());
                printf("Found payout:%s\n",randSeedString);

                std::set<int> drawNumbers;
                uint256 hash2;
                SHA256((unsigned char*)randSeedString, strlen(randSeedString), (unsigned char*)&hash2);
                drawNumbers = generateDrawNumbersFromString(hash2);

                uint256 seedHash;
                SHA256((unsigned char*)randSeedString, strlen(randSeedString), (unsigned char*)&seedHash);

                if(logTickets){
                    myfile << "------------------------------------------\n";
                    myfile << "Block: " << theHeight << "\n";
                    myfile << "Checkpointed Time: " << theTime << "\n";
                    myfile << "Numbers:";
                    std::set<int>::iterator itt;
                    for (itt=drawNumbers.begin(); itt!=drawNumbers.end(); ++itt){
                        myfile << " " << *itt;
                    }
                    myfile << "\n";
                    myfile << "Random Seed String:" << randSeedString << "\n";
                }
                //Note - the block may contain multiple draw results
                calculatePayoutRequirements(payoutRequirements,feesFromPayout,ncfeesFromPayout,theHashNew,drawNumbers,logTickets,seedHash);

            }
        }
    }
}



bool checkForPayouts(std::vector<CTransaction> &vtx, int64 &feesFromPayout, int64 &ncfeesFromPayout, bool addTransactions, bool logTickets, int blockHeight){

    ofstream myfile;
    if(logTickets){
        myfile.open ((GetDataDir() / "log-latestprizedraws.txt").string().c_str(), ios::app);
    }

    //printf("Check For Payouts:\n");
    std::map<string, int64> payoutRequirements;

    for (unsigned int i=0; i<vtx.size(); i++){
        //check each included transaction to see if it is a draw result
        if(vtx[i].IsCoinBase()){
            //This is a coinbase transaction, it can't be a draw result, skip
        }else{
            if(blockHeight<FORKHEIGHT){
                checkTransactionForPayoutsFromDrawTransaction(vtx[i],payoutRequirements,feesFromPayout,ncfeesFromPayout,logTickets,myfile);
            }else{
                checkTransactionForPayoutsFromCheckpointTransaction(vtx[i],payoutRequirements,feesFromPayout,ncfeesFromPayout,logTickets,myfile);
            }
        }
    }

    if(addTransactions){
        //Add payout outputs to VTX

        for (std::map<string, int64>::iterator it=payoutRequirements.begin(); it!=payoutRequirements.end(); ++it){
            vtx[0].vout.resize(vtx[0].vout.size()+1);
            CBitcoinAddress address(it->first);
            vtx[0].vout[vtx[0].vout.size()-1].scriptPubKey.SetDestination( address.Get() );
            vtx[0].vout[vtx[0].vout.size()-1].nValue = it->second;
            //feesFromPayout=feesFromPayout+it->second;
        }
        //feesFromPayout=feesFromPayout/1000;
       // printf("1 Fees From Payout - Calculated - %llu\n",feesFromPayout);

        return true;
    }else if(logTickets){
        myfile.close();
        return true;
    }else{
        
        //Check if payout outputs are present in coinbase transaction
        //return true if all present, return false if not

        for (std::map<string, int64>::iterator it=payoutRequirements.begin(); it!=payoutRequirements.end(); ++it){
            string addressString=it->first;

            bool foundIt=false;
            for (unsigned int i=0; i<vtx[0].vout.size(); i++){
                CTxDestination address;
                ExtractDestination(vtx[0].vout[i].scriptPubKey,address);

                if(addressString==CBitcoinAddress(address).ToString().c_str() && vtx[0].vout[i].nValue>=it->second){
                    //found
                    foundIt=true;
                    break;
                }

            }
            if(!foundIt){
                printf("Payout not found return false\n");
                return false;
            }
        }

        return true;
    }
}

int64 calculateTicketIncome(std::vector<CTransaction> vtx){
    //Check lottery tickets included - commission is paid on all outputs to lottery ticket addresses
    //even if they do not form part of a valid ticket
    int64 totalStake=0;
    for (unsigned int i=0; i<vtx.size(); i++){
        //check each included transaction to see if it is a lottery ticket
        if(vtx[i].IsCoinBase()){
               //This is a coinbase transaction, it can't be a lottery ticket, skip
        }else{
            //Sum outputs sent to ticket address
            CTxDestination address;
            for(unsigned int k=0;k<vtx[i].vout.size();k++){
                ExtractDestination(vtx[i].vout[k].scriptPubKey,address);
                std::string outputAddress=CBitcoinAddress(address).ToString().c_str();
                if(outputAddress==TICKETADDRESS){
                    totalStake=totalStake+vtx[i].vout[k].nValue;
                }
            }
        }
    }
    return totalStake;
}

int64 static availableSupply = 4000000000000000;
void writeLogInfoForBlock(uint256 logBlockHash){

    std::map<string, int64> logPayouts;
    std::set<int> emptyNumberSet;

    //Get the block
    CBlockIndex* ticketBlockHeader = pindexBest;
    while(ticketBlockHeader->GetBlockHash()!=logBlockHash){
        ticketBlockHeader=ticketBlockHeader->pprev;
        //Sometimes the block cannot be found - return in this case
        if(ticketBlockHeader==NULL){return;}
    }

    //Valid tickets
    //Tickets played
    int64 notNeeded=0;int64 notNeeded2=0;
    calculatePayoutRequirements(logPayouts,notNeeded,notNeeded2,logBlockHash, emptyNumberSet, true,0);

    CBlock ticketBlock;
    ticketBlock.ReadFromDisk(ticketBlockHeader);

    //Max ticket fees allowed
    int64 ticketIncome = calculateTicketIncome(ticketBlock.vtx);

    //Subsidy allowed
    int64 thefees=0;
    int64 subsidyAllowed = GetProofOfWorkReward(ticketBlockHeader->nHeight, thefees, ticketBlockHeader->pprev->nBits);

    //Draws found
    int64 feesFromPayout=0;int64 ncfeesFromPayout=0;
    checkForPayouts(ticketBlock.vtx, feesFromPayout,ncfeesFromPayout, false, true,ticketBlockHeader->nHeight);

    //Prizes awarded

    //Coinbase

    ofstream myfile;
    myfile.open ((GetDataDir() / "log-operatingstatement.txt").string().c_str(), ios::app);

    int64 coinbaseAward=0;
    for(unsigned int j=0;j<ticketBlock.vtx[0].vout.size();j++){
        coinbaseAward+=ticketBlock.vtx[0].vout[j].nValue;
    }
    double dcoin=100000000.0;
    myfile << "--------------------------------------------------------" << "\n";
    myfile << "          - INCOME STATEMENT Lotto DAC -" << "\n";
    myfile << "                       Block:" << ticketBlockHeader->nHeight << "\n";
    myfile << setiosflags(ios::right) << resetiosflags(ios::left) << setw(36) << "" << "     NRS" << setw(12) << "     NRS" << "\n";
    myfile << setiosflags(ios::right) << resetiosflags(ios::left) << setw(35) << "" << "    Debit" << setw(12) << "    Credit" << "\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "Revenues:" << "\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "Gross Revenues (Ticket sales)" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(24) << setiosflags(ios::fixed) << setprecision(2) << ticketIncome/dcoin << "\n";
    myfile << setiosflags(ios::right) << resetiosflags(ios::left) << setw(57) << "-----------\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "Expenses:" << "\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "  Prizes" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(12) << setiosflags(ios::fixed) << setprecision(2) << feesFromPayout/dcoin << "\n";
    int64 paymentCommissions=feesFromPayout >> PRIZEPAYMENTCOMMISSIONS;
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "  Prize Payment Commissions" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(12) << setiosflags(ios::fixed) << setprecision(2) << paymentCommissions/dcoin << "\n";
    int64 ticketCommissions=ticketIncome >> TICKETCOMMISSIONRATE;
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "  Ticket Commissions" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(12) << setiosflags(ios::fixed) << setprecision(2) << ticketCommissions/dcoin << "\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "  Subsidy Allowed" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(12) << setiosflags(ios::fixed) << setprecision(2) << subsidyAllowed/dcoin << "\n";
    int64 totalAllowed = feesFromPayout + (feesFromPayout >> PRIZEPAYMENTCOMMISSIONS) + (ticketIncome >> TICKETCOMMISSIONRATE) + subsidyAllowed;
    int64 processorDeficit = totalAllowed - coinbaseAward;
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "  Processor Deficit" << "(" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(11) << setiosflags(ios::fixed) << setprecision(2) << processorDeficit/dcoin << ")\n";
    myfile << setiosflags(ios::right) << resetiosflags(ios::left) << setw(57) << "-----------\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(44) << "    Total Expenses             " << setiosflags(ios::right) << resetiosflags(ios::left) <<"("<< setw(11) << setiosflags(ios::fixed) << setprecision(2) << coinbaseAward/dcoin << ")\n";
    myfile << setiosflags(ios::right) << resetiosflags(ios::left) << setw(57) << "-----------\n";
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "Net Income" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(24) << setiosflags(ios::fixed) << setprecision(2) << (ticketIncome-coinbaseAward)/dcoin << "\n\n";
    availableSupply-=ticketIncome;
    availableSupply+=coinbaseAward;
    myfile << setiosflags(ios::left) << resetiosflags(ios::right) << setw(32) << "Total Available Supply" << setiosflags(ios::right) << resetiosflags(ios::left) << setw(24) << setiosflags(ios::fixed) << setprecision(2) << (availableSupply)/dcoin << "\n\n";

    myfile.close();


    ofstream myfile2;
    myfile2.open ((GetDataDir() / "available-supply.txt").string().c_str(), ios::trunc);
    myfile2 << setiosflags(ios::fixed) << setprecision(2) << availableSupply/dcoin;
    myfile2.close();


}

string convertAddress(const char address[], char newVersionByte){
    std::vector<unsigned char> v;
    DecodeBase58Check(address,v);
    v[0]=newVersionByte;
    string result = EncodeBase58Check(v);
    return result;
}

boost::filesystem::path getShareDropsPath(const char *fileName)
{
#ifdef MAC_OSX
    char path[FILENAME_MAX];
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef mainBundleURL = CFBundleCopyBundleURL(mainBundle);
    CFStringRef cfStringRef = CFURLCopyFileSystemPath(mainBundleURL, kCFURLPOSIXPathStyle);
    CFStringGetCString(cfStringRef, path, sizeof(path), kCFStringEncodingASCII);
    CFRelease(mainBundleURL);
    CFRelease(cfStringRef);
    return boost::filesystem::path(path) / "Contents" / fileName;
#else
    return boost::filesystem::path(fileName);
#endif
}

void addShareDrops(CBlock &block){
	 //Add airdrops to genesis block
    std::string line;
    int dgCount=0;
    char intStr [10];
    int64 runningTotalCoins=0;
    //load from disk - distribute with exe
    ifstream myfile;
    const char* pszTimestamp = "NoirBits - Future in hand.";
	myfile.open(getShareDropsPath("shares.txt").string().c_str());
    if (myfile.is_open()){
                while ( myfile.good() ){
                    std::getline (myfile,line);
                    std::vector<std::string> strs;
                    boost::split(strs, line, boost::is_any_of(","));
                    
                    if(strs.size()==2){
							
                            dgCount++;
                            sprintf(intStr,"%d",dgCount);
                            CTransaction txNew;
                            txNew.nTime = 1410918978;
                            txNew.vin.resize(1);
                            txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)intStr, (const unsigned char*)intStr + strlen(intStr));
                            txNew.vout.resize(1);
                            txNew.vout[0].nValue = atoi64(strs[1].c_str());
                            runningTotalCoins+=txNew.vout[0].nValue;
                            CBitcoinAddress address(convertAddress(strs[0].c_str(),0x35));
                            txNew.vout[0].scriptPubKey.SetDestination( address.Get() );
                            block.vtx.push_back(txNew);
                        
                    }else{
                        printf("shares.txt - %s line parse failed\n",line.c_str());
                    }
                }
                myfile.close();
            }else{
                printf("shares.txt - required for distribution, not found\n");
            }
    printf("shares.txt, total coins :%llu\n",runningTotalCoins);
    
    myfile.open(getShareDropsPath("shares2.txt").string().c_str());
    if (myfile.is_open()){
                while ( myfile.good() ){
                    std::getline (myfile,line);
                    std::vector<std::string> strs;
                    boost::split(strs, line, boost::is_any_of(","));
                    
                    if(strs.size()==2){
							long l = atol(strs[1].c_str());
                            dgCount++;
                            sprintf(intStr,"%d",dgCount);
                            CTransaction txNew;
                            txNew.nTime = 1410918978;
                            txNew.vin.resize(1);
                            txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)intStr, (const unsigned char*)intStr + strlen(intStr));
                            txNew.vout.resize(1);
                            txNew.vout[0].nValue =((atoi64(strs[1].c_str()))/10);
                            runningTotalCoins+=txNew.vout[0].nValue;
                            CBitcoinAddress address(convertAddress(strs[0].c_str(),0x35));
                            txNew.vout[0].scriptPubKey.SetDestination( address.Get() );
                            block.vtx.push_back(txNew);
                        
                    }else{
                        printf("shares2.txt - %s line parse failed\n",line.c_str());
                    }
                }
                myfile.close();
            }else{
                printf("shares2.txt - required for distribution, not found\n");
            }
    printf("shares2.txt, total coins :%llu\n",runningTotalCoins);
  
}

bool sendmany(string addresses[], int amounts[], int numberAddresses, bool requireChange)
{
    //printf("Send 1:%d,%d\n",addresses.size());
    CWalletTx wtx;
    wtx.strFromAccount = "";

    //printf("Send 2:\n");

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, int64> > vecSend;

    int64 totalAmount = 0;

    for(int i=0;i<numberAddresses;i++)
    {
        CBitcoinAddress address(addresses[i]);
        if (!address.IsValid()){
            printf("Invalid NoirShares address: %s\n",addresses[i].c_str());
            return false;
        }

        /*if (setAddress.count(address)){
            printf("Invalid parameter, duplicated address: %s\n",addresses[i].c_str());
            return false;
        }*/

        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64 nAmount = amounts[i];
        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    //EnsureWalletIsUnlocked();

    // Send
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired = 0;
    string strFailReason;
    //printf("create transaction");
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, NULL,true);
    
    //printf("transaction created");

    if (!fCreated){
        printf("%s\n",strFailReason.c_str());
        return false;
    }

    printf("number of outputs:%d %lu\n",numberAddresses,wtx.vout.size());

    if(requireChange && wtx.vout.size()!=numberAddresses+1){
        printf("Transaction failed - would create a transaction with no change which may be invalid\n");
        return false;
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange)){
        printf("Transaction commit failed");
        return false;
    }
    return true;
}

void randomTickets(int64 amount, int64 interval){
    srand( time( NULL ) );
    while(1){

        //Every x seconds or so
        Sleep(interval*1000);

        while(IsInitialBlockDownload()){
            Sleep(1000);
        }

        //create a ticket and send it
        string addresses[7];
        addresses[0]=TICKETADDRESS;
        addresses[1]=TICKETADDRESS;
        addresses[2]=TICKETADDRESS;
        addresses[3]=TICKETADDRESS;
        addresses[4]=TICKETADDRESS;
        addresses[5]=TICKETADDRESS;
        addresses[6]=TICKETADDRESS;

        std::set<int> drawnNumbers;
        int amounts[7];
        int inc=0;
        int ticketAmount=0;
        do{
            int proposedNumber=(rand()%42)+1;
            if(drawnNumbers.find(proposedNumber)==drawnNumbers.end()){
                drawnNumbers.insert(proposedNumber);
                amounts[inc]=proposedNumber;
                ticketAmount=ticketAmount+amounts[inc];
                inc++;

            }

        }while(drawnNumbers.size()<6);

        amounts[6]=amount-ticketAmount;
        bool isSent=sendmany(addresses, amounts,7,true);
        if(!isSent){
            amounts[6]=amounts[6]-1;
            sendmany(addresses, amounts,7,true);
        }
    }
}

