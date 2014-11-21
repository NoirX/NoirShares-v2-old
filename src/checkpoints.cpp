// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>
#include <fstream>
using namespace std;

#include "checkpoints.h"
#include "lotto.h"

#include "main.h"
#include "uint256.h"

using namespace std;
using namespace boost;
#include <boost/algorithm/string.hpp>

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to
    // be slower. This number is a compromise, as it can't be accurate for
    // every system. When reindexing from a fast disk with a slow CPU, it
    // can be up to 20, while when downloading from a slow network with a
    // fast multicore CPU, it won't be much higher than 1.
    static const double fSigcheckVerificationFactor = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64 nTimeLastCheckpoint;
        int64 nTransactionsLastCheckpoint;
        double fTransactionsPerDay;
    };

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (  0, hashGenesisBlock)
        (128, uint256("0x0ca5e3eac4c5c29306aac38cca5ffd4bf8e7306c237b1bcca5964f03d2b378ec"))
        
    ;

    static MapCheckpoints mapSigs =
            boost::assign::map_list_of
            (  0, 0)
            ;

    static const CCheckpointData data = {
        &mapCheckpoints,
        1407510054, // * UNIX timestamp of last checkpoint block
        1408385,    // * total number of transactions between genesis and last checkpoint
                  //   (the tx=... number in the SetBestChain debug.log lines)
        600.0     // * estimated number of transactions per day after checkpoint
    };

    static MapCheckpoints mapCheckpointsTestnet = 
        boost::assign::map_list_of
        (     0, uint256("b92bc49428b600d337b78489b252a8f42b41d4aafcd220b022236444a9bd0b2a"))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1385836559,
        1,
        960.0
    };

    const CCheckpointData &Checkpoints() {
        if (fTestNet)
            return dataTestnet;
        else
            return data;
    }

    uint256 getCheckpointHash(int nHeight){
        if(nHeight==0){
            return hashGenesisBlock;
        }
        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;
        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        uint256 retVal=i->second;
        return retVal;
    }

    uint256 getSeedHash(int blockHeight){
        //const MapCheckpoints& checkpoints = *Checkpoints().mapSigs;
        MapCheckpoints::const_iterator i = mapSigs.find(blockHeight);
        if(i==mapSigs.end()){
            return 0;
        }else{
            uint256 retVal=i->second;
            return retVal;
        }
    }

    int highestCheckpointLowerOrEqualTo(int maxHeight){

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;
        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            int potential = i.first;
            if(maxHeight>=potential){
                return potential;
            }
        }
        return 0;
    }

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (fTestNet) return true; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", true))
            return true;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex) {
        if (pindex==NULL)
            return 0.0;

        int64 nNow = time(NULL);

        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (fTestNet) return 0; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", true))
            return 0;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (fTestNet) return NULL; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", true))
            return NULL;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    void addCheckpoint(int64 theTime, int64 theHeight, uint256 theHashBestChain, bool createQueue, bool blocklog, uint256 signatureHash){
        if(mapCheckpoints[theHeight]==0){
            ofstream myfile;
            myfile.open ((GetDataDir() / "checkpoints.txt").string().c_str(), ios::app);
            myfile << theHeight << "," << theHashBestChain.GetHex() << "," << theTime << "," << signatureHash.GetHex() << "\n";
            myfile.close();

            mapCheckpoints[theHeight]=theHashBestChain;
            mapSigs[theHeight]=signatureHash;

            printf("checkpoint added - decoded %llu, %llu, %s\n", theTime, theHeight, theHashBestChain.GetHex().c_str());

            if(createQueue){
                //Write to file - create a queue of files
                boost::filesystem::path path = GetDataDir() / "entropyqueue" / strprintf("%08lld.txt", theHeight);
                boost::filesystem::create_directories(path.parent_path());
                ofstream broadcastOutput;
                broadcastOutput.open(path.string().c_str());
                broadcastOutput << theHeight << ":" << theHashBestChain.ToString() << ":" << theTime << ":" << signatureHash.ToString();
                broadcastOutput.close();
            }

            if(blocklog){
                writeLogInfoForBlock(theHashBestChain);
            }
        }
    }

    void loadCheckpoints(){
        //load from disk - locally made
        ifstream myfile2 ((GetDataDir() / "checkpoints.txt").string().c_str());
        if (myfile2.is_open()){
            std::string line;
            while ( myfile2.good() ){
                std::getline (myfile2,line);
                std::vector<std::string> strs;
                boost::split(strs, line, boost::is_any_of(","));
                if(strs.size()==3 || strs.size()==4){
                    mapCheckpoints[atoi(strs[0])]=uint256(strs[1]);
                    if(strs.size()==4){
                        mapSigs[atoi(strs[0])]=uint256(strs[3]);
                    }
                }else{
                    printf("checkpoints.txt - %s line parse failed\n",line.c_str());
                }
            }
        }
    }

}
