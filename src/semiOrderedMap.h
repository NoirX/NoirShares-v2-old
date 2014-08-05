#include <math.h>

class semiOrderedMap
{
    private:

        uint64_t *indexOfBirthdayHashes;
        uint32_t *indexOfBirthdays;
        int bucketSizeExponent;
        int bucketSize;

        // This is useful for tracking performance
        // int discards;

    public:

        ~semiOrderedMap()
        {
            //printf("BSE:%d Discards:%d",bucketSizeExponent,discards);

            delete [] indexOfBirthdayHashes;
            delete [] indexOfBirthdays;
        }

        void allocate(int bSE)
        {
            bucketSizeExponent=bSE;
            bucketSize=pow(2.0,bSE);
            indexOfBirthdayHashes=new uint64_t[67108864];
            indexOfBirthdays=new uint32_t[67108864];
            //discards=0;
        }
        
        // Is there a match to the birthdayHash in a specific
        // part of indexOfBirthdayHashes?
        uint32_t checkAdd(uint64_t birthdayHash, uint32_t nonce)
        {
            // (2**(50 - 28)) * 2**4 -- birthdayHash is "random", so start is also
            uint64_t bucketStart = (birthdayHash >> (24+bucketSizeExponent))*bucketSize;
            for(int i=0;i<bucketSize;i++) // loop through 2**4
            {
                uint64_t bucketValue=indexOfBirthdayHashes[bucketStart+i];
                if(bucketValue==birthdayHash)
                {
                    //Found matching hash, return birthday
                    return indexOfBirthdays[bucketStart+i];
                }
                else if(bucketValue==0)
                {
                    //No match, add to index
                    indexOfBirthdayHashes[bucketStart+i]=birthdayHash;
                    indexOfBirthdays[bucketStart+i]=nonce;
                    return 0;
                }
                //bucket contains element at this place, but not a match, increment
            }
            //bucket full
            //discards++;
            return 0;
        }
};
