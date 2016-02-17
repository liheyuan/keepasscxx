#ifndef _KDBX_READER_H
#define _KDBX_READER_H

#include "AbstractKDBReader.h"
#include <map>
#include <vector>

using std::map;
using std::vector;

// kdbx signature 2
#define KDBX_SIG2_ARR_LEN  2 
const uint32_t KDBX_SIG2_ARR[KDBX_SIG2_ARR_LEN] = {0xB54BFB66, 0xB54BFB67};
#define KDBX_STREAM_IV_LEN 8
const uint8_t KDBX_STREAM_IV[KDBX_STREAM_IV_LEN] = {0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A};

// header field const
const char KDBX_HEADER_BEGIN = 0;
const char KDBX_HEADER_END_OF_HEADER = 0;
const char KDBX_HEADER_COMMENT = 1;
const char KDBX_HEADER_CIPHER_ID = 2;
const char KDBX_HEADER_COMPRESSION_FLAGS = 3;
const char KDBX_HEADER_MASTER_SEED = 4;
const char KDBX_HEADER_TRANSFORM_SEED = 5;
const char KDBX_HEADER_TRANSFORM_ROUNDS = 6;
const char KDBX_HEADER_ENCRYPTION_IV = 7;
const char KDBX_HEADER_PROTECTED_STREAM_KEY = 8;
const char KDBX_HEADER_STREAM_START_BYTES = 9;
const char KDBX_HEADER_INNER_RANDOM_STREAM_ID = 10;
const char KDBX_HEADER_END = 10;

enum KDBXCompression {
    NONE,
    GZIP,
    UNKNOWN 
}
;

class KDBXReader: public AbstractKDBReader {
    public:
        KDBXReader();
        bool checkSig2(uint32_t val);
        bool parseHeader();

        // true: gzip, false: none 
        KDBXCompression getCompression();
        // get transform round
        uint64_t getTransformRounds();
        // get transform seed
        vector<char> getTransformSeed();
        // get master seed(random every save)
        vector<char> getMasterSeed();
        // get encryption iv
        vector<char> getEncryptionIV();
        // get stream start bytes
        vector<char> getStreamStart();
        // get protect stream key 
        vector<char> getProtectedStreamKey();

        // from file to xml
        bool decrypt(const string& password, const string& keyFileName, vector<char>& output);
        // generate master key
        bool generateMasterKey(const string& password, const string& keyFileName, vector<char>& outputVec);
        bool generateMasterKey(const string& password, const string& keyFileName);
        // check verify
        bool verifyAndTrim(vector<char>& bodyAfter);
        // decrypt body
        bool decryptBody(vector<char>& bodyAfter); 
        // concat each block
        bool removeBlock(const vector<char>& input, vector<char>& output);
        // decompress if neede
        bool decompress(const vector<char>& data, vector<char>& output);
        // unprotect against salsa20 (assume password must be string)
        bool unprotect(const string& input, string& output);
    private:
        // generate salsa buf if not enough and return first len of buf
        bool getSalsa20ArrByLen(size_t len, vector<char>& output);
        // clear salsa20 arr (should be called after each open)
        void clearSalsa20Arr();

    protected:
        typedef map<char, vector<char> > HeaderMap;
        HeaderMap mHeaderMap;
        vector<char> mMasterKey; // unsafe for now
        vector<char> mSalsa20Arr; // for protect / unprotect
}
;

#endif
