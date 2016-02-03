#ifndef _KDBX_READER_H
#define _KDBX_READER_H

#include "AbstractKDBReader.h"
#include <map>
#include <vector>

using std::map;
using std::vector;

#define KDBX_SIG2_ARR_LEN  2 
const uint32_t KDBX_SIG2_ARR[KDBX_SIG2_ARR_LEN] = {0xB54BFB66, 0xB54BFB67};

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
        // get round
        uint64_t getTransformRounds();

    protected:
        typedef map<char, vector<char> > HeaderMap; 
        HeaderMap mHeaderMap;
}
;

#endif
