#ifndef _KDBX_READER_H
#define _KDBX_READER_H

#include "AbstractKDBReader.h"

#define KDBX_SIG2_ARR_LEN  2 
const uint32_t KDBX_SIG2_ARR[KDBX_SIG2_ARR_LEN] = {0xB54BFB66, 0xB54BFB67};

class KDBXReader: public AbstractKDBReader {
    public:
        bool checkSig2(uint32_t val);
}
;

#endif
