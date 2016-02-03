#ifndef _KDB_READER_H
#define _KDB_READER_H

#include "AbstractKDBReader.h"

#define KDB_SIG2_ARR_LEN  1 
const uint32_t KDB_SIG2_ARR[KDB_SIG2_ARR_LEN] = {0xB54BFB65};

class KDBReader: public AbstractKDBReader {
    public:
        bool checkSig2(uint32_t val);
}
;

#endif
