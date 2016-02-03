#include "KDBReader.h"
#include "Endian.h"

bool KDBReader::checkSig2(uint32_t val) {
    bool match2 = false;
    for(int i=0; i<KDB_SIG2_ARR_LEN; i++) {
        uint32_t tmp = KDB_SIG2_ARR[i];
        if(tmp == val) {
            return true; 
        }
    }
    return false;
}

