#include "KDBXReader.h"
#include "Endian.h"

bool KDBXReader::checkSig2(uint32_t val) {
    bool match2 = false;
    for(int i=0; i<KDBX_SIG2_ARR_LEN; i++) {
        uint32_t tmp = KDBX_SIG2_ARR[i];
        if(tmp == val) {
            return true; 
        }
    }
    return false;
}
