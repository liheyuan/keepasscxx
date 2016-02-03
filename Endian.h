#ifndef _ENDIAN_H
#define _ENDIAN_H

#include <stdint.h>
#include "endian.h"

// See http://stackoverflow.com/questions/2100331/c-macro-definition-to-determine-big-endian-or-little-endian-machine
class Endian {

    public:
    
        static bool isBigEndianness() {
            return !isLittleEndianness(); 
        }
    
        static bool isLittleEndianness() {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            return true;
            #else
            return false;
            #endif
        }
    
        // See http://stackoverflow.com/questions/7279393/quickest-way-to-change-endianness
        static uint16_t changeEndianness(uint16_t val) {
            return (val << 8) |          // left-shift always fills with zeros
                ((val >> 8) & 0x00ff); // right-shift sign-extends, so force to zero
        }
    
        static uint32_t changeEndianness(uint32_t val) {
            return (val << 24) |
                ((val <<  8) & 0x00ff0000) |
                ((val >>  8) & 0x0000ff00) |
                ((val >> 24) & 0x000000ff);
        }

        static uint64_t changeEndianness(uint64_t val) {
            val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
            val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
            return (val << 32) | (val >> 32);
        }
    
        static uint16_t convToLittle(uint16_t val) {
            if(isBigEndianness()) {
                val = changeEndianness(val);
            }
            return val;
        }
    
        static uint32_t convToLittle(uint32_t val) {
            if(isBigEndianness()) {
                val = changeEndianness(val);
            }
            return val;
        }

        static uint32_t convToLittle(uint64_t val) {
            if(isBigEndianness()) {
                val = changeEndianness(val);
            }
            return val;
        }
        static uint16_t convToBig(uint16_t val) {
            if(isLittleEndianness()) {
                val = changeEndianness(val);
            }
            return val;
        }
    
        static uint32_t convToBig(uint32_t val) {
            if(isLittleEndianness()) {
                val = changeEndianness(val);
            }
            return val;
        }

        static uint32_t convToBig(uint64_t val) {
            if(isLittleEndianness()) {
                val = changeEndianness(val);
            }
            return val;
        }
}
;

#endif
