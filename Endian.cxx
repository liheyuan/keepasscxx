#include "Endian.h"

uint16_t Endian::convToLittle(uint16_t val) {
    if(isBigEndianness()) {
        val = changeEndianness(val);
    }
    return val;
}

uint32_t Endian::convToLittle(uint32_t val) {
    if(isBigEndianness()) {
        val = changeEndianness(val);
    }
    return val;
}

uint32_t Endian::convToLittle(uint64_t val) {
    if(isBigEndianness()) {
        val = changeEndianness(val);
    }
    return val;
}

