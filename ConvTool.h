#ifndef _CONV_TOOL
#define _CONV_TOOL

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include "Endian.h"

class ConvTool {
    public:

        static bool vecToU16(const vector<char>& vec, uint16_t& val) {
            if(vec.size() != 2) {
                return false;
            }
            val = (uint16_t)(((unsigned char)vec[1] << 8) |
                    (unsigned char)vec[0]);
            return true;
        }

        static bool charToU32(const char* p, uint32_t& val) {
            if(!p) {
                return false;
            }
            val = (((unsigned char)p[3] << 24) |
             ((unsigned char)p[2] << 16) |
             ((unsigned char)p[1] << 8) |
             (unsigned char)p[0]);
            return true;
        }

        static bool vecToU32(const vector<char>& vec, uint32_t& val) {
            if(vec.size() != 4) {
                return false;
            }
            val = (((unsigned char)vec[3] << 24) |
             ((unsigned char)vec[2] << 16) |
             ((unsigned char)vec[1] << 8) |
             (unsigned char)vec[0]);
            return true;
        }

        static bool vecToU64(const vector<char>& vec, uint64_t& val) {
            if(vec.size() != 8) {
                return false;
            }
            memcpy(&val, &vec[0], sizeof(uint64_t));
            return true;
        }

        static bool U32ToVecReverse(const uint32_t val, vector<char>& vec) {
            vec.clear();
            vec.push_back(val & 0xFF);
            vec.push_back((val >> 8) & 0xFF);
            vec.push_back((val >> 16) & 0xFF);
            vec.push_back((val >> 24) & 0xFF);
            return true;
        }

        /*
        static bool U32ToVecNorm(const uint32_t val, vector<char>& vec) {
            vec.clear();
            vec.push_back((val >> 24) & 0xFF);
            vec.push_back((val >> 16) & 0xFF);
            vec.push_back((val >> 8) & 0xFF);
            vec.push_back(val & 0xFF);
            return true;
        }

        static bool U32ToVecLittle(const uint32_t val, vector<char>& vec) {
            if(Endian::isLittleEndianness()) {
                return U32ToVecReverse(val, vec);
            } else {
                return U32ToVecNorm(val, vec);
            }
        }
        */
}
;

#endif
