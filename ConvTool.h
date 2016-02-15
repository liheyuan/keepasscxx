#ifndef _CONV_TOOL
#define _CONV_TOOL

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

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
}
;

#endif
