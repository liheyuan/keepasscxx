#include "KDBXReader.h"
#include "Endian.h"
#include "ConvTool.h"

KDBXReader::KDBXReader()
:AbstractKDBReader() {
    // Init field map
    if(KDBX_HEADER_END > KDBX_HEADER_BEGIN) {
        for(char i = KDBX_HEADER_BEGIN; i <= KDBX_HEADER_END; i++) {
            mHeaderMap[i] = vector<char>();
        }
    }
}

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

bool KDBXReader::parseHeader() {
    if(!mFile) {
        printf("1\n");
        return false;
    }
    // header start at 12 bytes start of file
    fseek(mFile, 12, SEEK_SET);
    // parse type(1B) len(2B) value(?B) list
    while(true) {
        // type
        char type;
        if(1 != fread(&type, sizeof(char), 1, mFile)) {
            return false;
        }
        // len
        uint16_t len;
        if(1 != fread(&len, sizeof(uint16_t), 1, mFile)) {
            return false;
        }
        len = Endian::convToLittle(len);
        // Check header end
        if(type == KDBX_HEADER_END_OF_HEADER) {
            break;
        }
        // Check type contains
        if(mHeaderMap.count(type) == 0) {
            // ignore unknown type
            continue;
        }
        // known type, get value
        vector<char>& data = mHeaderMap[type];
        char tmp;
        for(int i=0; i<len; i++) {
            if(1 != fread(&tmp, sizeof(char), 1, mFile)) {
                printf("error\n");
                break;
            }
            data.push_back(tmp);
        }
        printf("%d %d\n", type, len);
    }
    return true;
}

KDBXCompression KDBXReader::getCompression() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_COMPRESSION_FLAGS);
    if(itr == mHeaderMap.end()) {
        return UNKNOWN;
    }
    vector<char>& data = itr->second; 
    // check size
    uint32_t uCompression;
    if(!ConvTool::vecToU32(data, uCompression)) {
        return UNKNOWN;
    }
    // 0:none, 1:gzip
    switch(Endian::convToLittle(uCompression)) {
        case 0:
            return NONE;
        case 1:
            return GZIP;
        default:
            return UNKNOWN;
    }
}

uint64_t KDBXReader::getTransformRounds() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_TRANSFORM_ROUNDS);
    if(itr == mHeaderMap.end()) {
        return UNKNOWN;
    }
    vector<char>& data = itr->second; 
    // convert to uint64
    uint64_t rounds;
    if(!ConvTool::vecToU64(data, rounds)) {
        return 0;
    }
    return Endian::convToLittle(rounds);
}
