#include "KDBXReader.h"
#include "Endian.h"
#include "ConvTool.h"
#include "Crypto.h"

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

        // Check if header end
        if(type == KDBX_HEADER_END_OF_HEADER) {
            // record position and break
            mHeaderLength = ftell(mFile);
            break;
        }
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

vector<char> KDBXReader::getTransformSeed() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_TRANSFORM_SEED);
    if(itr == mHeaderMap.end()) {
        return vector<char>();
    }
    // return copy of seed directly
    return itr->second;
}


bool KDBXReader::generateMasterKey(const string& password, const string& fileName, vector<char>& outputVec) {
    // first get composite key
    vector<char> compositeKeyVec;
    if(!generateCompositeKey(password, fileName, compositeKeyVec)) {
        return false;
    }
    // then get transform key using aes for rounds
    uint64_t tRounds = getTransformRounds();
    vector<char> tSeed = getTransformSeed();
    vector<char> tmpVec; // will reuse
    vector<char> transformVec;
    if(!Crypto::aesECBEncrypt(tSeed, compositeKeyVec, tmpVec, tRounds)) {
        return false;
    }
    if(!Crypto::sha256(tmpVec, transformVec)) {
        return true;
    }
    // sha256(masterseed + transform_key)
    vector<char> masterSeed = getMasterSeed(); 
    tmpVec.clear();
    if(!masterSeed.empty()) {
        tmpVec.assign(masterSeed.begin(), masterSeed.end());
    }
    if(!transformVec.empty()) {
        tmpVec.insert(tmpVec.end(), transformVec.begin(), transformVec.end());
    }
    return Crypto::sha256(tmpVec, outputVec);
}

vector<char> KDBXReader::getMasterSeed() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_MASTER_SEED);
    if(itr == mHeaderMap.end()) {
        return vector<char>();
    }
    // return copy of seed directly
    return itr->second;
}
