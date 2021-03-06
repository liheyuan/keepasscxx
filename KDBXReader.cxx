#include "KDBXReader.h"
#include "ConvTool.h"
#include "Crypto.h"
#include "Compress.h"
#include "Endian.h"
#include "HashBlockIO.h"

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

vector<char> KDBXReader::getEncryptionIV() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_ENCRYPTION_IV);
    if(itr == mHeaderMap.end()) {
        return vector<char>();
    }
    // return copy of seed directly
    return itr->second;
}

vector<char> KDBXReader::getStreamStart() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_STREAM_START_BYTES);
    if(itr == mHeaderMap.end()) {
        return vector<char>();
    }
    // return copy of seed directly
    return itr->second;
}

bool KDBXReader::generateMasterKey(const string& password, const string& keyFileName) {
    return generateMasterKey(password, keyFileName, mMasterKey);
}

bool KDBXReader::decryptBody(vector<char>& bodyAfter) {
    // First read body(rest after header) as vector
    vector<char> bodyBefore;
    fseek(mFile, mHeaderLength, SEEK_SET);
    char c;
    while(1 == fread(&c, sizeof(char), 1, mFile)) {
        bodyBefore.push_back(c);
    }
    // len(bodyVec) should >= 1
    if(bodyBefore.empty()) {
        return false;
    }
    // check mMasterKey
    if(mMasterKey.empty()) {
        return false;
    }
    // check iv
    vector<char> ivVec = getEncryptionIV();
    if(ivVec.empty()) {
        return false;
    }
    // decrypt 
    if(!Crypto::aesCBCDecrypt(mMasterKey, ivVec, bodyBefore, bodyAfter)) {
        return false;
    }
    return true;
}

bool KDBXReader::verifyAndTrim(vector<char>& bodyAfter) {
    // get header verify bytes
    vector<char> headVec = getStreamStart();
    if(headVec.empty()) {
        return false;
    }
    // get same length in bodyAfter
    size_t len = headVec.size();
    if(bodyAfter.size() < len) {
        return false;
    }
    vector<char> bodyVec(bodyAfter.begin(), bodyAfter.begin() + len);
    // compare 
    if(headVec != bodyVec) {
        return false;
    } else {
        bodyAfter.erase(bodyAfter.begin(), bodyAfter.begin() + len);
        return true;
    }
}

bool KDBXReader::decrypt(const string& password, const string& keyFileName, vector<char>& output) {
    if(!generateMasterKey(password, keyFileName)) {
        return false;
    }
    // decrypt
    vector<char> bodyAfter;
    if(!decryptBody(bodyAfter)) {
        return false;
    }
    // unpadding
    if(!Crypto::aesUnpad(bodyAfter)) {
        return false;
    }
    // verify head
    if(!verifyAndTrim(bodyAfter)) {
        return false;
    }
    vector<char> compressData;
    if(!removeBlock(bodyAfter, compressData)) {
        return false;
    }
    // decompress
    if(!decompress(compressData, output)) {
        return false;
    }
    return true;
}

bool KDBXReader::removeBlock(const vector<char>& input, vector<char>& output) {
    HashBlockIO hbio;
    hbio.initRead((char*)input.data(), input.size());
    vector<char> tmpVec;
    output.clear();
    while(hbio.readBlock(tmpVec)) {
        output.insert(output.end(), tmpVec.begin(), tmpVec.end());
    }
    return output.size() > 0;
}

bool KDBXReader::decompress(const vector<char>& data, vector<char>& output) {
    // check if need decompress
    switch(getCompression()) {
        case NONE:
        case UNKNOWN:
            break;
        case GZIP:
            //FILE* fp = fopen("data", "wb");
            //fwrite(data.data(), sizeof(char), data.size(), fp);
            //fclose(fp);
            output.clear();
            if(!Compress::gunzip2(data, output)) {
                return false;
            }
            //for(size_t i=0; i<output.size(); i++) {
            //    printf("%c", output[i]);
            //}
            //printf("\n");
            break;
    }
    return true;
}

vector<char> KDBXReader::getProtectedStreamKey() {
    // check map data contains
    HeaderMap::iterator itr = mHeaderMap.find(KDBX_HEADER_PROTECTED_STREAM_KEY);
    if(itr == mHeaderMap.end()) {
        return vector<char>();
    }
    // return copy of seed directly
    return itr->second;
}

bool KDBXReader::unprotect(const string& input, string& output) {
    
    // get data in vector
    vector<char> inputVec;
    if(!Crypto::stringToVec(input, inputVec)) {
        return false;
    }
    // base64decode
    vector<char> inputNo64Vec;
    if(!Crypto::base64Decode(inputVec, inputNo64Vec)) {
        return false;
    }
    // get next salsa20 vec 
    vector<char> salsa20Vec;
    if(!getSalsa20ArrByLen(inputNo64Vec.size(), salsa20Vec)) {
        return false;
    }
   
    // xor 
    vector<char> finalVec;
    if(!Crypto::xorVec(inputNo64Vec, salsa20Vec, finalVec)) {
        return false;
    }

    // convert to string
    return Crypto::vecToString(finalVec, output);
}

bool KDBXReader::getSalsa20ArrByLen(size_t len, vector<char>& output) {
    // get stream key
    vector<char> streamKey = getProtectedStreamKey();
    // sha256(stream key)
    vector<char> streamKeySha256;
    if(!Crypto::sha256(streamKey, streamKeySha256)) {
        return false;
    }
    // get stream iv
    vector<char> streamIV;
    for(size_t i=0; i<KDBX_STREAM_IV_LEN; i++) {
        streamIV.push_back(KDBX_STREAM_IV[i]);
    }
    // extend salsa20 buf if not enough
    vector<char> vecb64(64, 0);
    while(mSalsa20Arr.size() < len) {
        vector<char> tmpVec;
        if(!Crypto::salsa20Encrypt(streamKeySha256, streamIV, vecb64, tmpVec)) {
            return false;
        }
        mSalsa20Arr.insert(mSalsa20Arr.end(), tmpVec.begin(), tmpVec.end());
    }

    if(mSalsa20Arr.size() >= len) {
        // return salsa20Buf
        output.assign(mSalsa20Arr.begin(), mSalsa20Arr.begin() + len);
        // clear used buf
        mSalsa20Arr.erase(mSalsa20Arr.begin(), mSalsa20Arr.begin() + len);
        return true;
    } else {
        return false;
    }
}

void KDBXReader::clearSalsa20Arr() {
    mSalsa20Arr.clear();
}
