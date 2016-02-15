#include "HashBlockIO.h"
#include "Endian.h"
#include "ConvTool.h"
#include "Crypto.h"

HashBlockIO::HashBlockIO()
:mSrcData(NULL), mSrcLen(0), mSrcPos(0), mMode(0), mWriteIndex(0){
}

void HashBlockIO::init(char* data, uint32_t len, int mode) {
    mSrcData = data;
    mSrcLen = len;
    mSrcPos = 0;
    mMode = mode;
}

void HashBlockIO::initRead(char* data, uint32_t len) {
    init(data, len, HASH_BLOCK_READ);
}

void HashBlockIO::initWrite(char* data, uint32_t len) {
    init(data, len, HASH_BLOCK_WRITE);
}

bool HashBlockIO::readBlock(vector<char>& output) {
    // check mode
    if(mMode != HASH_BLOCK_READ) {
        return false;
    }
    // clear output
    output.clear();
    // check if have enough len for 4 + 32 + 4 = 40 Bytes
    if(!enough(40)) {
        // not enough
        return false;
    }
    // read hash head
    char* p = NULL;
    uint32_t index, len;
    // read index
    p = getSrcCur();
    if(!p) {
        return false;
    }
    if(!ConvTool::charToU32(p, index)) {
        return false;
    }
    index = Endian::convToLittle(index);
    incSrcPos(4);
    // read hash
    p = getSrcCur(); 
    if(!p) {
        return false;
    }
    vector<char> hash(p, p+32);
    incSrcPos(32);
    // read len
    p = getSrcCur();
    if(!p) {
        return false;
    }
    if(!ConvTool::charToU32(p, len)) {
        return false;
    }
    len = Endian::convToLittle(len);
    incSrcPos(4);
    // check if finished
    if(len == 0) {
        return false;
    } else {
        // read data
        if(!enough(len)) {
            return false;
        }
        p = getSrcCur();
        if(!p) {
            return false;
        }
        vector<char> data(p, p+len);
        incSrcPos(len);
        // verify sha256
        vector<char> hash2;
        if(!Crypto::sha256(data, hash2)) {
            return false;
        }
        if(hash2 != hash) {
            return false;
        }
        // all pass
        output.assign(data.begin(), data.end());
        return true;
    }
}

bool HashBlockIO::writeBlock(vector<char>& output, uint32_t blockSize) {
    output.clear();
    if(mMode != HASH_BLOCK_WRITE) {
        return false;
    }
    // judge if have enough data
    if(!enough(1)) {
        return false;
    } else {
        if(mSrcPos >= mSrcLen) {
            return false;
        }
        // check cur block size
        uint32_t len = mSrcLen - mSrcPos;
        if(len > blockSize) {
            len = blockSize;
        }
        // write index
        vector<char> tmp;
        ConvTool::U32ToVecReverse(mWriteIndex++, tmp);
        output.insert(output.end(), tmp.begin(), tmp.end());
        // prepare data & calculate hash
        char* p = getSrcCur();
        if(!p) {
            return false;
        }
        vector<char> data(p, p+len);
        vector<char> hash;
        if(!Crypto::sha256(data, hash)) {
            return false;
        }
        // write hash
        output.insert(output.end(), hash.begin(), hash.end());
        // write len
        ConvTool::U32ToVecReverse(len, tmp);
        output.insert(output.end(), tmp.begin(), tmp.end());
        // write data
        output.insert(output.end(), data.begin(), data.end());
        incSrcPos(len);
        // check if finished
        if(!enough(1)) {
            // index 
            ConvTool::U32ToVecReverse(mWriteIndex++, tmp);
            output.insert(output.end(), tmp.begin(), tmp.end());
            // hash 32 * 0
            for(size_t i=0; i<32; i++) {
                output.push_back(0);
            }
            // len = 0
            uint32_t lenTmp = 0;
            ConvTool::U32ToVecReverse(lenTmp, tmp);
            output.insert(output.end(), tmp.begin(), tmp.end());
        }
        return true;
    }
}

bool HashBlockIO::enough(uint32_t len) {
    if(mSrcPos < mSrcLen && mSrcLen - mSrcPos >= len) {
        return true;
    } else {
        return false;
    }
}

char* HashBlockIO::getSrcCur() {
    if(mSrcData != NULL && mSrcPos < mSrcLen) {
        return mSrcData + mSrcPos;
    } else {
        return NULL;
    }
}

void HashBlockIO::incSrcPos(uint32_t add) {
    mSrcPos += add;
}
