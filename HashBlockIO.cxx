#include "HashBlockIO.h"
#include "Endian.h"
#include "ConvTool.h"
#include "Crypto.h"

HashBlockIO::HashBlockIO()
:mSrcData(NULL), mSrcLen(0), mSrcPos(0), mMode(0){
}

void HashBlockIO::init(char* data, size_t len, int mode) {
    mSrcData = data;
    mSrcLen = len;
    mSrcPos = 0;
    mMode = mode;
}

void HashBlockIO::initRead(char* data, size_t len) {
    init(data, len, HASH_BLOCK_READ);
}

void HashBlockIO::initWrite(char* data, size_t len) {
    init(data, len, HASH_BLOCK_WRITE);
}

bool HashBlockIO::readBlock(vector<char>& output) {
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

bool HashBlockIO::enough(size_t len) {
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

void HashBlockIO::incSrcPos(size_t add) {
    mSrcPos += add;
}
