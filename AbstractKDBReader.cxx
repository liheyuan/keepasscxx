#include "AbstractKDBReader.h"
#include "Endian.h"

AbstractKDBReader::~AbstractKDBReader() {
    if(mFile) {
        fclose(mFile);
        mFile = NULL;
    }
}
bool AbstractKDBReader::open(const string& filename) {
    mFileName.assign(filename);
    // open & test
    mFile = fopen(mFileName.c_str(), "rb");
    if(!mFile) {
        return false;
    }
    return true;
}

bool AbstractKDBReader::checkSignature() {
    // check file
    if(!mFile) {
        return false;
    }
    // rewind
    rewind(mFile);
    // signature 1
    uint32_t sig1;
    if(1 != fread(&sig1, sizeof(uint32_t), 1, mFile)) {
        return false;
    }
    if(!checkSig1(Endian::convToLittle(sig1))) {
        return false;
    }
    // signature 2
    uint32_t sig2;
    if(1 != fread(&sig2, sizeof(uint32_t), 1, mFile)) {
        return false;
    }
    if(!checkSig2(Endian::convToLittle(sig2))) {
        return false;
    }

    return true;
}

bool AbstractKDBReader::checkSig1(uint32_t val) {
    return val == KDB_SIG1;
}
