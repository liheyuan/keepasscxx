#include "AbstractKDBReader.h"
#include "Endian.h"
#include "Crypto.h"

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

bool AbstractKDBReader::generateCompositeKey(const string& password, const string& fileName, vector<char>& outputVec) {
    // first hash the password
    vector<char> aSha256Vec;
    if(!password.empty()) {
        if(!Crypto::sha256(password, aSha256Vec)) {
            return false;
        }
    }

    // than hash fileName if not empty
    vector<char> bSha256Vec;
    if(!fileName.empty()) {
        if(!Crypto::sha256ByFile(fileName, bSha256Vec)) {
            return false;
        }
    }

    // concat a, b(if not empty)
    vector<char> tmpVec;
    tmpVec.assign(aSha256Vec.begin(), aSha256Vec.end());
    if(!bSha256Vec.empty()) {
        tmpVec.insert(tmpVec.end(), bSha256Vec.begin(), bSha256Vec.end());
    }

    // and final sha256
    if(!Crypto::sha256(tmpVec, outputVec)) {
        return false;
    }

    return true;
}

bool AbstractKDBReader::generateCompositeKeyHex(const string& password, const string& fileName, string& outputStr) {
    vector<char> outputVec;
    if(!generateCompositeKey(password, fileName, outputVec)) {
        return false;
    }
    if(!Crypto::digestToHex(outputVec, outputStr)) {
        return false;
    }
    return true;
}
