#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include "Crypto.h"

bool Crypto::sha256(const vector<char> &input, vector<char>& output) {
    CryptoPP::SHA256 hash;
    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, reinterpret_cast<const byte*>(&input[0]), sizeof(char)*input.size());
    // write output
    output.clear();
    for(int i=0; i < sizeof(digest) / sizeof(char); i++) {
        output.push_back((char)digest[i]);
    }
    return true;
}

bool Crypto::sha256(const string &input, vector<char>& outputVec) {
    // make vec input
    vector<char> inputVec;
    if(!stringToVec(input, inputVec)) {
        return false;
    }
    // sha256(vec)
    return sha256(inputVec, outputVec);
}

bool Crypto::sha256Hex(const string &input, string& output) {
    // make vec input
    vector<char> inputVec;
    if(!stringToVec(input, inputVec)) {
        return false;
    }
    // sha256(vec)
    vector<char> outputVec;
    if(!sha256(inputVec, outputVec)) {
        return false;
    }
    // debug
    return digestToHex(outputVec, output);
}

bool Crypto::stringToVec(const string& str, vector<char>& vec) {
    std::copy( str.begin(), str.end(), std::back_inserter(vec));
    return true;
}

bool Crypto::digestToHex(const vector<char>& input, string& output) {
    output.clear();
    CryptoPP::HexEncoder encoder;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( reinterpret_cast<const byte*>(&input[0]), sizeof(char)*input.size() );
    encoder.MessageEnd();
    return true;
}

bool Crypto::sha256ByFile(const string& fileName, vector<char>& output) {
    // Open & load file 
    FILE* fp = fopen(fileName.c_str(), "rb");
    if(!fp) {
        return false;
    }
    vector<char> input;
    char tmp;
    while(1 == fread(&tmp, sizeof(char), 1, fp)) {
        input.push_back(tmp);
    }
    fclose(fp);
    return sha256(input, output);
}

bool Crypto::sha256HexByFile(const string& fileName, string& output) {
    vector<char> outputVec;
    if(!sha256ByFile(fileName, outputVec)) {
        return false;
    }
    return digestToHex(outputVec, output);
}

bool Crypto::aesECBEncrypt(const vector<char>& key, const vector<char>& input, vector<char>& output, uint64_t rounds) {
    // check key length
    size_t keyLen = key.size();
    if(keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return false;
    }
    // ecb inplace encrypt
    CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption e(reinterpret_cast<const byte*>(&key[0]), key.size() * sizeof(char));
    vector<char> tmpVec(input.begin(), input.end());
    byte* ptr = reinterpret_cast<byte*>(&tmpVec[0]);
    for(size_t i=0; i<rounds; i++) {
        e.ProcessData(ptr, ptr, sizeof(char) * tmpVec.size());
    }
    output.assign(tmpVec.begin(), tmpVec.end());
    return true;
}

bool Crypto::aesECBEncryptHex(const string& key, const string& input, string& output, uint64_t rounds) {
    // convert key to vec
    vector<char> keyVec;
    if(!stringToVec(key, keyVec)) {
        return false;
    }
    // convert input to vec
    vector<char> inputVec;
    if(!stringToVec(input, inputVec)) {
        return false;
    }
    // aesECBEncrypt
    vector<char> outputVec;
    if(!aesECBEncrypt(keyVec, inputVec, outputVec, rounds)) {
        return false;
    }
    // convert to hex
    return digestToHex(outputVec, output);
}

bool Crypto::aesCBCEncrypt(const vector<char>& key, const vector<char>& iv, const vector<char>& input, vector<char>& output) {
    // check key length
    size_t keyLen = key.size();
    if(keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return false;
    }
    // check iv length
    if(iv.size() != 16) {
        return false;
    }
    // ecb inplace encrypt
    const byte* pKey = reinterpret_cast<const byte*>(&key[0]);
    const byte* pIv = reinterpret_cast<const byte*>(&iv[0]);
    CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e(pKey, key.size() * sizeof(char), pIv);
    vector<char> tmpVec(input.begin(), input.end());
    byte* pTmp = reinterpret_cast<byte*>(&tmpVec[0]);
    e.ProcessData(pTmp, pTmp, sizeof(char) * tmpVec.size());
    output.assign(tmpVec.begin(), tmpVec.end());
    return true;
}

bool Crypto::aesCBCEncrypt(const string& key, const string& iv, const string& input, vector<char>& outputVec) {
    // convert key to vec
    vector<char> keyVec;
    if(!stringToVec(key, keyVec)) {
        return false;
    }
    // convert input to vec
    vector<char> inputVec;
    if(!stringToVec(input, inputVec)) {
        return false;
    }
    // convert iv to vec
    vector<char> ivVec;
    if(!stringToVec(iv, ivVec)) {
        return false;
    }
    // aesCBCEncrypt
    return aesCBCEncrypt(keyVec, ivVec, inputVec, outputVec);
}

bool Crypto::aesCBCEncryptHex(const string& key, const string& iv, const string& input, string& output) {
    // convert key to vec
    vector<char> keyVec;
    if(!stringToVec(key, keyVec)) {
        return false;
    }
    // convert input to vec
    vector<char> inputVec;
    if(!stringToVec(input, inputVec)) {
        return false;
    }
    // convert iv to vec
    vector<char> ivVec;
    if(!stringToVec(iv, ivVec)) {
        return false;
    }
    // aesCBCEncrypt
    vector<char> outputVec;
    if(!aesCBCEncrypt(keyVec, ivVec, inputVec, outputVec)) {
        return false;
    }
    // convert to hex
    return digestToHex(outputVec, output);
}

bool Crypto::aesCBCDecrypt(const vector<char>& key, const vector<char>& iv, const vector<char>& input, vector<char>& output) {
    // check key length
    size_t keyLen = key.size();
    if(keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return false;
    }
    // check iv length
    if(iv.size() != 16) {
        return false;
    }
    // ecb inplace encrypt
    const byte* pKey = reinterpret_cast<const byte*>(&key[0]);
    const byte* pIv = reinterpret_cast<const byte*>(&iv[0]);
    CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption d(pKey, key.size() * sizeof(char), pIv);
    vector<char> tmpVec(input.begin(), input.end());
    byte* pTmp = reinterpret_cast<byte*>(&tmpVec[0]);
    d.ProcessData(pTmp, pTmp, sizeof(char) * tmpVec.size());
    output.assign(tmpVec.begin(), tmpVec.end());
    return true;
}

bool Crypto::aesCBCDecrypt(const string& key, const string& iv, const vector<char>& inputVec, vector<char>& outputVec) {
    // convert key to vec
    vector<char> keyVec;
    if(!stringToVec(key, keyVec)) {
        return false;
    }
    // convert iv to vec
    vector<char> ivVec;
    if(!stringToVec(iv, ivVec)) {
        return false;
    }
    // aesCBCDecrypt
    return aesCBCDecrypt(keyVec, ivVec, inputVec, outputVec);
}

bool Crypto::aesCBCDecryptHex(const string& key, const string& iv, const string& input, string& output) {
    // convert key to vec
    vector<char> keyVec;
    if(!stringToVec(key, keyVec)) {
        return false;
    }
    // convert input to vec
    vector<char> inputVec;
    if(!stringToVec(input, inputVec)) {
        return false;
    }
    // convert iv to vec
    vector<char> ivVec;
    if(!stringToVec(iv, ivVec)) {
        return false;
    }
    // aesCBCDecrypt
    vector<char> outputVec;
    if(!aesCBCDecrypt(keyVec, ivVec, inputVec, outputVec)) {
        return false;
    }
    // convert to hex
    return digestToHex(outputVec, output);
}
