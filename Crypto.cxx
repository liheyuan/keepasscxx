#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
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
