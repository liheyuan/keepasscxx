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
    std::copy( input.begin(), input.end(), std::back_inserter(inputVec));
    // sha256(vec)
    vector<char> outputVec;
    if(!sha256(inputVec, outputVec)) {
        return false;
    }
    // debug
    output.clear();
    CryptoPP::HexEncoder encoder;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( reinterpret_cast<const byte*>(&outputVec[0]), sizeof(char)*outputVec.size() );
    encoder.MessageEnd();
    return true;
}
