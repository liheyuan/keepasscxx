#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <vector>
#include <string>
#include <cstdint>

using std::string;
using std::vector;

#define CRYPTO_SIZE_MAX 1024 * 1024

class Crypto {
    public:
        // sha256 hash
        static bool sha256(const vector<char> &input, vector<char>& output);
        static bool sha256(const string &input, vector<char>& output);
        static bool sha256Hex(const string &input, string& output);
        static bool sha256ByFile(const string& fileName, vector<char>& output);
        static bool sha256HexByFile(const string& fileName, string& output);

        // aes ecb inplace encrypt (size must be x*aes_block_size)
        static bool aesECBEncrypt(const vector<char>& key, const vector<char>& input, vector<char>& output, uint64_t rounds = 1);
        static bool aesECBEncryptHex(const string& key, const string& input, string& output, uint64_t rounds = 1);

        // aes cbc inplace encrypt && decrypt (size must follows aes block size)
        static bool aesCBCEncrypt(const vector<char>& key, const vector<char>& iv, const vector<char>& input, vector<char>& output);
        static bool aesCBCEncrypt(const string& key, const string& iv, const string& input, vector<char>& output);
        static bool aesCBCEncryptHex(const string& key, const string& iv, const string& input, string& output);
        static bool aesCBCDecrypt(const vector<char>& key, const vector<char>& iv, const vector<char>& input, vector<char>& output);
        static bool aesCBCDecrypt(const string& key, const string& iv, const vector<char>& input, vector<char>& output);
        static bool aesCBCDecryptHex(const string& key, const string& iv, const string& input, string& output);

        // aes pad & unpad
        static bool aesUnpad(vector<char>& data);

        // salsa20 encrypt && decrypt
        static bool salsa20Decrypt(const vector<char>& key, const vector<char>& iv, const vector<char>& input, vector<char>& output);
        static bool salsa20Encrypt(const vector<char>& key, const vector<char>& iv, const vector<char>& input, vector<char>& output);

        // base64
        static bool base64Encode(const vector<char>& input, vector<char>& output);
        static bool base64Decode(const vector<char>& input, vector<char>& output);

        // util
        static bool vecToString(const vector<char>& vec, string& str);
        static bool stringToVec(const string& str, vector<char>& vec);
        static bool hexToDigest(const string& intput, vector<char>& output);
        static bool digestToHex(const vector<char>& input, string& output);
        static bool xorVec(const vector<char>& aVec, const vector<char>& bVec, vector<char>& output);
}
;

#endif
