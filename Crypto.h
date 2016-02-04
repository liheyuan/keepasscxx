#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <vector>
#include <string>

using std::string;
using std::vector;

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

        // util
        static bool stringToVec(const string& str, vector<char>& vec);
        static bool digestToHex(const vector<char>& input, string& output);
}
;

#endif
