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
        // aes

        // util
        static bool stringToVec(const string& str, vector<char>& vec);
        static bool digestToHex(const vector<char>& input, string& output);
}
;

#endif
