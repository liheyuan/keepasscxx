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
        static bool sha256Hex(const string &input, string& output);
        // aes
}
;

#endif
