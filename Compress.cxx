#include <cryptopp/gzip.h>
// #include <zlib/zlib.h>
#include "Compress.h"

/*
bool Compress::gzip(vector<char>& data) {
    // get gzipper
    CryptoPP::Gzip zipper;
    zipper.Put((byte*)data.data(), sizeof(char) * data.size());
    zipper.MessageEnd();
    // gzip
    size_t avail = zipper.MaxRetrievable();
    if(avail)
    {
        vector<char> compressed;
        compressed.resize(avail);
        zipper.Get((byte*)&compressed[0], compressed.size());
        data.assign(compressed.begin(), compressed.end());
        return true;
    } else {
        return false;
    }
    return true;
}

bool Compress::gunzip(vector<char>& data) {
    // get unzipper
    CryptoPP::Gunzip unzipper(NULL, true);
    unzipper.Put((byte*)data.data(), sizeof(char) * data.size());
    unzipper.MessageEnd();
    // gunzip
    size_t avail = unzipper.MaxRetrievable();
    if(avail)
    {
        vector<char> decompressed;
        decompressed.resize(avail);
        unzipper.Get(reinterpret_cast<byte*>(&decompressed[0]), decompressed.size());
        data.assign(decompressed.begin(), decompressed.end());
        return true;
    } else {
        return false;
    }
}
*/

bool Compress::gzip2(const vector<char>& input, vector<char>& output) {
    return true;
}

bool Compress::gunzip2(const vector<char>& input, vector<char>& output) {
    return true;
}
