#include <cryptopp/gzip.h>
#include <zlib.h>
// #include <zlib/zlib.h>
#include "Compress.h"

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

bool Compress::gzip2(const vector<char>& input, vector<char>& output) {
    // init stream
    z_stream strm = {0};
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = (Byte*)&input[0];
    strm.avail_in = input.size();
    if(deflateInit2(&strm, 9, Z_DEFLATED,
                31, 8,
                Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }
    // compress
    output.clear();
    const size_t CHUNK = 0x4000; // zlib default
    char* buf = new char[CHUNK + 1];
    int err;
    bool haveErr = false;
    do {
        size_t have;
        strm.avail_out = CHUNK;
        strm.next_out = (Byte*)buf;
        err = deflate (& strm, Z_FINISH);
        if(err == Z_OK || err == Z_STREAM_END) {
            have = CHUNK - strm.avail_out;
            printf("%ld\n", have);
            if(have > 0) {
                output.insert(output.end(), buf, buf + have);
            }
        }else {
            haveErr = true;
            printf("have err %d\n", err);
            break;
        }
    }
    while (strm.avail_out == 0);
    deflateEnd(& strm);
    if(buf) {
        delete [] buf;
        buf = NULL;
    }
    if(haveErr) {
        return false;
    }
    return true;
}

bool Compress::gunzip2(const vector<char>& input, vector<char>& output) {
    // init stream
    z_stream strm = {0};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = (Byte*)&input[0];
    strm.avail_in = 0;
    if(inflateInit2(&strm, MAX_WBITS + 16) != Z_OK) {
        return false;
    }
    // small buf
    const size_t CHUNK = 512;
    char* buf = new char[CHUNK];
    // decompress
    output.clear();
    size_t remain = input.size();
    int err;
    const size_t READ_BATCH = 16;
    bool haveErr = false;
    while(true) {
        // set next read batch
        strm.avail_in = READ_BATCH;
        if(remain < READ_BATCH) {
            strm.avail_in = remain;
        }
        // read until have out
        do {
            strm.next_out = (Byte*)buf;
            strm.avail_out = CHUNK;
            err = inflate (&strm, Z_NO_FLUSH);
            if(err == Z_OK) {
                size_t have = CHUNK - strm.avail_out;
                // printf("have %ld\n", have);
                if( have > 0 ) {
                    output.insert(output.end(), buf, buf + have);
                }
                remain -= 1;
            } else if(err == Z_STREAM_END) {
                remain = 0;
                break;
            } else {
                return false;
            }
        }
        while (strm.avail_out == 0 && remain > 0 && !haveErr);
        // check if should end or have err
        if(remain == 0 || haveErr) {
            inflateEnd (& strm);
            break;
        }
    }
    // clean buf
    if(buf != NULL) {
        delete [] buf;
        buf = NULL;
    }
    if(haveErr) {
        return false;
    }
    return true;
}
