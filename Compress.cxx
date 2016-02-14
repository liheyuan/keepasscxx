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
    if(deflateInit2(&strm, 6, Z_DEFLATED,
                MAX_WBITS + 16, 8,
                Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }
    // compress
    output.clear();
    const size_t CHUNK = 16384; // zlib default
    char* buf = new char[CHUNK + 1];
    int ret;
    size_t remain = input.size();
    int flush_flag = 0;
    do {
        // set in
        if(remain < CHUNK) {
            strm.avail_in = remain;
            flush_flag = Z_FINISH;
        } else {
            strm.avail_in = CHUNK;
            flush_flag = Z_NO_FLUSH;
        }
        remain -= strm.avail_in;
        // set out
        strm.avail_out = CHUNK;
        strm.next_out = (Byte*)buf;
        // do compress
        ret = deflate (& strm, flush_flag);
        if(ret != Z_STREAM_ERROR) {
            size_t have;
            have = CHUNK - strm.avail_out;
            // printf("%ld\n", have);
            if(have > 0) {
                output.insert(output.end(), buf, buf + have);
            }
        }else {
            deflateEnd(& strm);
            clearBuf(buf);
            return false;
        }
    }
    while (flush_flag != Z_FINISH);
    deflateEnd(& strm);
    clearBuf(buf);
    return ret == Z_STREAM_END;
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
    const size_t READ_BATCH = 16;
    const size_t CHUNK = 512;
    char* buf = new char[CHUNK];
    // decompress
    output.clear();
    int ret = 0;
    size_t remain = input.size();
    do {
        if(remain < READ_BATCH) {
            strm.avail_in = remain;
        } else {
            strm.avail_in = READ_BATCH;
        }
        if(strm.avail_in == 0) {
            break;
        }

        do {
            strm.avail_out = CHUNK;
            strm.next_out = (Byte*)buf;
            ret = inflate(&strm, Z_NO_FLUSH);
            switch(ret) {
                case Z_NEED_DICT:
                ret = Z_DATA_ERROR;
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    inflateEnd(&strm);
                    clearBuf(buf);
                    return false;
            }
            size_t have = CHUNK - strm.avail_out;
            // printf("have %ld\n", have);
            if( have > 0 ) {
                output.insert(output.end(), buf, buf + have);
            }
        } while (strm.avail_out == 0);

        remain -= strm.avail_in;
    } while (ret != Z_STREAM_END);
    // clean buf
    clearBuf(buf);
    inflateEnd (& strm);
    return ret == Z_STREAM_END;
}

void Compress::clearBuf(char*& buf) {
    if(buf) {
        delete [] buf;
        buf = NULL;
    }
}
