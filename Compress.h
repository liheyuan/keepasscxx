#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <vector>

using std::vector;

class Compress {
    public:
        static bool gzip(vector<char>& data);
        static bool gunzip(vector<char>& data);
        static bool gzip2(const vector<char>& input, vector<char>& output);
        static bool gunzip2(const vector<char>& input, vector<char>& output);

    private:
        static void clearBuf(char*& buf);
}
;

#endif
