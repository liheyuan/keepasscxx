#ifndef _COMPRESS_H
#define _COMPRESS_H

#include <vector>

using std::vector;

class Compress {
    public:
        bool gzip(const vector<char>& input, vector<char>& output);
        bool gunzip(const vector<char>& input, vector<char>& output);
        bool gzip2(const vector<char>& input, vector<char>& output);
        bool gunzip2(const vector<char>& input, vector<char>& output);
}
;

#endif
