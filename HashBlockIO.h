#ifndef _HASH_BLOCK_IO_H
#define _HASH_BLOCK_IO_H

#define HASH_BLOCK_READ 0
#define HASH_BLOCK_WRITE 1

#include <iostream>
#include <vector>
using std::vector;

class HashBlockIO {

    public:
        HashBlockIO();

        // init func
        void initRead(char* data, size_t len);
        void initWrite(char* data, size_t len);

        // read block return value means current success (and should try next)
        bool readBlock(vector<char>& output);
        // write block
        bool writeBlock(vector<char>& output);

    private:
        void init(char* data, size_t len, int mode);
        char* getSrcCur();
        void incSrcPos(size_t add);
        bool enough(size_t len);

    private:
        char* mSrcData; // read / write src data
        size_t mSrcLen;
        size_t mSrcPos; // current pos
        int mMode; // 1 is 
};

#endif
