#ifndef _HASH_BLOCK_IO_H
#define _HASH_BLOCK_IO_H

#define HASH_BLOCK_READ 0
#define HASH_BLOCK_WRITE 1
#define HASH_BLOCK_DEFAULT_SIZE 1024 * 1024

#include <iostream>
#include <vector>
using std::vector;

class HashBlockIO {

    public:
        HashBlockIO();

        // init func
        void initRead(char* data, uint32_t len);
        void initWrite(char* data, uint32_t len);

        // read block return value means current success (and should try next)
        bool readBlock(vector<char>& output);
        // write block
        bool writeBlock(vector<char>& output, uint32_t blockSize = HASH_BLOCK_DEFAULT_SIZE);

    private:
        void init(char* data, uint32_t len, int mode);
        char* getSrcCur();
        void incSrcPos(uint32_t add);
        bool enough(uint32_t len);

    private:
        char* mSrcData; // read / write src data
        uint32_t mSrcLen;
        uint32_t mSrcPos; // current pos
        uint32_t mWriteIndex; // index
        int mMode; // 1 is 
};

#endif
