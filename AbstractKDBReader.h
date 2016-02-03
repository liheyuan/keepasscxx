#ifndef _ABSTRACT_FILE_READER_H
#define _ABSTRACT_FILE_READER_H 

#include <string>
#include <cstdlib>
#include <cstdio>

using std::string;

const uint32_t KDB_SIG1 = 0x9AA2D903;

class AbstractKDBReader {
    public:
        AbstractKDBReader()
        :mFileName(""), mFile(NULL){
        }

        virtual ~AbstractKDBReader();

        // open file
        bool open(const string& filename);
        // check signature
        bool checkSignature();
        // parse header
        virtual bool parseHeader() = 0;

    protected:
        bool checkSig1(uint32_t val);
        virtual bool checkSig2(uint32_t val) = 0;

    protected:
       string mFileName; 
       FILE* mFile;
};

#endif
