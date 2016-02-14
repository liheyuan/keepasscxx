#Const
#CRYPTO_CXX_PREFIX = /usr/
CRYPTO_CXX_PREFIX = /usr/local/Cellar/cryptopp/5.6.2
#Compiler and flags
CC = g++
LD = g++
CXXFLAGS := -I. -I /usr/include -I$(CRYPTO_CXX_PREFIX)/include -std=c++0x
LINKFLAGS := $(CRYPTO_CXX_PREFIX)/lib/libcryptopp.a -lz 
#Objects
OBJS := $(patsubst %.cxx, %.o, $(wildcard *.cxx)) \
        $(patsubst %.cxx, %.o, $(wildcard ./common/*.cxx))
#Generate binary name
PROGS = main.bin 

#Binary
all: $(PROGS)
          
$(PROGS): $(OBJS)
	$(LD) $(OBJS) $(LINKFLAGS) -o $(PROGS)
               
%.o:%.cxx
	$(CC) $(CXXFLAGS) -c -o $@ $<
                     
.PHONY: all clean
clean:
	rm -rf $(OBJS) $(OJBS:.o=.d) $(PROGS)
