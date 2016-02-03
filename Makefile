#Compiler and flags
CC = g++
LD = g++
CXXFLAGS := -O3 -I /usr/include
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
