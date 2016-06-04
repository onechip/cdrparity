CC		= gcc
CXX		= g++
CXXLD		= g++

PREFFLAGS	= -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wall -Wextra -Os
CFLAGS		= $(PREFFLAGS)
CXXFLAGS	= $(PREFFLAGS) -std=c++11
LDFLAGS		=

PROGS	= siphash24_test cdrparity cdrparity-v1 cdrverify cdrrescue

all:	$(PROGS)

install:	$(PROGS)
	cp $(PROGS) ../../bin

siphash24_test:	siphash24_test.o siphash24.o siphash24inc.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

cdrparity:	cdrparity.o siphash24inc.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

cdrparity-v1:	cdrparity-v1.o Marker.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

cdrverify:	cdrverify.o cdrverify-v1.o cdrverify-v2.o siphash24.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

cdrrescue:	cdrrescue.o Marker.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(PROGS) *.o *~ core
