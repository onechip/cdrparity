CC		= gcc
CXX		= g++
CXXLD		= g++

PREFFLAGS	= -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wall -Wextra -O2
CFLAGS		= $(PREFFLAGS)
CXXFLAGS	= $(PREFFLAGS)
LDFLAGS		=

ALL_PROGS	= cdrparity cdrverify cdrrescue
COMMON_OBJS	= Marker.o
COMMON_HEADERS	=


all:	$(ALL_PROGS)

install:	$(ALL_PROGS)
	cp $(ALL_PROGS) ../../bin

cdrparity:	$(COMMON_OBJS) cdrparity.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

cdrrescue:	$(COMMON_OBJS) cdrrescue.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

cdrverify:	cdrverify.o
	$(CXXLD) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *% *~ *.o core $(ALL_PROGS) keylist.cpp
