
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-common.o \
        ascon128.o \
        ascon-hash.o \
        ascon-xof.o \
	gimli24.o \
	internal-ascon.o \
	internal-chachapoly.o \
	internal-gift128.o \
	internal-skinny128.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

individual:
	(cd ../individual ; $(MAKE) all)

aead-common.o: aead-common.h
ascon128.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
ascon-hash.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
ascon-xof.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
gimli24.o: gimli24.h aead-common.h internal-util.h
internal-ascon.o: internal-ascon.h internal-util.h
internal-chachapoly.o: internal-chachapoly.h internal-util.h
internal-gift128.o: internal-gift128.h internal-util.h
internal-skinny128.o: internal-skinny128.h internal-util.h
