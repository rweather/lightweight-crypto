
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-common.o \
        ascon128.o \
        ascon-hash.o \
        ascon-xof.o \
        comet.o \
        estate.o \
        gift-cofb.o \
	gimli24.o \
	hyena.o \
        pyjamask-128.o \
        pyjamask-96.o \
        saturnin.o \
        skinny-aead.o \
        sparkle.o \
        sundae-gift.o \
        tinyjambu.o \
	internal-ascon.o \
	internal-chachapoly.o \
	internal-cham.o \
	internal-gift128.o \
	internal-keccak.o \
	internal-pyjamask.o \
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
comet.o: comet.h aead-common.h internal-cham.h internal-util.h
estate.o: estate.h aead-common.h internal-gift128.h internal-util.h
gift-cofb.o: gift-cofb.h aead-common.h internal-gift128.h internal-util.h
gimli24.o: gimli24.h aead-common.h internal-util.h
hyena.o: hyena.h aead-common.h internal-gift128.h internal-util.h
pyjamask-128.o: pyjamask.h internal-ocb.h internal-pyjamask.h internal-util.h
pyjamask-96.o: pyjamask.h internal-ocb.h internal-pyjamask.h internal-util.h
saturnin.o: saturnin.h aead-common.h internal-util.h
skinny-aead.o: skinny-aead.h internal-skinny128.h aead-common.h internal-util.h
sparkle.o: sparkle.h aead-common.h internal-util.h
sundae-gift.o: sundae-gift.h aead-common.h internal-gift128.h internal-util.h
tinyjambu.o: tinyjambu.h aead-common.h internal-util.h
internal-ascon.o: internal-ascon.h internal-util.h
internal-chachapoly.o: internal-chachapoly.h internal-util.h
internal-gift128.o: internal-gift128.h internal-util.h
internal-keccak.o: internal-keccak.h internal-util.h
internal-pyjamask.o: internal-pyjamask.h internal-util.h
internal-skinny128.o: internal-skinny128.h internal-util.h
