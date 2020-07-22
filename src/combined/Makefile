
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-common.o \
        ace.o \
        ascon128.o \
        ascon-hash.o \
        ascon-xof.o \
        comet.o \
        drygascon.o \
        elephant.o \
        estate.o \
        forkae.o \
        gift-cofb.o \
	gimli24.o \
	grain128.o \
	hyena.o \
        isap.o \
        knot-aead.o \
        knot-hash.o \
        lotus-locus.o \
        orange.o \
        oribatida.o \
        photon-beetle.o \
        pyjamask-128.o \
        pyjamask-128-masked.o \
        pyjamask-96.o \
        pyjamask-96-masked.o \
        romulus.o \
        saturnin.o \
        skinny-aead.o \
        skinny-hash.o \
        sparkle.o \
        spix.o \
        spoc.o \
        spook.o \
        subterranean.o \
        sundae-gift.o \
        tinyjambu.o \
        wage.o \
        xoodyak.o \
	internal-ascon.o \
	internal-blake2s.o \
	internal-chachapoly.o \
	internal-cham.o \
	internal-drysponge.o \
	internal-forkskinny.o \
	internal-gift128.o \
	internal-gift64.o \
	internal-gimli24.o \
	internal-grain128.o \
	internal-keccak.o \
        internal-knot.o \
	internal-masking.o \
	internal-photon256.o \
	internal-pyjamask.o \
	internal-pyjamask-m.o \
	internal-saturnin.o \
	internal-simp.o \
	internal-sliscp-light.o \
	internal-skinny128.o \
        internal-sparkle.o \
        internal-speck64.o \
        internal-spongent.o \
        internal-spook.o \
        internal-subterranean.o \
        internal-tinyjambu.o \
        internal-wage.o \
        internal-xoodoo.o

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
ace.o: ace.h aead-common.h internal-util.h internal-sliscp-light.h
ascon128.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
ascon-hash.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
ascon-xof.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
comet.o: comet.h aead-common.h internal-cham.h internal-speck64.h internal-util.h
drygascon.o: drygascon.h internal-drysponge.h internal-util.h
elephant.o: elephant.h aead-common.h internal-keccak.h internal-spongent.h internal-util.h
estate.o: estate.h aead-common.h internal-gift128.h internal-gift128-config.h internal-util.h
forkae.o: forkae.h aead-common.h internal-forkskinny.h internal-forkae-paef.h internal-forkae-saef.h internal-util.h
gift-cofb.o: gift-cofb.h aead-common.h internal-gift128.h internal-gift128-config.h internal-util.h
gimli24.o: gimli24.h internal-gimli24.h aead-common.h internal-util.h
grain128.o: grain128.h internal-grain128.h aead-common.h internal-util.h
hyena.o: hyena.h aead-common.h internal-gift128.h internal-gift128-config.h internal-util.h
isap.o: isap.h aead-common.h internal-isap.h internal-ascon.h internal-keccak.h internal-util.h
knot-aead.o: knot.h aead-common.h internal-knot.h internal-util.h
knot-hash.o: knot.h aead-common.h internal-knot.h internal-util.h
lotus-locus.o: lotus-locus.h aead-common.h internal-gift64.h internal-util.h
orange.o: orange.h aead-common.h internal-photon256.h internal-util.h
oribatida.o: oribatida.h aead-common.h internal-simp.h internal-util.h
photon-beetle.o: photon-beetle.h internal-photon256.h internal-util.h
pyjamask-128.o: pyjamask.h internal-ocb.h internal-pyjamask.h internal-util.h
pyjamask-128-masked.o: pyjamask-masked.h internal-ocb.h internal-pyjamask-m.h internal-util.h internal-masking.h
pyjamask-96.o: pyjamask.h internal-ocb.h internal-pyjamask.h internal-util.h
pyjamask-96-masked.o: pyjamask-masked.h internal-ocb.h internal-pyjamask-m.h internal-util.h internal-masking.h
romulus.o: romulus.h internal-skinny128.h aead-common.h internal-util.h
saturnin.o: saturnin.h aead-common.h internal-saturnin.h internal-util.h
skinny-aead.o: skinny-aead.h internal-skinny128.h aead-common.h internal-util.h
skinny-hash.o: skinny-hash.h internal-skinny128.h aead-common.h internal-util.h
sparkle.o: sparkle.h internal-sparkle.h aead-common.h internal-util.h
spix.o: spix.h aead-common.h internal-util.h internal-sliscp-light.h
spoc.o: spoc.h aead-common.h internal-util.h internal-sliscp-light.h
spook.o: spook.h aead-common.h internal-util.h internal-spook.h
subterranean.o: subterranean.h aead-common.h internal-util.h internal-subterranean.h
sundae-gift.o: sundae-gift.h aead-common.h internal-gift128.h internal-gift128-config.h internal-util.h
tinyjambu.o: tinyjambu.h internal-tinyjambu.h aead-common.h internal-util.h
wage.o: wage.h internal-wage.h aead-common.h internal-util.h
xoodyak.o: xoodyak.h internal-xoodoo.h aead-common.h internal-util.h
internal-ascon.o: internal-ascon.h internal-util.h
internal-blake2s.o: internal-blake2s.h internal-util.h
internal-chachapoly.o: internal-chachapoly.h internal-util.h
internal-cham.o: internal-cham.h internal-util.h
internal-drysponge.o: internal-drysponge.h internal-util.h
internal-forkskinny.o: internal-forkskinny.h internal-skinnyutil.h internal-util.h
internal-gift128.o: internal-gift128.h internal-gift128-config.h internal-util.h
internal-gift64.o: internal-gift64.h internal-util.h
internal-gimli24.o: internal-gimli24.h internal-util.h
internal-grain128.o: internal-grain128.h internal-util.h
internal-keccak.o: internal-keccak.h internal-util.h
internal-knot.o: internal-knot.h internal-util.h
internal-masking.o: internal-masking.h
internal-photon256.o: internal-photon256.h internal-util.h
internal-pyjamask.o: internal-pyjamask.h internal-util.h
internal-pyjamask-m.o: internal-pyjamask-m.h internal-util.h internal-masking.h
internal-saturnin.o: internal-saturnin.h internal-util.h
internal-simp.o: internal-simp.h internal-util.h
internal-sliscp-light.o: internal-sliscp-light.h internal-util.h
internal-skinny128.o: internal-skinny128.h internal-skinnyutil.h internal-util.h
internal-sparkle.o: internal-sparkle.h internal-util.h
internal-speck64.o: internal-speck64.h internal-util.h
internal-spongent.o: internal-spongent.h internal-util.h
internal-spook.o: internal-spook.h internal-util.h
internal-subterranean.o: internal-subterranean.h internal-util.h
internal-tinyjambu.o: internal-tinyjambu.h internal-util.h
internal-wage.o: internal-wage.h internal-util.h
internal-xoodoo.o: internal-xoodoo.h internal-util.h
