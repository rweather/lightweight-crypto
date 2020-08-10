
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = kat
TARGET2 = kat-gen

OBJS1 = \
    kat.o \
    algorithms.o

OBJS2 = \
    kat-gen.o \
    algorithms.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

$(TARGET2): $(OBJS2) $(DEPS)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

RUN_KAT = $(SHELL) ./kat-run.sh ./$(TARGET1) ./$(TARGET2)

check: $(TARGET1) $(TARGET2)
	@$(RUN_KAT) ACE ACE.txt
	@$(RUN_KAT) ACE-HASH ACE-HASH.txt
	@$(RUN_KAT) ASCON-128 ASCON-128.txt
	@$(RUN_KAT) ASCON-128a ASCON-128a.txt
	@$(RUN_KAT) ASCON-80pq ASCON-80pq.txt
	@$(RUN_KAT) ASCON-128-Masked ASCON-128.txt
	@$(RUN_KAT) ASCON-128a-Masked ASCON-128a.txt
	@$(RUN_KAT) ASCON-80pq-Masked ASCON-80pq.txt
	@$(RUN_KAT) ASCON-HASH ASCON-HASH.txt
	@$(RUN_KAT) ASCON-XOF ASCON-XOF.txt
	@$(RUN_KAT) COMET-128_CHAM-128/128 COMET-128-CHAM.txt
	@$(RUN_KAT) COMET-64_CHAM-64/128 COMET-64-CHAM.txt
	@$(RUN_KAT) COMET-64_SPECK-64/128 COMET-64-SPECK.txt
	@$(RUN_KAT) Delirium Delirium.txt
	@$(RUN_KAT) DryGASCON128 DryGASCON128.txt
	@$(RUN_KAT) DryGASCON256 DryGASCON256.txt
	@$(RUN_KAT) DryGASCON128-HASH DryGASCON128-HASH.txt
	@$(RUN_KAT) DryGASCON256-HASH DryGASCON256-HASH.txt
	@$(RUN_KAT) Dumbo Dumbo.txt
	@$(RUN_KAT) Esch256 Esch256.txt
	@$(RUN_KAT) Esch384 Esch384.txt
	@$(RUN_KAT) ESTATE_TweGIFT-128 ESTATE-TWEGIFT-128.txt
	@$(RUN_KAT) GIFT-COFB GIFT-COFB.txt
	@$(RUN_KAT) GIFT-COFB-Masked GIFT-COFB.txt
	@$(RUN_KAT) GIMLI-24 GIMLI-24-CIPHER.txt
	@$(RUN_KAT) GIMLI-24-Masked GIMLI-24-CIPHER.txt
	@$(RUN_KAT) GIMLI-24-HASH GIMLI-24-HASH.txt
	@$(RUN_KAT) Grain-128AEAD Grain-128AEAD.txt
	@$(RUN_KAT) HYENA-v1 HYENA-v1.txt
	@$(RUN_KAT) HYENA-v2 HYENA-v2.txt
	@$(RUN_KAT) ISAP-A-128 ISAP-A-128.txt
	@$(RUN_KAT) ISAP-A-128A ISAP-A-128A.txt
	@$(RUN_KAT) ISAP-K-128 ISAP-K-128.txt
	@$(RUN_KAT) ISAP-K-128A ISAP-K-128A.txt
	@$(RUN_KAT) Jumbo Jumbo.txt
	@$(RUN_KAT) KNOT-AEAD-128-256 KNOT-AEAD-128-256.txt
	@$(RUN_KAT) KNOT-AEAD-128-384 KNOT-AEAD-128-384.txt
	@$(RUN_KAT) KNOT-AEAD-192-384 KNOT-AEAD-192-384.txt
	@$(RUN_KAT) KNOT-AEAD-256-512 KNOT-AEAD-256-512.txt
	@$(RUN_KAT) KNOT-HASH-256-256 KNOT-HASH-256-256.txt
	@$(RUN_KAT) KNOT-HASH-256-384 KNOT-HASH-256-384.txt
	@$(RUN_KAT) KNOT-HASH-384-384 KNOT-HASH-384-384.txt
	@$(RUN_KAT) KNOT-HASH-512-512 KNOT-HASH-512-512.txt
	@$(RUN_KAT) LOCUS-AEAD LOCUS-AEAD.txt
	@$(RUN_KAT) LOTUS-AEAD LOTUS-AEAD.txt
	@$(RUN_KAT) ORANGE-Zest ORANGE-Zest.txt
	@$(RUN_KAT) ORANGISH ORANGISH.txt
	@$(RUN_KAT) Oribatida-256-64 Oribatida-256-64.txt
	@$(RUN_KAT) Oribatida-192-96 Oribatida-192-96.txt
	@$(RUN_KAT) PAEF-ForkSkinny-64-192 PAEF-ForkSkinny-64-192.txt
	@$(RUN_KAT) PAEF-ForkSkinny-128-192 PAEF-ForkSkinny-128-192.txt
	@$(RUN_KAT) PAEF-ForkSkinny-128-256 PAEF-ForkSkinny-128-256.txt
	@$(RUN_KAT) PAEF-ForkSkinny-128-288 PAEF-ForkSkinny-128-288.txt
	@$(RUN_KAT) PHOTON-Beetle-AEAD-ENC-128 PHOTON-Beetle-AEAD-ENC-128.txt
	@$(RUN_KAT) PHOTON-Beetle-AEAD-ENC-32 PHOTON-Beetle-AEAD-ENC-32.txt
	@$(RUN_KAT) PHOTON-Beetle-HASH PHOTON-Beetle-HASH.txt
	@$(RUN_KAT) Pyjamask-128-AEAD Pyjamask-128-AEAD.txt
	@$(RUN_KAT) Pyjamask-96-AEAD Pyjamask-96-AEAD.txt
	@$(RUN_KAT) Pyjamask-128-AEAD-Masked Pyjamask-128-AEAD.txt
	@$(RUN_KAT) Pyjamask-96-AEAD-Masked Pyjamask-96-AEAD.txt
	@$(RUN_KAT) Romulus-N1 Romulus-N1.txt
	@$(RUN_KAT) Romulus-N2 Romulus-N2.txt
	@$(RUN_KAT) Romulus-N3 Romulus-N3.txt
	@$(RUN_KAT) Romulus-M1 Romulus-M1.txt
	@$(RUN_KAT) Romulus-M2 Romulus-M2.txt
	@$(RUN_KAT) Romulus-M3 Romulus-M3.txt
	@$(RUN_KAT) SAEF-ForkSkinny-128-192 SAEF-ForkSkinny-128-192.txt
	@$(RUN_KAT) SAEF-ForkSkinny-128-256 SAEF-ForkSkinny-128-256.txt
	@$(RUN_KAT) SATURNIN-CTR-Cascade SATURNIN-CTR-Cascade.txt
	@$(RUN_KAT) SATURNIN-Short SATURNIN-Short.txt --max-ad=0 --max-pt=15
	@$(RUN_KAT) SATURNIN-Hash SATURNIN-Hash.txt
	@$(RUN_KAT) Schwaemm256-128 Schwaemm256-128.txt
	@$(RUN_KAT) Schwaemm192-192 Schwaemm192-192.txt
	@$(RUN_KAT) Schwaemm128-128 Schwaemm128-128.txt
	@$(RUN_KAT) Schwaemm256-256 Schwaemm256-256.txt
	@$(RUN_KAT) SKINNY-AEAD-M1 SKINNY-AEAD-M1.txt
	@$(RUN_KAT) SKINNY-AEAD-M2 SKINNY-AEAD-M2.txt
	@$(RUN_KAT) SKINNY-AEAD-M3 SKINNY-AEAD-M3.txt
	@$(RUN_KAT) SKINNY-AEAD-M4 SKINNY-AEAD-M4.txt
	@$(RUN_KAT) SKINNY-AEAD-M5 SKINNY-AEAD-M5.txt
	@$(RUN_KAT) SKINNY-AEAD-M6 SKINNY-AEAD-M6.txt
	@$(RUN_KAT) SKINNY-tk2-HASH SKINNY-tk2-HASH.txt
	@$(RUN_KAT) SKINNY-tk3-HASH SKINNY-tk3-HASH.txt
	@$(RUN_KAT) SPIX SPIX.txt
	@$(RUN_KAT) SpoC-128 SpoC-128.txt
	@$(RUN_KAT) SpoC-128-Masked SpoC-128.txt
	@$(RUN_KAT) SpoC-64 SpoC-64.txt
	@$(RUN_KAT) SpoC-64-Masked SpoC-64.txt
	@$(RUN_KAT) Spook-128-512-su Spook-128-512-su.txt
	@$(RUN_KAT) Spook-128-384-su Spook-128-384-su.txt
	@$(RUN_KAT) Spook-128-512-mu Spook-128-512-mu.txt
	@$(RUN_KAT) Spook-128-384-mu Spook-128-384-mu.txt
	@$(RUN_KAT) Spook-128-512-su-masked Spook-128-512-su.txt
	@$(RUN_KAT) Spook-128-384-su-masked Spook-128-384-su.txt
	@$(RUN_KAT) Spook-128-512-mu-masked Spook-128-512-mu.txt
	@$(RUN_KAT) Spook-128-384-mu-masked Spook-128-384-mu.txt
	@$(RUN_KAT) Subterranean Subterranean.txt
	@$(RUN_KAT) Subterranean-Hash Subterranean-Hash.txt
	@$(RUN_KAT) SUNDAE-GIFT-0 SUNDAE-GIFT-0.txt
	@$(RUN_KAT) SUNDAE-GIFT-64 SUNDAE-GIFT-64.txt
	@$(RUN_KAT) SUNDAE-GIFT-96 SUNDAE-GIFT-96.txt
	@$(RUN_KAT) SUNDAE-GIFT-128 SUNDAE-GIFT-128.txt
	@$(RUN_KAT) TinyJAMBU-128 TinyJAMBU-128.txt
	@$(RUN_KAT) TinyJAMBU-192 TinyJAMBU-192.txt
	@$(RUN_KAT) TinyJAMBU-256 TinyJAMBU-256.txt
	@$(RUN_KAT) TinyJAMBU-128-Masked TinyJAMBU-128.txt
	@$(RUN_KAT) TinyJAMBU-192-Masked TinyJAMBU-192.txt
	@$(RUN_KAT) TinyJAMBU-256-Masked TinyJAMBU-256.txt
	@$(RUN_KAT) WAGE WAGE.txt
	@$(RUN_KAT) Xoodyak Xoodyak.txt
	@$(RUN_KAT) Xoodyak-Masked Xoodyak.txt
	@$(RUN_KAT) Xoodyak-Hash Xoodyak-Hash.txt

kat.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
kat-gen.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
algorithms.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
