
SRCDIR = ../combined

COMMON_FILES = \
	aead-common.h \
	aead-common.c \
	internal-util.h

ACE_FILES = \
    ace.c \
    ace.h \
    internal-sliscp-light.c \
    internal-sliscp-light.h \
    $(COMMON_FILES)
ASCON_FILES = \
    ascon128.c \
    ascon128.h \
    ascon-hash.c \
    ascon-xof.c \
    internal-ascon.c \
    internal-ascon.h \
    $(COMMON_FILES)
COMET_FILES = \
    comet.c \
    comet.h \
    internal-cham.c \
    internal-cham.h \
    $(COMMON_FILES)
ESTATE_FILES = \
    estate.c \
    estate.h \
    internal-gift128.c \
    internal-gift128.h \
    $(COMMON_FILES)
GIFT_COFB_FILES = \
    gift-cofb.c \
    gift-cofb.h \
    internal-gift128.c \
    internal-gift128.h \
    $(COMMON_FILES)
GIMLI_FILES = \
    gimli24.c \
    gimli24.h \
    $(COMMON_FILES)
HYENA_FILES = \
    hyena.c \
    hyena.h \
    internal-gift128.c \
    internal-gift128.h \
    $(COMMON_FILES)
ISAP_FILES = \
    isap.c \
    isap.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-isap.h \
    internal-keccak.c \
    internal-keccak.h \
    $(COMMON_FILES)
KNOT_FILES = \
    knot-aead.c \
    knot-hash.c \
    knot.h \
    internal-knot.c \
    internal-knot.h \
    $(COMMON_FILES)
LOTUS_FILES = \
    lotus-locus.c \
    lotus-locus.h \
    internal-gift64.c \
    internal-gift64.h \
    $(COMMON_FILES)
PYJAMASK_FILES = \
    pyjamask-128.c \
    pyjamask-128-masked.c \
    pyjamask-96.c \
    pyjamask-96-masked.c \
    pyjamask.h \
    internal-masking.c \
    internal-masking.h \
    internal-pyjamask.c \
    internal-pyjamask.h \
    internal-ocb.h \
    $(COMMON_FILES)
ROMULUS_FILES = \
    romulus.c \
    romulus.h \
    internal-skinny128.c \
    internal-skinny128.h \
    $(COMMON_FILES)
SATURNIN_FILES = \
    saturnin.c \
    saturnin.h \
    $(COMMON_FILES)
SKINNY_AEAD_FILES = \
    skinny-aead.c \
    skinny-aead.h \
    internal-skinny128.c \
    internal-skinny128.h \
    $(COMMON_FILES)
SPARKLE_FILES = \
    sparkle.c \
    sparkle.h \
    $(COMMON_FILES)
SPIX_FILES = \
    spix.c \
    spix.h \
    internal-sliscp-light.c \
    internal-sliscp-light.h \
    $(COMMON_FILES)
SPOOK_FILES = \
    spook.c \
    spook.h \
    internal-spook.c \
    internal-spook.h \
    $(COMMON_FILES)
SUNDAE_GIFT_FILES = \
    sundae-gift.c \
    sundae-gift.h \
    internal-gift128.c \
    internal-gift128.h \
    $(COMMON_FILES)
TINYJAMBU_FILES = \
    tinyjambu.c \
    tinyjambu.h \
    $(COMMON_FILES)
XOODYAK_FILES = \
    xoodyak.c \
    xoodyak.h \
    $(COMMON_FILES)

ALL_ALGORITHMS = \
    ace \
    ascon \
    comet \
    estate \
    gift_cofb \
    gimli \
    hyena \
    isap \
    knot \
    lotus \
    pyjamask \
    romulus \
    saturnin \
    skinny_aead \
    sparkle \
    spix \
    spook \
    sundae_gift \
    tinyjambu \
    xoodyak

.PHONY: all $(ALL_ALGORITHMS)

all: $(ALL_ALGORITHMS)

ace:
	cp $(foreach file,$(ACE_FILES),$(SRCDIR)/$(file)) ACE

ascon:
	cp $(foreach file,$(ASCON_FILES),$(SRCDIR)/$(file)) ASCON

comet:
	cp $(foreach file,$(COMET_FILES),$(SRCDIR)/$(file)) COMET

estate:
	cp $(foreach file,$(ESTATE_FILES),$(SRCDIR)/$(file)) ESTATE

gift_cofb:
	cp $(foreach file,$(GIFT_COFB_FILES),$(SRCDIR)/$(file)) GIFT-COFB

gimli:
	cp $(foreach file,$(GIMLI_FILES),$(SRCDIR)/$(file)) Gimli

hyena:
	cp $(foreach file,$(HYENA_FILES),$(SRCDIR)/$(file)) HYENA

isap:
	cp $(foreach file,$(ISAP_FILES),$(SRCDIR)/$(file)) ISAP

knot:
	cp $(foreach file,$(KNOT_FILES),$(SRCDIR)/$(file)) KNOT

lotus:
	cp $(foreach file,$(LOTUS_FILES),$(SRCDIR)/$(file)) LOTUS-AEAD

pyjamask:
	cp $(foreach file,$(PYJAMASK_FILES),$(SRCDIR)/$(file)) Pyjamask

romulus:
	cp $(foreach file,$(ROMULUS_FILES),$(SRCDIR)/$(file)) Romulus

saturnin:
	cp $(foreach file,$(SATURNIN_FILES),$(SRCDIR)/$(file)) Saturnin

skinny_aead:
	cp $(foreach file,$(SKINNY_AEAD_FILES),$(SRCDIR)/$(file)) SKINNY-AEAD

sparkle:
	cp $(foreach file,$(SPARKLE_FILES),$(SRCDIR)/$(file)) SPARKLE

spix:
	cp $(foreach file,$(SPIX_FILES),$(SRCDIR)/$(file)) SPIX

spook:
	cp $(foreach file,$(SPOOK_FILES),$(SRCDIR)/$(file)) Spook

sundae_gift:
	cp $(foreach file,$(SUNDAE_GIFT_FILES),$(SRCDIR)/$(file)) SUNDAE-GIFT

tinyjambu:
	cp $(foreach file,$(TINYJAMBU_FILES),$(SRCDIR)/$(file)) TinyJAMBU

xoodyak:
	cp $(foreach file,$(XOODYAK_FILES),$(SRCDIR)/$(file)) Xoodyak
