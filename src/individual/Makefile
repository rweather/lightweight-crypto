
SRCDIR = ../combined

COMMON_FILES = \
	aead-common.h \
	aead-common.c \
	internal-util.h

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
PYJAMASK_FILES = \
    pyjamask-128.c \
    pyjamask-96.c \
    pyjamask.h \
    internal-pyjamask.c \
    internal-pyjamask.h \
    internal-ocb.h \
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
SUNDAE_GIFT_FILES = \
    sundae-gift.c \
    sundae-gift.h \
    internal-gift128.c \
    internal-gift128.h \
    $(COMMON_FILES)

ALL_ALGORITHMS = \
    ascon \
    comet \
    estate \
    gift_cofb \
    gimli \
    hyena \
    pyjamask \
    saturnin \
    skinny_aead \
    sparkle \
    sundae_gift

.PHONY: all $(ALL_ALGORITHMS)

all: $(ALL_ALGORITHMS)

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

pyjamask:
	cp $(foreach file,$(PYJAMASK_FILES),$(SRCDIR)/$(file)) Pyjamask

saturnin:
	cp $(foreach file,$(SATURNIN_FILES),$(SRCDIR)/$(file)) Saturnin

skinny_aead:
	cp $(foreach file,$(SKINNY_AEAD_FILES),$(SRCDIR)/$(file)) SKINNY-AEAD

sparkle:
	cp $(foreach file,$(SPARKLE_FILES),$(SRCDIR)/$(file)) SPARKLE

sundae_gift:
	cp $(foreach file,$(SUNDAE_GIFT_FILES),$(SRCDIR)/$(file)) SUNDAE-GIFT
