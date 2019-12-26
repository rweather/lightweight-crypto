
SRCDIR = ../combined

COMMON_FILES = \
	aead-common.h \
	aead-common.c \
	internal-util.h

GIMLI_FILES = gimli24.c gimli24.h $(COMMON_FILES)
ASCON_FILES = \
    ascon128.c \
    ascon128.h \
    ascon-hash.c \
    ascon-xof.c \
    internal-ascon.c \
    internal-ascon.h \
    $(COMMON_FILES)
SUNDAE_GIFT_FILES = \
    sundae-gift.c \
    sundae-gift.h \
    internal-gift128.c \
    internal-gift128.h \
    $(COMMON_FILES)

.PHONY: all gimli ascon sundae_gift

all: \
    ascon \
    gimli \
    sundae_gift

ascon:
	cp $(foreach file,$(ASCON_FILES),$(SRCDIR)/$(file)) ASCON

gimli:
	cp $(foreach file,$(GIMLI_FILES),$(SRCDIR)/$(file)) Gimli

sundae_gift:
	cp $(foreach file,$(SUNDAE_GIFT_FILES),$(SRCDIR)/$(file)) SUNDAE-GIFT
