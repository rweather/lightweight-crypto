
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

.PHONY: all gimli ascon

all: gimli ascon

gimli:
	cp $(foreach file,$(GIMLI_FILES),$(SRCDIR)/$(file)) Gimli

ascon:
	cp $(foreach file,$(ASCON_FILES),$(SRCDIR)/$(file)) ASCON
