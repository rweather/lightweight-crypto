
SRCDIR = ../combined

COMMON_FILES = \
	aead-common.h \
	aead-common.c \
	util-aead.h \
	util-load-store.h \
	util-rotate.h

GIMLI_FILES = gimli24.c gimli24.h $(COMMON_FILES)

.PHONY: all gimli

all: gimli

gimli:
	cp $(foreach file,$(GIMLI_FILES),$(SRCDIR)/$(file)) Gimli
