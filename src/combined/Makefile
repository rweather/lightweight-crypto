
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-common.o \
	gimli24.o \
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
gimli24.o: gimli24.h aead-common.h util-aead.h util-load-store.h util-rotate.h
internal-gift128.o: internal-gift128.h util-load-store.h util-rotate.h
internal-skinny128.o: internal-skinny128.h util-load-store.h util-rotate.h
