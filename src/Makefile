
include ../options.mak

.PHONY: all clean check

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS) -I../include

LIBRARY = libcryptolw.a

OBJS = \
	internal-gift128.o \
	internal-skinny128.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

internal-gift128.o: internal-gift128.h util-load-store.h util-rotate.h
internal-skinny128.o: internal-skinny128.h util-load-store.h util-rotate.h
