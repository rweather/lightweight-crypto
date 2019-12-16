
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = unit-tests

OBJS1 = \
    test-cipher.o \
    test-main.o \
    test-gift128.o \
    test-gimli24.o \
    test-skinny128.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	./$(TARGET1)

test-gift128.o: $(LIBSRC_DIR)/internal-gift128.h test-cipher.h
test-gimli24.o: $(LIBSRC_DIR)/gimli24.h test-cipher.h
test-skinny128.o: $(LIBSRC_DIR)/internal-skinny128.h test-cipher.h
test-cipher.o: test-cipher.h
test-main.o: test-cipher.h
