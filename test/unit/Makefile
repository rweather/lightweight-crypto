
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = unit-tests

OBJS1 = \
    test-cipher.o \
    test-main.o \
    test-chachapoly.o \
    test-cham.o \
    test-gift128.o \
    test-gimli24.o \
    test-keccak.o \
    test-pyjamask.o \
    test-skinny128.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	./$(TARGET1)

TEST_CIPHER_INC = test-cipher.h $(LIBSRC_DIR)/aead-common.h

test-chachapoly.o: $(LIBSRC_DIR)/internal-chachapoly.h $(TEST_CIPHER_INC)
test-cham.o: $(LIBSRC_DIR)/internal-cham.h $(TEST_CIPHER_INC)
test-gift128.o: $(LIBSRC_DIR)/internal-gift128.h $(TEST_CIPHER_INC)
test-gimli24.o: $(LIBSRC_DIR)/gimli24.h $(TEST_CIPHER_INC)
test-keccak.o: $(LIBSRC_DIR)/internal-keccak.h $(TEST_CIPHER_INC)
test-pyjamask.o: $(LIBSRC_DIR)/internal-pyjamask.h $(TEST_CIPHER_INC)
test-skinny128.o: $(LIBSRC_DIR)/internal-skinny128.h $(TEST_CIPHER_INC)
test-cipher.o: $(TEST_CIPHER_INC)
test-main.o: $(TEST_CIPHER_INC)
