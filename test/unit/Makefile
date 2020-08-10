
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = unit-tests

OBJS1 = \
    test-cipher.o \
    test-main.o \
    test-ascon.o \
    test-blake2s.o \
    test-chachapoly.o \
    test-cham.o \
    test-drygascon.o \
    test-forkskinny.o \
    test-gift128.o \
    test-gift64.o \
    test-gimli24.o \
    test-grain128.o \
    test-keccak.o \
    test-knot.o \
    test-masking.o \
    test-photon256.o \
    test-pyjamask.o \
    test-saturnin.o \
    test-simp.o \
    test-skinny128.o \
    test-sliscp-light.o \
    test-sparkle.o \
    test-speck64.o \
    test-spongent.o \
    test-spook.o \
    test-subterranean.o \
    test-tinyjambu.o \
    test-wage.o \
    test-xoodoo.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	./$(TARGET1)

TEST_CIPHER_INC = test-cipher.h $(LIBSRC_DIR)/aead-common.h
TEST_CIPHER_MASKING_INC = test-cipher.h $(LIBSRC_DIR)/aead-common.h $(LIBSRC_DIR)/aead-random.h $(LIBSRC_DIR)/internal-masking.h

test-ascon.o: $(LIBSRC_DIR)/ascon128.h $(LIBSRC_DIR)/internal-ascon.h $(LIBSRC_DIR)/internal-ascon-m.h $(TEST_CIPHER_MASKING_INC)
test-blake2s.o: $(LIBSRC_DIR)/internal-blake2s.h $(TEST_CIPHER_INC)
test-chachapoly.o: $(LIBSRC_DIR)/internal-chachapoly.h $(TEST_CIPHER_INC)
test-cham.o: $(LIBSRC_DIR)/internal-cham.h $(TEST_CIPHER_INC)
test-drygascon.o: $(LIBSRC_DIR)/internal-drysponge.h $(TEST_CIPHER_INC)
test-forkskinny.o: $(LIBSRC_DIR)/internal-forkskinny.h $(LIBSRC_DIR)/internal-skinnyutil.h $(TEST_CIPHER_INC)
test-gift128.o: $(LIBSRC_DIR)/internal-gift128.h $(LIBSRC_DIR)/internal-gift128-m.h $(LIBSRC_DIR)/internal-gift128-config.h $(TEST_CIPHER_MASKING_INC)
test-gift64.o: $(LIBSRC_DIR)/internal-gift64.h $(TEST_CIPHER_INC)
test-gimli24.o: $(LIBSRC_DIR)/gimli24.h $(LIBSRC_DIR)/internal-gimli24.h $(LIBSRC_DIR)/internal-gimli24-m.h $(TEST_CIPHER_MASKING_INC)
test-grain128.o: $(LIBSRC_DIR)/internal-grain128.h $(TEST_CIPHER_INC)
test-keccak.o: $(LIBSRC_DIR)/internal-keccak.h $(TEST_CIPHER_INC)
test-knot.o: $(LIBSRC_DIR)/internal-knot.h $(TEST_CIPHER_INC)
test-masking.o: $(LIBSRC_DIR)/aead-random.h $(LIBSRC_DIR)/internal-masking.h $(TEST_CIPHER_INC) test-masking-common.c
test-photon256.o: $(LIBSRC_DIR)/internal-photon256.h $(TEST_CIPHER_INC)
test-pyjamask.o: $(LIBSRC_DIR)/internal-pyjamask.h $(LIBSRC_DIR)/internal-pyjamask-m.h $(TEST_CIPHER_INC)
test-saturnin.o: $(LIBSRC_DIR)/internal-saturnin.h $(TEST_CIPHER_INC)
test-simp.o: $(LIBSRC_DIR)/internal-simp.h $(TEST_CIPHER_INC)
test-skinny128.o: $(LIBSRC_DIR)/internal-skinny128.h $(LIBSRC_DIR)/internal-skinnyutil.h $(TEST_CIPHER_INC)
test-sliscp-light.o: $(LIBSRC_DIR)/internal-sliscp-light.h $(LIBSRC_DIR)/internal-sliscp-light.h $(TEST_CIPHER_MASKING_INC)
test-sparkle.o: $(LIBSRC_DIR)/internal-sparkle.h $(TEST_CIPHER_INC)
test-speck64.o: $(LIBSRC_DIR)/internal-speck64.h $(TEST_CIPHER_INC)
test-spongent.o: $(LIBSRC_DIR)/internal-spongent.h $(TEST_CIPHER_INC)
test-spook.o: $(LIBSRC_DIR)/internal-spook.h $(TEST_CIPHER_INC)
test-subterranean.o: $(LIBSRC_DIR)/internal-subterranean.h $(TEST_CIPHER_INC)
test-tinyjambu.o: $(LIBSRC_DIR)/internal-tinyjambu.h $(LIBSRC_DIR)/internal-tinyjambu-m.h $(TEST_CIPHER_MASKING_INC)
test-wage.o: $(LIBSRC_DIR)/internal-wage.h $(TEST_CIPHER_INC)
test-xoodoo.o: $(LIBSRC_DIR)/internal-xoodoo.h $(LIBSRC_DIR)/internal-xoodoo-m.h $(TEST_CIPHER_MASKING_INC)
test-cipher.o: $(TEST_CIPHER_INC)
test-main.o: $(TEST_CIPHER_INC)
