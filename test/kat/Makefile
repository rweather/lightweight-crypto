
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = kat

OBJS1 = \
    kat.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	@./$(TARGET1) ASCON-128 ASCON-128.txt
	@./$(TARGET1) ASCON-128a ASCON-128a.txt
	@./$(TARGET1) ASCON-HASH ASCON-HASH.txt
	@./$(TARGET1) ASCON-XOF ASCON-XOF.txt
	@./$(TARGET1) GIMLI-24 GIMLI-24-CIPHER.txt

kat.o: KAT_INC = $(wildcard $(LIBSRC_DIR)/*.h)
