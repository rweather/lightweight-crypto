
include ../options.mak

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../include -I../src
LDFLAGS += $(COMMON_LDFLAGS) -L../src -lcryptolw

TARGET1 = test-ciphers

OBJS1 = \
    test-cipher.o \
    test-main.o \
    test-gift128.o \
    test-gimli24.o \
    test-skinny128.o

DEPS = ../src/libcryptolw.a

all: $(TARGET1)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	./$(TARGET1)

test-gift128.o: ../src/internal-gift128.h test-cipher.h
test-gimli24.o: ../src/gimli24.h test-cipher.h
test-skinny128.o: ../src/internal-skinny128.h test-cipher.h
test-cipher.o: test-cipher.h
test-main.o: test-cipher.h
