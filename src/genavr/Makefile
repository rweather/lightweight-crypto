
include ../../options.mak

.PHONY: all clean check generate

CXXFLAGS += -g $(COMMON_CFLAGS) $(STDC_CXXFLAGS)

TARGET = genavr

OBJS = \
	algorithm_ascon.o \
	algorithm_cham.o \
	algorithm_gascon.o \
	algorithm_gift128.o \
	algorithm_gift64.o \
	algorithm_keccak.o \
	algorithm_sparkle.o \
	algorithm_speck64.o \
	algorithm_spongent.o \
	algorithm_tinyjambu.o \
	code.o \
	code_out.o \
	interpret.o \
        main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

check: all
	./$(TARGET) --test

code.o: code.h
code_out.o: code.h
algorithm_ascon.o: code.h gen.h
algorithm_cham.o: code.h gen.h
algorithm_gascon.o: code.h gen.h
algorithm_gift128.o: code.h gen.h
algorithm_gift64.o: code.h gen.h
algorithm_keccak.o: code.h gen.h
algorithm_sparkle.o: code.h gen.h
algorithm_speck64.o: code.h gen.h
algorithm_spongent.o: code.h gen.h
algorithm_tinyjambu.o: code.h gen.h
interpret.o: code.h

generate: $(TARGET)
	./$(TARGET) ASCON >../combined/internal-ascon-avr.S
	./$(TARGET) CHAM >../combined/internal-cham-avr.S
	./$(TARGET) GASCON >../combined/internal-drysponge-avr.S
	./$(TARGET) GIFT-128b >../combined/internal-gift128b-avr.S
	./$(TARGET) GIFT-128n >../combined/internal-gift128n-avr.S
	./$(TARGET) GIFT-64 >../combined/internal-gift64-avr.S
	./$(TARGET) Keccak >../combined/internal-keccak-avr.S
	./$(TARGET) SPARKLE >../combined/internal-sparkle-avr.S
	./$(TARGET) SPECK-64 >../combined/internal-speck64-avr.S
	./$(TARGET) Spongent-pi >../combined/internal-spongent-avr.S
	./$(TARGET) TinyJAMBU >../combined/internal-tinyjambu-avr.S
