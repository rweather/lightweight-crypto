
include ../../options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_arm_cortex_m3 \
	bin/gascon_arm_cortex_m3

all: $(TARGETS)

bin/ascon_arm_cortex_m3: ascon_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/gascon_arm_cortex_m3: gascon_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

check:

generate: all
	bin/ascon_arm_cortex_m3 >../combined/internal-ascon-arm-cm3.S
	bin/gascon_arm_cortex_m3 >../combined/internal-gascon-arm-cm3.S
