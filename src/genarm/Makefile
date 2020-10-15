
include ../../options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_arm_cortex_m3 \
	bin/cham_arm_cortex_m3 \
	bin/gascon_arm_cortex_m3 \
	bin/gimli24_arm_cortex_m3 \
	bin/tinyjambu_arm_cortex_m3 \
	bin/sparkle_arm_cortex_m3 \
	bin/speck_arm_cortex_m3 \
	bin/xoodoo_arm_cortex_m3

all: $(TARGETS)

bin/ascon_arm_cortex_m3: ascon_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/cham_arm_cortex_m3: cham_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/gascon_arm_cortex_m3: gascon_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/gimli24_arm_cortex_m3: gimli24_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_arm_cortex_m3: tinyjambu_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/sparkle_arm_cortex_m3: sparkle_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/speck_arm_cortex_m3: speck_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/xoodoo_arm_cortex_m3: xoodoo_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

check:

generate: all
	bin/ascon_arm_cortex_m3 >../combined/internal-ascon-arm-cm3.S
	bin/cham_arm_cortex_m3 >../combined/internal-cham-arm-cm3.S
	bin/gascon_arm_cortex_m3 >../combined/internal-gascon-arm-cm3.S
	bin/gimli24_arm_cortex_m3 >../combined/internal-gimli24-arm-cm3.S
	bin/tinyjambu_arm_cortex_m3 >../combined/internal-tinyjambu-arm-cm3.S
	bin/sparkle_arm_cortex_m3 >../combined/internal-sparkle-arm-cm3.S
	bin/speck_arm_cortex_m3 >../combined/internal-speck64-arm-cm3.S
	bin/xoodoo_arm_cortex_m3 >../combined/internal-xoodoo-arm-cm3.S
