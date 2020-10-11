
SRCDIR = ../combined

COMMON_FILES = \
	aead-common.h \
	aead-common.c \
	internal-util.h
COMMON_MASKING_FILES = \
	aead-common.h \
	aead-common.c \
	aead-random.h \
	aead-random.c \
	internal-masking.h \
	internal-util.h

ACE_FILES = \
    ace.c \
    ace.h \
    internal-sliscp-light.c \
    internal-sliscp-light.h \
    internal-sliscp-320-avr.S \
    $(COMMON_FILES)
ASCON_FILES = \
    ascon128.c \
    ascon128.h \
    ascon-hash.c \
    ascon-xof.c \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-arm-cm3.S \
    internal-ascon-avr.S \
    $(COMMON_FILES)
ASCON_MASKED_FILES = \
    ascon128-masked.c \
    ascon128-masked.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-m.c \
    internal-ascon-m.h \
    internal-ascon-arm-cm3.S \
    internal-ascon-avr.S \
    $(COMMON_MASKING_FILES)
COMET_FILES = \
    comet.c \
    comet.h \
    internal-cham.c \
    internal-cham.h \
    internal-cham-arm-cm3.S \
    internal-cham-avr.S \
    internal-speck64.c \
    internal-speck64.h \
    internal-speck64-arm-cm3.S \
    internal-speck64-avr.S \
    $(COMMON_FILES)
DRYGASCON_FILES = \
    drygascon.c \
    drygascon.h \
    internal-drysponge.c \
    internal-drysponge.h \
    internal-drysponge-avr.S \
    drygascon128_arm-v6m.S \
    drygascon128_arm-v7m.S \
    drygascon128_arm-v7m_fpu.S \
    drygascon128_arm_selector.h \
    $(COMMON_FILES)
ELEPHANT_FILES = \
    elephant.c \
    elephant.h \
    internal-keccak.c \
    internal-keccak.h \
    internal-keccak-avr.S \
    internal-spongent.c \
    internal-spongent.h \
    internal-spongent-avr.S \
    $(COMMON_FILES)
ESTATE_FILES = \
    estate.c \
    estate.h \
    internal-gift128.c \
    internal-gift128.h \
    internal-gift128-config.h \
    internal-gift128n-full-avr.S \
    internal-gift128n-small-avr.S \
    internal-gift128n-tiny-avr.S \
    $(COMMON_FILES)
FORKAE_FILES = \
    forkae.c \
    forkae.h \
    internal-forkae-paef.h \
    internal-forkae-saef.h \
    internal-forkskinny.c \
    internal-forkskinny.h \
    internal-forkskinny-avr.S \
    internal-skinnyutil.h \
    $(COMMON_FILES)
GIFT_COFB_FILES = \
    gift-cofb.c \
    gift-cofb.h \
    internal-gift128.c \
    internal-gift128.h \
    internal-gift128-config.h \
    internal-gift128b-full-avr.S \
    internal-gift128b-small-avr.S \
    internal-gift128b-tiny-avr.S \
    $(COMMON_FILES)
GIFT_COFB_MASKED_FILES = \
    gift-cofb-masked.c \
    gift-cofb-masked.h \
    internal-gift128-config.h \
    internal-gift128-m.c \
    internal-gift128-m.h \
    $(COMMON_MASKING_FILES)
GIMLI_FILES = \
    gimli24.c \
    gimli24.h \
    internal-gimli24.c \
    internal-gimli24.h \
    internal-gimli24-arm-cm3.S \
    internal-gimli24-avr.S \
    $(COMMON_FILES)
GIMLI_MASKED_FILES = \
    gimli24-masked.c \
    gimli24-masked.h \
    internal-gimli24.c \
    internal-gimli24.h \
    internal-gimli24-m.c \
    internal-gimli24-m.h \
    internal-gimli24-avr.S \
    $(COMMON_MASKING_FILES)
GRAIN128_FILES = \
    grain128.c \
    grain128.h \
    internal-grain128.c \
    internal-grain128.h \
    internal-grain128-avr.S \
    $(COMMON_FILES)
HYENA_FILES = \
    hyena.c \
    hyena.h \
    internal-gift128.c \
    internal-gift128.h \
    internal-gift128-config.h \
    internal-gift128n-full-avr.S \
    internal-gift128n-small-avr.S \
    internal-gift128n-tiny-avr.S \
    $(COMMON_FILES)
ISAP_FILES = \
    isap.c \
    isap.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-arm-cm3.S \
    internal-ascon-avr.S \
    internal-isap.h \
    internal-keccak.c \
    internal-keccak.h \
    internal-keccak-avr.S \
    $(COMMON_FILES)
KNOT_FILES = \
    knot-aead.c \
    knot-hash.c \
    knot.h \
    internal-knot.c \
    internal-knot.h \
    internal-knot-256-avr.S \
    internal-knot-384-avr.S \
    internal-knot-512-avr.S \
    $(COMMON_FILES)
KNOT_MASKED_FILES = \
    knot-masked.c \
    knot-masked.h \
    internal-knot.c \
    internal-knot.h \
    internal-knot-m.c \
    internal-knot-m.h \
    internal-knot-256-avr.S \
    internal-knot-384-avr.S \
    internal-knot-512-avr.S \
    $(COMMON_MASKING_FILES)
LOTUS_FILES = \
    lotus-locus.c \
    lotus-locus.h \
    internal-gift64.c \
    internal-gift64.h \
    internal-gift64-avr.S \
    $(COMMON_FILES)
ORANGE_FILES = \
    orange.c \
    orange.h \
    internal-photon256.c \
    internal-photon256.h \
    internal-photon256-avr.S \
    $(COMMON_FILES)
ORIBATIDA_FILES = \
    oribatida.c \
    oribatida.h \
    internal-simp.c \
    internal-simp.h \
    internal-simp-avr.S \
    $(COMMON_FILES)
PHOTON_BEETLE_FILES = \
    photon-beetle.c \
    photon-beetle.h \
    internal-photon256.c \
    internal-photon256.h \
    internal-photon256-avr.S \
    $(COMMON_FILES)
PYJAMASK_FILES = \
    pyjamask-128.c \
    pyjamask-96.c \
    pyjamask.h \
    internal-pyjamask.c \
    internal-pyjamask.h \
    internal-pyjamask-avr.S \
    internal-ocb.h \
    $(COMMON_FILES)
PYJAMASK_MASKED_FILES = \
    pyjamask-128-masked.c \
    pyjamask-96-masked.c \
    pyjamask-masked.h \
    internal-pyjamask-m.c \
    internal-ocb.h \
    $(COMMON_MASKING_FILES)
ROMULUS_FILES = \
    romulus.c \
    romulus.h \
    internal-skinny128.c \
    internal-skinny128.h \
    internal-skinnyutil.h \
    internal-skinny128-avr.S \
    $(COMMON_FILES)
SATURNIN_FILES = \
    saturnin.c \
    saturnin.h \
    internal-saturnin.c \
    internal-saturnin.h \
    internal-saturnin-avr.S \
    $(COMMON_FILES)
SKINNY_AEAD_FILES = \
    skinny-aead.c \
    skinny-aead.h \
    skinny-hash.c \
    skinny-hash.h \
    internal-skinny128.c \
    internal-skinny128.h \
    internal-skinny128-avr.S \
    internal-skinnyutil.h \
    $(COMMON_FILES)
SPARKLE_FILES = \
    sparkle.c \
    sparkle.h \
    internal-sparkle.c \
    internal-sparkle.h \
    internal-sparkle-avr.S \
    $(COMMON_FILES)
SPIX_FILES = \
    spix.c \
    spix.h \
    internal-sliscp-light.c \
    internal-sliscp-light.h \
    internal-sliscp-256-spix-avr.S \
    $(COMMON_FILES)
SPIX_MASKED_FILES = \
    spix-masked.c \
    spix-masked.h \
    internal-sliscp-light.c \
    internal-sliscp-light.h \
    internal-sliscp-light-m.c \
    internal-sliscp-light-m.h \
    internal-sliscp-256-spix-avr.S \
    $(COMMON_MASKING_FILES)
SPOC_FILES = \
    spoc.c \
    spoc.h \
    internal-sliscp-light.c \
    internal-sliscp-light.h \
    internal-sliscp-192-avr.S \
    internal-sliscp-256-spoc-avr.S \
    $(COMMON_FILES)
SPOC_MASKED_FILES = \
    spoc-masked.c \
    spoc-masked.h \
    internal-sliscp-light-m.c \
    internal-sliscp-light-m.h \
    $(COMMON_MASKING_FILES)
SPOOK_FILES = \
    spook.c \
    spook.h \
    internal-spook.c \
    internal-spook.h \
    internal-spook-avr.S \
    $(COMMON_FILES)
SPOOK_MASKED_FILES = \
    spook-masked.c \
    spook-masked.h \
    internal-spook.c \
    internal-spook.h \
    internal-spook-m.c \
    internal-spook-avr.S \
    $(COMMON_MASKING_FILES)
SUBTERRANEAN_FILES = \
    subterranean.c \
    subterranean.h \
    internal-subterranean.c \
    internal-subterranean.h \
    internal-subterranean-avr.S \
    $(COMMON_FILES)
SUNDAE_GIFT_FILES = \
    sundae-gift.c \
    sundae-gift.h \
    internal-gift128.c \
    internal-gift128.h \
    internal-gift128-config.h \
    internal-gift128b-full-avr.S \
    internal-gift128b-small-avr.S \
    internal-gift128b-tiny-avr.S \
    $(COMMON_FILES)
TINYJAMBU_FILES = \
    tinyjambu.c \
    tinyjambu.h \
    internal-tinyjambu.c \
    internal-tinyjambu.h \
    internal-tinyjambu-arm-cm3.S \
    internal-tinyjambu-avr.S \
    $(COMMON_FILES)
TINYJAMBU_MASKED_FILES = \
    tinyjambu-masked.c \
    tinyjambu-masked.h \
    internal-tinyjambu-m.c \
    internal-tinyjambu-m.h \
    $(COMMON_MASKING_FILES)
WAGE_FILES = \
    wage.c \
    wage.h \
    internal-wage.c \
    internal-wage.h \
    internal-wage-avr.S \
    $(COMMON_FILES)
XOODYAK_FILES = \
    xoodyak.c \
    xoodyak.h \
    internal-xoodoo.c \
    internal-xoodoo.h \
    internal-xoodoo-arm-cm3.S \
    internal-xoodoo-avr.S \
    $(COMMON_FILES)
XOODYAK_MASKED_FILES = \
    xoodyak-masked.c \
    xoodyak-masked.h \
    internal-xoodoo.c \
    internal-xoodoo.h \
    internal-xoodoo-m.c \
    internal-xoodoo-m.h \
    internal-xoodoo-avr.S \
    $(COMMON_MASKING_FILES)

ALL_ALGORITHMS = \
    ace \
    ascon \
    ascon_masked \
    comet \
    drygascon \
    elephant \
    estate \
    forkae \
    gift_cofb \
    gift_cofb_masked \
    gimli \
    gimli_masked \
    grain128 \
    hyena \
    isap \
    knot \
    knot_masked \
    lotus \
    orange \
    oribatida \
    photon_beetle \
    pyjamask \
    pyjamask_masked \
    romulus \
    saturnin \
    skinny_aead \
    sparkle \
    spix \
    spix_masked \
    spoc \
    spoc_masked \
    spook \
    spook_masked \
    subterranean \
    sundae_gift \
    tinyjambu \
    tinyjambu_masked \
    wage \
    xoodyak \
    xoodyak_masked

.PHONY: all $(ALL_ALGORITHMS)

all: $(ALL_ALGORITHMS)

ace:
	cp $(foreach file,$(ACE_FILES),$(SRCDIR)/$(file)) ACE

ascon:
	cp $(foreach file,$(ASCON_FILES),$(SRCDIR)/$(file)) ASCON

ascon_masked:
	cp $(foreach file,$(ASCON_MASKED_FILES),$(SRCDIR)/$(file)) ASCON_masked

comet:
	cp $(foreach file,$(COMET_FILES),$(SRCDIR)/$(file)) COMET

drygascon:
	cp $(foreach file,$(DRYGASCON_FILES),$(SRCDIR)/$(file)) DryGASCON

elephant:
	cp $(foreach file,$(ELEPHANT_FILES),$(SRCDIR)/$(file)) Elephant

estate:
	cp $(foreach file,$(ESTATE_FILES),$(SRCDIR)/$(file)) ESTATE

forkae:
	cp $(foreach file,$(FORKAE_FILES),$(SRCDIR)/$(file)) ForkAE

gift_cofb:
	cp $(foreach file,$(GIFT_COFB_FILES),$(SRCDIR)/$(file)) GIFT-COFB

gift_cofb_masked:
	cp $(foreach file,$(GIFT_COFB_MASKED_FILES),$(SRCDIR)/$(file)) GIFT-COFB_masked

gimli:
	cp $(foreach file,$(GIMLI_FILES),$(SRCDIR)/$(file)) Gimli

gimli_masked:
	cp $(foreach file,$(GIMLI_MASKED_FILES),$(SRCDIR)/$(file)) Gimli_masked

grain128:
	cp $(foreach file,$(GRAIN128_FILES),$(SRCDIR)/$(file)) Grain-128AEAD

hyena:
	cp $(foreach file,$(HYENA_FILES),$(SRCDIR)/$(file)) HYENA

isap:
	cp $(foreach file,$(ISAP_FILES),$(SRCDIR)/$(file)) ISAP

knot:
	cp $(foreach file,$(KNOT_FILES),$(SRCDIR)/$(file)) KNOT

knot_masked:
	cp $(foreach file,$(KNOT_MASKED_FILES),$(SRCDIR)/$(file)) KNOT_masked

lotus:
	cp $(foreach file,$(LOTUS_FILES),$(SRCDIR)/$(file)) LOTUS-AEAD

orange:
	cp $(foreach file,$(ORANGE_FILES),$(SRCDIR)/$(file)) ORANGE

oribatida:
	cp $(foreach file,$(ORIBATIDA_FILES),$(SRCDIR)/$(file)) Oribatida

photon_beetle:
	cp $(foreach file,$(PHOTON_BEETLE_FILES),$(SRCDIR)/$(file)) PHOTON-Beetle

pyjamask:
	cp $(foreach file,$(PYJAMASK_FILES),$(SRCDIR)/$(file)) Pyjamask

pyjamask_masked:
	cp $(foreach file,$(PYJAMASK_MASKED_FILES),$(SRCDIR)/$(file)) Pyjamask_masked

romulus:
	cp $(foreach file,$(ROMULUS_FILES),$(SRCDIR)/$(file)) Romulus

saturnin:
	cp $(foreach file,$(SATURNIN_FILES),$(SRCDIR)/$(file)) Saturnin

skinny_aead:
	cp $(foreach file,$(SKINNY_AEAD_FILES),$(SRCDIR)/$(file)) SKINNY-AEAD

sparkle:
	cp $(foreach file,$(SPARKLE_FILES),$(SRCDIR)/$(file)) SPARKLE

spix:
	cp $(foreach file,$(SPIX_FILES),$(SRCDIR)/$(file)) SPIX

spix_masked:
	cp $(foreach file,$(SPIX_MASKED_FILES),$(SRCDIR)/$(file)) SPIX_masked

spoc:
	cp $(foreach file,$(SPOC_FILES),$(SRCDIR)/$(file)) SpoC

spoc_masked:
	cp $(foreach file,$(SPOC_MASKED_FILES),$(SRCDIR)/$(file)) SpoC_masked

spook:
	cp $(foreach file,$(SPOOK_FILES),$(SRCDIR)/$(file)) Spook

spook_masked:
	cp $(foreach file,$(SPOOK_MASKED_FILES),$(SRCDIR)/$(file)) Spook_masked

subterranean:
	cp $(foreach file,$(SUBTERRANEAN_FILES),$(SRCDIR)/$(file)) Subterranean

sundae_gift:
	cp $(foreach file,$(SUNDAE_GIFT_FILES),$(SRCDIR)/$(file)) SUNDAE-GIFT

tinyjambu:
	cp $(foreach file,$(TINYJAMBU_FILES),$(SRCDIR)/$(file)) TinyJAMBU

tinyjambu_masked:
	cp $(foreach file,$(TINYJAMBU_MASKED_FILES),$(SRCDIR)/$(file)) TinyJAMBU_masked

wage:
	cp $(foreach file,$(WAGE_FILES),$(SRCDIR)/$(file)) WAGE

xoodyak:
	cp $(foreach file,$(XOODYAK_FILES),$(SRCDIR)/$(file)) Xoodyak

xoodyak_masked:
	cp $(foreach file,$(XOODYAK_MASKED_FILES),$(SRCDIR)/$(file)) Xoodyak_masked
