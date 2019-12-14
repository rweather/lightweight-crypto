
# Common optimization and warning CFLAGS for compiling all source files.
COMMON_CFLAGS = -O3 -Wall -Wextra

# Common linker flags.
COMMON_LDFLAGS =

# Select the C standard to compile the core library with.
STDC_CFLAGS = -std=c99

# Extra CFLAGS to activate SIMD vector extensions for 128-bit vectors.
VEC128_CFLAGS = -msse2
#VEC128_CFLAGS = -mfpu=neon
#VEC128_CFLAGS =

# Extra CFLAGS to activate SIMD vector extensions for 256-bit vectors.
VEC256_CFLAGS = -mavx2
#VEC256_CFLAGS =
