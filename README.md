
Lightweight Cryptography Primitives
===================================

This repository contains implementations of many of the second round
submissions to the [NIST lightweight cryptography competition](https://csrc.nist.gov/projects/lightweight-cryptography/round-2-candidates).

The implementations here are focused on efficient implementation for 32-bit
embedded architectures, particularly ARM.  The reference code from the NIST
web site by contrast is focused on correctness and amenity to academic
cryptanalysis.

Note: I don't provide any implementations for 8-bit microprocessors like the
AVR chips in low end Arduino devices.  This is because the embedded space is
quickly coalescing on 32-bit architectures with the cost and power budget of
32-bit chips dropping by the day.  By the time the final NIST lightweight
algorithm selection is made, 8-bit and 16-bit architectures won't be an
issue any more for embedded applications that require security.

Hardware vs software implementations
------------------------------------

Many of the algorithms in the competition are designed for efficient
hardware gate-level implementation in FPGA's and ASIC's.  My personal
feeling is that optimising for gate-level implementation is a waste of time.

It took 20 years after the AES standard was adopted before hardware modules
started showing up as a common feature of embedded processors.  Just in
time for a replacement algorithm to be needed!

We can expect the same will apply for the eventual NIST selection: it will
be some time before the algorithm is available in off-the-shelf embedded
microprocessors.  In the meantime, embedded systems will need good software
implementations to drive adoption.

This library does include some algorithms that were designed with hardware
implementation in mind, such as GIFT-128.  We do the best we can in software.

Authenticated encryption vs block ciphers
-----------------------------------------

Pretty much all of the NIST submissions are Authenticated Encryption with
Associated Data (AEAD) schemes.  AEAD provides the basic primitives for
"How do I encrypt and authenticate a packet?".  Thus, each of the algorithms
in this library provide high-level API's for "encrypt packet" and
"decrypt packet" with other lower-level details hidden.

Many of the NIST submissions use a block cipher as their core, but users
of this library should avoid using the block ciphers directly and use an
AEAD scheme instead.  The high-level API does not expose the block
operations directly to users of the library.

AEAD schemes require that the nonce be unique for every packet that is
encrypted under the same key.  Usually the nonce is set to the packet
sequence number or something similar.  I cannot stress enough how important
it is for the nonce to be unique.  New users of cryptography regularly make
the mistake of reusing nonces or skipping AEAD entirely and using
block ciphers in ECB mode!

Some of the NIST algorithms are resistant against nonce reuse, but you
shouldn't rely upon that to make your system secure.  For stream-based
connections the packet number can be used as the nonce.  For datagram-based
connections, the nonce can be prepended to the packet when it is transmitted.

No AES
------

Some of the submissions to NIST use AES as the inner block cipher in the
AEAD implementation.  I haven't implemented any of those variants.  AES is
notoriously difficult to implement in software in a manner that avoids
cache timing attacks.  It is best to ignore AES and do something else.

Performance comparisons
-----------------------

There is a lot of variation in the capabilities of embedded microprocessors.
Some are superscalar; others are not.  Some have specialised vector
instructions; others do not.  Clock speeds can also vary considerably.
All this means that "cycles per byte" or "megabytes per second" are
pretty meaningless.

At the end of the day, the best measure will always be "Is it fast enough
to accomplish the task I have in my embedded project?".  If your data
collection device is only encrypting one packet an hour to send to a
central server, then an algorithm that can do gigabytes per second is
overkill.  Even if it takes a minute to encrypt one packet, it is too fast!

The approach we take in this library is "ChaChaPoly Units".  The library
contains a reasonably efficient 32-bit non-vectorized implementation of
the ChaChaPoly AEAD scheme from my Arduino cryptography library.  This
makes it a known quanitity to compare with other algorithms side by side.

If an algorithm is measured at 0.8 ChaChaPoly Units on a specific embedded
microprocessor at a specific clock speed, then that means that it is
slower than ChaChaPoly by a factor of 0.8 on that microprocessor.
If the algorithm is instead measured at 2 ChaChaPoly Units, then it is
twice as fast as ChaChaPoly on the same microprocessor.  The higher the
number of units, the better the algorithm.

The number of ChaChaPoly Units for each algorithm will vary for each
microprocessor that is tested.  The figures quoted here should be used as a
guide to the relative performance of the algorithms, not an absolute metric.

Contact
-------

For more information on this code, to report bugs, or to suggest
improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).
