
The primary source for all algorithms is in the "combined" subdirectory,
which makes it easier to share common building blocks between algorithms
and to test all of the algorithms as a set.

If you want to use a specific algorithm in your project, you should instead
copy the source files under "individual/ALG" where "ALG" is the name
of the algorithm you require.

The build rule "make individual" can be used to copy the relevant files
under "combined" to subdirectories of "individual" after you make a change
to the source in "combined".

The source code is mostly plain C99, tested with gcc and clang.
There are some platform-specific and compiler-specific definitions
in "combined/internal-util.h" that may need adjusting to get the
code to work with other compilers.  Patches welcome to improve portability.
