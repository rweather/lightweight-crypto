/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "test-cipher.h"

void test_blake2s(void);
void test_chachapoly(void);
void test_cham(void);
void test_clyde128(void);
void test_drygascon(void);
void test_forkskinny(void);
void test_gift128(void);
void test_gift64(void);
void test_gimli24(void);
void test_grain128(void);
void test_keccak(void);
void test_knot(void);
void test_photon256(void);
void test_pyjamask(void);
void test_shadow(void);
void test_simp(void);
void test_skinny128(void);
void test_sliscp_light(void);
void test_sparkle(void);
void test_speck64(void);
void test_spongent(void);
void test_subterranean(void);
void test_tinyjambu(void);
void test_wage(void);
void test_xoodoo(void);

int main(int argc, char *argv[])
{
    test_blake2s();
    test_chachapoly();
    test_cham();
    test_clyde128();
    test_drygascon();
    test_forkskinny();
    test_gift128();
    test_gift64();
    test_gimli24();
    test_grain128();
    test_keccak();
    test_knot();
    test_photon256();
    test_pyjamask();
    test_shadow();
    test_simp();
    test_skinny128();
    test_sliscp_light();
    test_sparkle();
    test_speck64();
    test_spongent();
    test_subterranean();
    test_tinyjambu();
    test_wage();
    test_xoodoo();
    return test_exit_result;
}
