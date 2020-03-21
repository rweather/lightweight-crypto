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

#include "gen.h"
#include <iostream>
#include <cstring>

enum Mode
{
    Generate,
    Test
};

static void header(std::ostream &ostream)
{
    ostream << "#if defined(__AVR__)" << std::endl;
    ostream << "#include <avr/io.h>" << std::endl;
    ostream << "/* Automatically generated - do not edit */" << std::endl;
}

static void footer(std::ostream &ostream)
{
    ostream << std::endl;
    ostream << "#endif" << std::endl;
}

static bool cham128(enum Mode mode)
{
    Code code;
    gen_cham128_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_cham128_encrypt(code)) {
            std::cout << "CHAM128-128 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "CHAM128-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool cham64(enum Mode mode)
{
    Code code;
    gen_cham64_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_cham64_encrypt(code)) {
            std::cout << "CHAM64-128 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "CHAM64-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool speck64(enum Mode mode)
{
    Code code;
    gen_speck64_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_speck64_encrypt(code)) {
            std::cout << "SPECK-64 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SPECK-64 tests succeeded" << std::endl;
        }
    }
    return true;
}

typedef bool (*gen_code)(enum Mode mode);

int main(int argc, char *argv[])
{
    bool generate = true;
    int exit_val = 0;
    gen_code gen1 = 0;
    gen_code gen2 = 0;

    if (argc > 1 && !strcmp(argv[1], "--test")) {
        generate = false;
    } else {
        if (argc <= 1) {
            fprintf(stderr, "Usage: %s algorithm-name\n", argv[0]);
            return 1;
        }
        if (!strcmp(argv[1], "CHAM")) {
            gen1 = cham128;
            gen2 = cham64;
        } else if (!strcmp(argv[1], "SPECK-64")) {
            gen1 = speck64;
        }
    }

    if (generate) {
        header(std::cout);
        if (gen1)
            gen1(Generate);
        if (gen2)
            gen2(Generate);
        footer(std::cout);
    } else {
        if (!cham128(Test))
            exit_val = 1;
        if (!cham64(Test))
            exit_val = 1;
        if (!speck64(Test))
            exit_val = 1;
    }

    return exit_val;
}
