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

#include "code.h"
#include <stdexcept>
#include <cstring>
#include <algorithm>

/* AVR calling conventions from https://gcc.gnu.org/wiki/avr-gcc
 *
 * r0       Can be clobbered - temporary scratch register.
 * r1       Always set to zero.
 * r2-r17   Call-saved registers.
 * r18-r25  Can be clobbered.
 * r26,r27  Can be clobbered - X register.
 * r28,r29  Call-saved - Y register, usually the frame pointer.
 * r30,r31  Can be clobbered - Z register.
 *
 * Function call arguments are passed in registers r8-r25, starting at
 * the highest register r25.  For each register, round up to an even size
 * and then subtract that many bytes; e.g. func(ptr, char, int) will put
 * the arguments into r24:r25, r22, and r20:r21.  Once the allocation
 * goes past r8, arguments will be passed on the stack instead.
 *
 * Similar register allocation is used for return values up to 8 bytes;
 * e.g. 1 byte return values will be returned in r24, 2 byte in r24:r25.
 */

Insn Insn::bare(Type type)
{
    return Insn(type, 0, 0);
}

Insn Insn::reg1(Type type, unsigned char reg)
{
    if (reg >= 32) {
        throw std::invalid_argument("invalid register number");
    }
    return Insn(type, reg, 0);
}

Insn Insn::reg2(Type type, unsigned char reg1, unsigned char reg2)
{
    if (reg1 >= 32 || reg2 >= 32) {
        throw std::invalid_argument("invalid register number");
    }
    if (type == MOVW) {
        if ((reg1 % 2) != 0 || (reg2 % 2) != 0) {
            throw std::invalid_argument("not an even register number");
        }
    }
    return Insn(type, reg1, reg2);
}

Insn Insn::imm(Type type, unsigned reg, unsigned char value)
{
    if (reg < 16 || reg >= 32) {
        throw std::invalid_argument("not a high register");
    }
    if (type == ADIW || type == SBIW) {
        if (reg != 24 && reg != 26 && reg != 28 && reg != 30) {
            throw std::invalid_argument("invalid register for word immediate");
        }
    }
    return Insn(type, reg, value);
}

Insn Insn::branch(Type type, unsigned char ref)
{
    return Insn(type, ref, 0);
}

Insn Insn::label(unsigned char ref)
{
    return Insn(LABEL, ref, 0);
}

Insn Insn::memory(Type type, unsigned char reg, unsigned char offset)
{
    if (offset != PRE_DEC && offset != POST_INC) {
        if (type == LD_X || type == ST_X) {
            if (offset != 0)
                throw std::invalid_argument("invalid X pointer offset");
        } else {
            if (offset >= 64)
                throw std::invalid_argument("invalid Y or Z pointer offset");
        }
    }
    return Insn(type, reg, offset);
}

/**
 * \brief Constructs a subset of another register.
 *
 * \param other The other register to subset.
 * \param offset The offset into the low-level register list to start at.
 * \param count The number of registers to copy starting at \a offset.
 *
 * If \a count is zero then all low-level registers starting at \a offset
 * are copied, with registers before \a offset omitted.
 *
 * If \a offset + \a count exceeds the register size, then the copy
 * wraps around to the start of \a other.  This allows the application
 * to extract a rotated version of the register.
 */
Reg::Reg(const Reg &other, unsigned char offset, unsigned char count)
{
    if (offset >= other.size())
        return;
    if (count == 0)
        count = other.size() - offset;
    else if (count >= other.size())
        count = other.size();
    while (count > 0) {
        m_regs.push_back(other.m_regs[offset]);
        offset = (offset + 1) % other.m_regs.size();
        --count;
    }
}

Reg Reg::reversed() const
{
    Reg temp;
    for (int index = size(); index > 0; --index)
        temp.m_regs.push_back(m_regs[index - 1]);
    return temp;
}

Reg Reg::shuffle(const unsigned char *pattern) const
{
    Reg temp;
    for (int index = 0; index < size(); ++index)
        temp.m_regs.push_back(m_regs[pattern[index]]);
    return temp;
}

Reg Reg::shuffle(unsigned char offset0, unsigned char offset1,
                 unsigned char offset2, unsigned char offset3)
{
    unsigned char pattern[4] = {offset0, offset1, offset2, offset3};
    if (size() != 4)
        throw new std::invalid_argument("not a 32-bit register");
    return shuffle(pattern);
}

Reg Reg::shuffle(unsigned char offset0, unsigned char offset1,
                 unsigned char offset2, unsigned char offset3,
                 unsigned char offset4, unsigned char offset5,
                 unsigned char offset6, unsigned char offset7)
{
    unsigned char pattern[8] = {
        offset0, offset1, offset2, offset3,
        offset4, offset5, offset6, offset7
    };
    if (size() != 8)
        throw new std::invalid_argument("not a 64-bit register");
    return shuffle(pattern);
}

Reg Reg::x_ptr()
{
    Reg ptr;
    ptr.m_regs.push_back(26);
    ptr.m_regs.push_back(27);
    return ptr;
}

Reg Reg::y_ptr()
{
    Reg ptr;
    ptr.m_regs.push_back(28);
    ptr.m_regs.push_back(29);
    return ptr;
}

Reg Reg::z_ptr()
{
    Reg ptr;
    ptr.m_regs.push_back(30);
    ptr.m_regs.push_back(31);
    return ptr;
}

Code::Code()
{
    memset(m_immValues, 0, sizeof(m_immValues));
    clear();
}

Code::~Code()
{
}

void Code::clear()
{
    m_flags = MoveWord;
    m_insns.clear();
    m_labels.clear();
    m_allocated = 0;
    m_usedRegs = 0;
    m_immRegs = 0;
    m_immCount = 0;
    m_prologueType = Permutation;
    m_localsSize = 0;
    m_name = std::string();
    resetRegs();
}

int Code::getLabel(unsigned char ref) const
{
    if (ref < 1 || ref > m_labels.size()) {
        throw std::invalid_argument("invalid label reference");
    }
    int offset = m_labels[ref - 1];
    if (offset < 0) {
        throw std::invalid_argument("label is not set");
    }
    return offset;
}

/**
 * \brief Allocates a register consisting of multiple low-level registers
 * of any type.
 *
 * \param size Size of the register in bytes.
 *
 * \return The register that was allocated.
 *
 * \sa allocateHighReg(), releaseReg()
 */
Reg Code::allocateReg(unsigned size)
{
    return allocateRegInternal(size, false, false);
}

/**
 * \brief Allocates a register consisting of multiple low-level registers
 * as long as they are high registers.
 *
 * \param size Size of the register in bytes.
 *
 * \return The register that was allocated.
 *
 * \sa allocateReg(), releaseReg()
 */
Reg Code::allocateHighReg(unsigned size)
{
    return allocateRegInternal(size, true, false);
}

/**
 * \brief Allocates a register consisting of multiple low-level registers.
 *
 * \param size Size of the register in bytes.
 *
 * \return The register that was allocated.
 *
 * This function will not fail if there aren't enough low-level registers.
 * It will return as many registers as it can get.  This is useful when
 * allocating temporaries.  If there aren't enough, then the caller can
 * make use of the stack instead so the lack of temporaries isn't a problem.
 *
 * \sa allocateReg(), allocateHighReg(), releaseReg()
 */
Reg Code::allocateOptionalReg(unsigned size)
{
    return allocateRegInternal(size, false, true);
}

/**
 * \brief Releases a register back to the allocation pool.
 *
 * \param reg The register to be released.
 *
 * \sa allocateReg(), allocateHighReg()
 */
void Code::releaseReg(const Reg &reg)
{
    for (int index = 0; index < reg.size(); ++index)
        m_allocated &= ~(1 << reg.reg(index));
}

/**
 * \brief Adds two registers with carry in.
 *
 * \param reg1 The destination register to add to.
 * \param reg2 The source register to add from.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the carry
 * will continue to be propagated to the end of \a reg1.
 */
void Code::adc(const Reg &reg1, const Reg &reg2)
{
    for (int index = 0; index < reg1.size(); ++index) {
        if (index < reg2.size()) {
            tworeg(Insn::ADC, reg1.reg(index), reg2.reg(index));
        } else {
            tworeg(Insn::ADC, reg1.reg(index), ZERO_REG);
        }
    }
}

/**
 * \brief Adds two registers with no initial carry in.
 *
 * \param reg1 The destination register to add to.
 * \param reg2 The source register to add from.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the carry
 * will continue to be propagated to the end of \a reg1.
 */
void Code::add(const Reg &reg1, const Reg &reg2)
{
    if (reg2.size() == 0)
        return; // Adding zero to a register means do nothing.
    for (int index = 0; index < reg1.size(); ++index) {
        if (index == 0) {
            tworeg(Insn::ADD, reg1.reg(index), reg2.reg(index));
        } else if (index < reg2.size()) {
            tworeg(Insn::ADC, reg1.reg(index), reg2.reg(index));
        } else {
            tworeg(Insn::ADC, reg1.reg(index), ZERO_REG);
        }
    }
}

/**
 * \brief Adds an immediate value to a register.
 *
 * \param reg1 The destination register to add to.
 * \param value The immediate value to add.
 * \param carryIn Set to true to add an immediate value with a carry in.
 */
void Code::add(const Reg &reg1, unsigned long long value, bool carryIn)
{
    bool haveCarry = carryIn;
    for (int index = 0; index < reg1.size(); ++index) {
        unsigned char bvalue = (unsigned char)value;
        if (bvalue == 0) {
            // Only need to add zero if we may have a carry out
            // from the previous byte.  Otherwise skip the byte.
            if (haveCarry)
                tworeg(Insn::ADC, reg1.reg(index), ZERO_REG);
        } else if (bvalue == 1 && !haveCarry && reg1.size() == 1) {
            // Adding 1 to a single-byte register can be done with "inc".
            onereg(Insn::INC, reg1.reg(index));
            haveCarry = true;
        } else if (!haveCarry && reg1.size() == 1 && reg1.reg(0) >= 16) {
            // Adding an immediate to a single-byte high register can
            // be done with a "SUBI" instruction instead.
            immreg(Insn::SUBI, reg1.reg(index), 256 - bvalue);
            haveCarry = true;
        } else {
            // We need a high register to store the immediate byte value.
            unsigned char high_reg = immtemp(bvalue);
            if (haveCarry)
                tworeg(Insn::ADC, reg1.reg(index), high_reg);
            else
                tworeg(Insn::ADD, reg1.reg(index), high_reg);
            haveCarry = true;
        }
        value >>= 8;
    }
}

/**
 * \brief Performs an arithmetic shift right by 1 bit on a register.
 *
 * \param reg The register to shift.
 */
void Code::asr(const Reg &reg)
{
    for (int index = reg.size(); index > 0; --index) {
        if (index == reg.size())
            onereg(Insn::ASR, reg.reg(index - 1));
        else
            onereg(Insn::ROR, reg.reg(index - 1));
    }
}

/**
 * \brief Gets a single bit out of a register and copies it to T.
 *
 * \param reg The source register.
 * \param bit The index of the bit.
 *
 * \sa bit_put()
 */
void Code::bit_get(const Reg &reg, int bit)
{
    bitop(Insn::BST, reg.reg(bit / 8), bit % 8);
}

/**
 * \brief Puts the contents of T into a single bit of a register.
 *
 * \param reg The destination register.
 * \param bit The index of the bit.
 *
 * \sa bit_get()
 */
void Code::bit_put(const Reg &reg, int bit)
{
    bitop(Insn::BLD, reg.reg(bit / 8), bit % 8);
}

/**
 * \brief Permutes the bits in a register by manually moving them 1 at a time.
 *
 * \param reg The register to be permuted.
 * \param perm Points to the permutation to apply.
 * \param size Size of the permutation which must be between 0 and 240
 * and less than or equal to the size of the register.
 * \param inverse Set to true if the permutation should be inverted.
 *
 * Each element in the permutation specifies the destination bit.  For example,
 * the element at index 3 specifies the destination bit for source bit 3.
 */
void Code::bit_permute
    (const Reg &reg, const unsigned char *perm, int size, bool inverse)
{
    int index, prev, next;

    // Validate th size of the permutation.
    if (size < 0 || size > (reg.size() * 8) || size > 240)
        throw std::invalid_argument("invalid permutation size");

    // Invert the permutation to convert "source bit goes to destination bit"
    // into "destination bit comes from source bit".
    unsigned char P[size];
    if (!inverse) {
        memset(P, 0xFF, size);
        for (index = 0; index < size; ++index) {
            int dest = perm[index];
            if (dest >= size || P[dest] != 0xFF) {
                // Invalid destination bit number, or multiple source bits
                // are mapped to the same destination bit.
                throw std::invalid_argument("invalid permutation data");
            }
            P[dest] = index;
        }
    } else {
        // Permutation has already been inverted.
        memcpy(P, perm, size);
    }

    // Scan through the inverted permutation multiple times to find all
    // bit cycles, where A <- B <- ... <- Z <- A.  We stop once all
    // elements in the permutation have been moved to their destination.
    unsigned char done[size];
    memset(done, 0, size);
    for (index = 0; index < size; ++index) {
        int src = P[index];
        if (index == src) {
            // Bit is moving to itself, so nothing to do.
            done[index] = 1;
            continue;
        } else if (done[index]) {
            // We already handled this bit as part of a previous bit cycle.
            continue;
        }

        // Move the first bit in the cycle out into the temporary register.
        bit_get(reg, index);
        bitop(Insn::BLD, TEMP_REG, 0);
        done[index] = 1;

        // Copy the rest of the bits in the cycle.  We stop once we
        // see something that is already done because that is the
        // starting bit in the cycle.  Or at least it should be.
        prev = index;
        next = P[index];
        while (!done[next]) {
            bit_get(reg, next);
            bit_put(reg, prev);
            done[next] = 1;
            prev = next;
            next = P[prev];
        }

        // Copy the saved bit in the temporary register to the last position.
        bitop(Insn::BST, TEMP_REG, 0);
        bit_put(reg, prev);
    }
}

/**
 * \brief Clears a register by XOR'ing it with itself.
 *
 * \param reg The register to clear.
 *
 * This will affect the status flags.  Use move() with an immediate
 * instead to avoid modifying the status flags.
 *
 * \sa move()
 */
void Code::clr(const Reg &reg)
{
    for (int index = 0; index < reg.size(); ++index)
        tworeg(Insn::EOR, reg.reg(index), reg.reg(index));
}

/**
 * \brief Compares two registers.
 *
 * \param reg1 The first register.
 * \param reg2 The second register.
 *
 * If one of the registers is shorter than the other then the remaining
 * bytes will be compared against zero.
 *
 * The result is left in the status register so that a branch instruction
 * that follows can jump or not jump as expected.
 */
void Code::compare(const Reg& reg1, const Reg& reg2)
{
    int index;
    int minsize = reg1.size();
    Insn::Type type = Insn::CP;
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        tworeg(type, reg1.reg(index), reg2.reg(index));
        type = Insn::CPC;
    }
    while (index < reg1.size()) {
        tworeg(type, reg1.reg(index), ZERO_REG);
        type = Insn::CPC;
        ++index;
    }
    while (index < reg2.size()) {
        tworeg(type, ZERO_REG, reg2.reg(index));
        type = Insn::CPC;
        ++index;
    }
}

/**
 * \brief Compares a register against an immediate value.
 *
 * \param reg1 The register.
 * \param value The immediate value.
 *
 * The result is left in the status register so that a branch instruction
 * that follows can jump or not jump as expected.
 */
void Code::compare(const Reg& reg1, unsigned long long value)
{
    if (reg1.size() == 0)
        return;
    unsigned char bvalue = (unsigned char)value;
    if (bvalue == 0) {
        tworeg(Insn::CP, reg1.reg(0), ZERO_REG);
    } else if (reg1.reg(0) >= 16) {
        immreg(Insn::CPI, reg1.reg(0), (unsigned char)value);
    } else {
        unsigned char high_reg = immtemp((unsigned char)value);
        tworeg(Insn::CP, reg1.reg(0), high_reg);
    }
    for (int index = 1; index < reg1.size(); ++index) {
        value >>= 8;
        bvalue = (unsigned char)value;
        if (bvalue == 0) {
            tworeg(Insn::CPC, reg1.reg(index), ZERO_REG);
        } else {
            unsigned char high_reg = immtemp((unsigned char)value);
            tworeg(Insn::CPC, reg1.reg(index), high_reg);
        }
    }
}

/**
 * \brief Compares a register against an immediate value and loop back
 * if the values are not equal.
 *
 * \param reg1 The register.
 * \param value The immediate value.
 * \param label Reference to the label to loop back to if not equal.
 *
 * This function can be more efficient than compare() followed by brne()
 * when looping on the value of a single-byte register.
 */
void Code::compare_and_loop
    (const Reg& reg1, unsigned long long value, unsigned char &label)
{
    if (reg1.size() == 1) {
        // For a single-byte register we can be slightly more efficient.
        bool closeBy = false;
        if (label != 0 && (m_insns.size() - getLabel(label)) <= 50)
            closeBy = true;
        if (value == 0 && closeBy) {
            tworeg(Insn::CP, reg1.reg(0), ZERO_REG);
            brne(label);
        } else if (reg1.reg(0) >= 16 && closeBy) {
            immreg(Insn::CPI, reg1.reg(0), (unsigned char)value);
            brne(label);
        } else if (value == 0) {
            tworeg(Insn::CPSE, reg1.reg(0), ZERO_REG);
            jmp(label);
        } else {
            unsigned char high_reg = immtemp((unsigned char)value);
            tworeg(Insn::CPSE, reg1.reg(0), high_reg);
            jmp(label);
        }
    } else {
        // Multi-byte registers need a full comparison followed by "brne".
        compare(reg1, value);
        brne(label);
    }
}

/**
 * \brief Compares two registers for equality and set another
 * register based on the result.
 *
 * \param regout The output register to set.
 * \param reg1 The first register to compare.
 * \param reg2 The second register to compare (same size as \a reg1).
 * \param set The value to set in \a regout on equal.
 *
 * If \a set is zero, then \a regout is set to zero if the values are
 * equal and all-0xFF bytes if the values are not equal.
 *
 * If \a set is 1, then \a regout is set to 1 if the values are equal
 * and zero if the values are not equal.
 *
 * If \a set is anything else, then \a regout is set to all-0xFF bytes
 * if the values are equal and all-zero bytes if the values are not equal.
 *
 * The comparison is performed in a manner that is constant time.
 */
void Code::compare_and_set
    (const Reg &regout, const Reg& reg1, const Reg& reg2, unsigned char set)
{
    // Check the parameters.
    if (reg1.size() != reg2.size())
        throw std::invalid_argument("registers must be the same size");
    else if (reg1.size() == 0)
        throw std::invalid_argument("cannot compare empty registers");

    // Compute TEMP_REG = (R1[0] ^ R2[0]) | (R1[1] ^ R2[1]) | ...
    Reg temp = allocateReg(1);
    tworeg(Insn::MOV, TEMP_REG, reg1.reg(0));
    tworeg(Insn::EOR, TEMP_REG, reg2.reg(0));
    for (int index = 1; index < reg1.size(); ++index) {
        tworeg(Insn::MOV, temp.reg(0), reg1.reg(0));
        tworeg(Insn::EOR, temp.reg(0), reg2.reg(0));
        tworeg(Insn::OR, TEMP_REG, temp.reg(0));
    }

    // Subtract the result from zero.  If there is a carry out
    // then the two values are not equal.
    tworeg(Insn::MOV, temp.reg(0), ZERO_REG);
    tworeg(Insn::SUB, temp.reg(0), TEMP_REG);
    releaseReg(temp);

    // Now determine how to set the result register.
    if (set == 0) {
        // Result should be zero if equal or all-0xFF if not equal.
        tworeg(Insn::MOV, regout.reg(0), ZERO_REG);
        tworeg(Insn::SBC, regout.reg(0), ZERO_REG);
        for (int index = 1; index < regout.size(); ++index)
            tworeg(Insn::MOV, regout.reg(index), regout.reg(0));
    } else if (set == 1) {
        // Result should be 1 if equal or zero if not equal.
        tworeg(Insn::MOV, regout.reg(0), ZERO_REG);
        onereg(Insn::ROL, regout.reg(0));
        unsigned char high_reg = immtemp(0x01);
        tworeg(Insn::EOR, regout.reg(0), high_reg);
        for (int index = 1; index < regout.size(); ++index)
            tworeg(Insn::MOV, regout.reg(index), ZERO_REG);
    } else {
        // Result should be all-0xFF if equal or zero if not equal.
        tworeg(Insn::MOV, regout.reg(0), ZERO_REG);
        onereg(Insn::ROL, regout.reg(0));
        onereg(Insn::DEC, regout.reg(0));
        for (int index = 1; index < regout.size(); ++index)
            tworeg(Insn::MOV, regout.reg(index), regout.reg(0));
    }
}

/**
 * \brief Shifts the contents of a register left by a number of bits.
 *
 * \param reg The register to shift.
 * \param bits The number of bits to shift by.
 *
 * \sa lsr(), lsl_bytes()
 */
void Code::lsl(const Reg &reg, unsigned bits)
{
    if (bits == 0 || reg.size() == 0) {
        // Nothing to do.
        return;
    } else if (bits == 1) {
        // Shift left by 1 bit.
        for (int index = 0; index < reg.size(); ++index) {
            if (index == 0)
                onereg(Insn::LSL, reg.reg(index));
            else
                onereg(Insn::ROL, reg.reg(index));
        }
    } else if ((bits % 8) == 0) {
        // Shift left by a number of bytes.
        lsl_bytes(reg, bits / 8);
    } else if (bits == 4 && reg.size() == 1) {
        // We can do the shift with a nibble SWAP followed by an AND.
        onereg(Insn::SWAP, reg.reg(0));
        if (reg.reg(0) >= 16) {
            immreg(Insn::ANDI, reg.reg(0), 0xF0);
        } else {
            unsigned char high_reg = immtemp(0xF0);
            tworeg(Insn::AND, reg.reg(0), high_reg);
        }
    } else if ((bits % 8) <= 4) {
        // Shift left by 2, 3, or 4 bits plus a byte shift.
        lsl_bytes(reg, bits / 8);
        bits %= 8;
        while (bits > 0) {
            lsl(reg, 1);
            --bits;
        }
    } else {
        // Shift left by 5, 6, or 7 bits plus a byte shift.  We do this
        // by shifting right by 3, 2, or 1 bits and then do the byte shift.
        unsigned count = bits / 8;
        bits = (8 - (bits % 8));
        tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
        Reg temp(reg, 0, reg.size() - count);
        temp.m_regs.insert(temp.m_regs.begin(), TEMP_REG);
        while (bits > 0) {
            lsr(temp, 1);
            --bits;
        }
        moveHighFirst(Reg(reg, count, reg.size() - count),
                      Reg(temp, 0, reg.size() - count));
        move(Reg(reg, 0, count), 0);
    }
}

/**
 * \brief Shifts the contents of a register left by a number of bytes.
 *
 * \param reg The register to shift.
 * \param count The number of bytes to shift by.
 *
 * \sa lsl(), lsr_bytes()
 */
void Code::lsl_bytes(const Reg &reg, unsigned count)
{
    if (count == 0 || reg.size() == 0) {
        // Nothing to do.
        return;
    } else if (count >= (unsigned)reg.size()) {
        // The entire register will be shifted away.  Set it to zero.
        move(reg, 0);
    } else {
        // Shift the bytes up and then zero the remainder.
        Reg top(reg, count, reg.size() - count);
        Reg bottom(reg, 0, reg.size() - count);
        moveHighFirst(top, bottom);
        move(Reg(reg, 0, count), 0);
    }
}

/**
 * \brief Shifts the contents of a register right by a number of bits.
 *
 * \param reg The register to shift.
 * \param bits The number of bits to shift by.
 *
 * \sa lsl(), lsr_bytes()
 */
void Code::lsr(const Reg &reg, unsigned bits)
{
    if (bits == 0 || reg.size() == 0) {
        // Nothing to do.
        return;
    } else if (bits == 1) {
        // Shift right by 1 bit.
        for (int index = reg.size() - 1; index >= 0; --index) {
            if (index == (reg.size() - 1))
                onereg(Insn::LSR, reg.reg(index));
            else
                onereg(Insn::ROR, reg.reg(index));
        }
    } else if ((bits % 8) == 0) {
        // Shift right by a number of bytes.
        lsr_bytes(reg, bits / 8);
    } else if (bits == 4 && reg.size() == 1) {
        // We can do the shift with a nibble SWAP followed by an AND.
        onereg(Insn::SWAP, reg.reg(0));
        if (reg.reg(0) >= 16) {
            immreg(Insn::ANDI, reg.reg(0), 0x0F);
        } else {
            unsigned char high_reg = immtemp(0x0F);
            tworeg(Insn::AND, reg.reg(0), high_reg);
        }
    } else if ((bits % 8) <= 4) {
        // Shift right by 2, 3, or 4 bits plus a byte shift.
        lsr_bytes(reg, bits / 8);
        bits %= 8;
        while (bits > 0) {
            lsr(reg, 1);
            --bits;
        }
    } else {
        // Shift right by 5, 6, or 7 bits plus a byte shift.  We do this
        // by shifting left by 3, 2, or 1 bits and then do the byte shift.
        unsigned count = bits / 8;
        bits = (8 - (bits % 8));
        tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
        Reg temp(reg, count, reg.size() - count);
        temp.m_regs.push_back(TEMP_REG);
        while (bits > 0) {
            lsl(temp, 1);
            --bits;
        }
        move(Reg(reg, 0, reg.size() - count),
             Reg(temp, 1, reg.size() - count));
        move(Reg(reg, reg.size() - count, count), 0);
    }
}

/**
 * \brief Shifts the contents of a register right by a number of bytes.
 *
 * \param reg The register to shift.
 * \param count The number of bytes to shift by.
 *
 * \sa lsr(), lsl_bytes()
 */
void Code::lsr_bytes(const Reg &reg, unsigned count)
{
    if (count == 0 || reg.size() == 0) {
        // Nothing to do.
        return;
    } else if (count >= (unsigned)reg.size()) {
        // The entire register will be shifted away.  Set it to zero.
        move(reg, 0);
    } else {
        // Shift the bytes down and then zero the remainder.
        Reg top(reg, count, reg.size() - count);
        Reg bottom(reg, 0, reg.size() - count);
        move(bottom, top);
        move(Reg(reg, reg.size() - count, count), 0);
    }
}

/**
 * \brief Determine if we have a register pair that can be moved with "MOVW".
 *
 * \param reg The register to inspect.
 * \param index The index to look at for a register pair.
 */
static bool isRegPair(const Reg &reg, int index)
{
    if (index < 0 || index >= (reg.size() - 1))
        return false;
    if ((reg.reg(index) % 2) != 0)
        return false;
    return reg.reg(index + 1) == (reg.reg(index) + 1);
}

/**
 * \brief Determine if we have a reversed register pair that can be
 * moved with "MOVW".
 *
 * \param reg The register to inspect.
 * \param index The index to look at for a reversed register pair.
 */
static bool isRevRegPair(const Reg &reg, int index)
{
    if (index < 0 || index >= (reg.size() - 1))
        return false;
    if ((reg.reg(index) % 2) == 0)
        return false;
    return reg.reg(index + 1) == (reg.reg(index) - 1);
}

static bool sameReg(const Reg &reg1, int index1, const Reg &reg2, int index2)
{
    if (index1 < 0 || index1 >= reg1.size())
        return false;
    if (index2 < 0 || index2 >= reg2.size())
        return false;
    return reg1.reg(index1) == reg2.reg(index2);
}

/**
 * \brief Check two register pairs to ensure no overlap between them.
 *
 * \param reg1 First register.
 * \param reg2 Second register.
 * \param index Offset of the pair of registers.
 *
 * \return Returns true if there is no overlap, false if there is an overlap.
 */
static bool noOverlap(const Reg &reg1, const Reg &reg2, int index)
{
    if (sameReg(reg1, index, reg2, index))
        return false;
    if (sameReg(reg1, index, reg2, index + 1))
        return false;
    if (sameReg(reg1, index + 1, reg2, index))
        return false;
    if (sameReg(reg1, index + 1, reg2, index + 1))
        return false;
    return true;
}

/**
 * \brief Moves the contents of one register into another.
 *
 * \param reg1 The destination register.
 * \param reg2 The source register.
 * \param zeroFill Set to true to zero-fill the remaining bytes if \a reg1
 * is longer than \a reg2.  Otherwise only move the low bytes and leave
 * the high bytes of \a reg1 alone.
 *
 * The move starts with the low order bytes.  The \a reg1 and \a reg2
 * parameters can overlap only if the data is being moved downwards.
 * Use moveHighFirst() instead if the data is being moved upwards.
 *
 * \sa moveHighFirst()
 */
void Code::move(const Reg &reg1, const Reg &reg2, bool zeroFill)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        if (reg1.reg(index) == reg2.reg(index))
            continue; // Already in the destination.
        if (isRegPair(reg1, index) && isRegPair(reg2, index) &&
                hasFlag(MoveWord)) {
            tworeg(Insn::MOVW, reg1.reg(index), reg2.reg(index));
            ++index;
        } else if (isRevRegPair(reg1, index) && isRevRegPair(reg2, index) &&
                   hasFlag(MoveWord)) {
            tworeg(Insn::MOVW, reg1.reg(index) - 1, reg2.reg(index) - 1);
            ++index;
        } else {
            tworeg(Insn::MOV, reg1.reg(index), reg2.reg(index));
        }
    }
    while (index < reg1.size() && zeroFill) {
        // Zero-fill the rest of the destination register.
        tworeg(Insn::MOV, reg1.reg(index), ZERO_REG);
        ++index;
    }
}

/**
 * \brief Move an immediate value into a register.
 *
 * \param reg1 The register to load the value into.
 * \param value The immediate value to load.
 */
void Code::move(const Reg &reg1, unsigned long long value)
{
    for (int index = 0; index < reg1.size(); ++index) {
        unsigned char bvalue = (unsigned char)value;
        if (bvalue == 0) {
            tworeg(Insn::MOV, reg1.reg(index), ZERO_REG);
        } else if (reg1.reg(index) >= 16) {
            immreg(Insn::LDI, reg1.reg(index), bvalue);
        } else {
            unsigned char high_reg = immtemp(bvalue);
            tworeg(Insn::MOV, reg1.reg(index), high_reg);
        }
        value >>= 8;
    }
}

/**
 * \brief Moves the contents of one register into another, starting with
 * the high byte.
 *
 * \param reg1 The destination register.
 * \param reg2 The source register.
 *
 * This function differs from move() in that it starts at the high byte.
 * This may be necessary when moving values upwards from one section of a
 * register to another.
 *
 * If \a reg2 is smaller in size than \a reg1 then the extra bytes in
 * \a reg1 will be left as-is.
 *
 * \sa move()
 */
void Code::moveHighFirst(const Reg &reg1, const Reg &reg2)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = minsize - 1; index >= 0; --index) {
        if (reg1.reg(index) == reg2.reg(index))
            continue; // Already in the destination.
        if (isRegPair(reg1, index - 1) &&
                isRegPair(reg2, index - 1) &&
                noOverlap(reg1, reg2, index - 1) &&
                hasFlag(MoveWord)) {
            tworeg(Insn::MOVW, reg1.reg(index - 1), reg2.reg(index - 1));
            --index;
        } else if (isRevRegPair(reg1, index - 1) &&
                   isRevRegPair(reg2, index - 1) &&
                   noOverlap(reg1, reg2, index - 1) &&
                   hasFlag(MoveWord)) {
            tworeg(Insn::MOVW, reg1.reg(index), reg2.reg(index));
            --index;
        } else {
            tworeg(Insn::MOV, reg1.reg(index), reg2.reg(index));
        }
    }
}

/**
 * \brief Negates the contents of a register.
 *
 * \param reg The register to negate.
 */
void Code::neg(const Reg &reg)
{
    if (reg.size() == 1) {
        onereg(Insn::NEG, reg.reg(0));
    } else {
        lognot(reg);
        add(reg, 1);
    }
}

/**
 * \brief Performs a logical AND between two registers.
 *
 * \param reg1 The destination register to AND into.
 * \param reg2 The source register to AND from.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will be set to zero.
 */
void Code::logand(const Reg &reg1, const Reg &reg2)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        // AND all bytes that the two registers have in common.
        tworeg(Insn::AND, reg1.reg(index), reg2.reg(index));
    }
    while (index < reg1.size()) {
        // Zero-fill the rest of the destination register.
        tworeg(Insn::MOV, reg1.reg(index), ZERO_REG);
        ++index;
    }
}

/**
 * \brief Performs a logical AND between a register and an immediate value.
 *
 * \param reg1 The destination register to AND into.
 * \param value The immediate value to AND with.
 */
void Code::logand(const Reg &reg1, unsigned long long value)
{
    for (int index = 0; index < reg1.size(); ++index) {
        unsigned char bvalue = (unsigned char)value;
        if (bvalue == 0) {
            // AND'ing with zero simply sets the byte to zero.
            tworeg(Insn::MOV, reg1.reg(index), ZERO_REG);
        } else if (bvalue == 0xFF) {
            // AND'ing with 0xFF does nothing to the byte.  Skip it.
        } else if (reg1.reg(index) >= 16) {
            // We have a high register so we can AND with the value directly.
            immreg(Insn::ANDI, reg1.reg(index), bvalue);
        } else {
            // We need a temporary high register to hold the immediate value.
            unsigned char high_reg = immtemp(bvalue);
            tworeg(Insn::AND, reg1.reg(index), high_reg);
        }
        value >>= 8;
    }
}

/**
 * \brief Performs a logical AND-NOT between two registers.
 *
 * \param reg1 The destination register to AND into.
 * \param reg2 The source register to AND from.
 *
 * The result in reg1 will be set to (reg1 & ~reg2).
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will be ignored.
 */
void Code::logand_not(const Reg &reg1, const Reg &reg2)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        // AND-NOT all bytes that the two registers have in common.
        tworeg(Insn::MOV, TEMP_REG, reg2.reg(index));
        onereg(Insn::COM, TEMP_REG);
        tworeg(Insn::AND, reg1.reg(index), TEMP_REG);
    }
}

/**
 * \brief Complements a register by XOR'ing it with 0xFF.
 *
 * \param reg The register to complement.
 */
void Code::lognot(const Reg &reg)
{
    for (int index = 0; index < reg.size(); ++index)
        onereg(Insn::COM, reg.reg(index));
}

/**
 * \brief Performs a logical NOT of one register and puts the
 * result into another.
 *
 * \param reg1 The destination register to NOT into.
 * \param reg2 The source register to NOT from.
 *
 * The result in reg1 will be set to ~reg2.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will be set to 0xFF.
 */
void Code::lognot(const Reg &reg1, const Reg &reg2)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        // NOT and copy all bytes that the two registers have in common.
        tworeg(Insn::MOV, reg1.reg(index), reg2.reg(index));
        onereg(Insn::COM, reg1.reg(index));
    }
    while (index < reg1.size()) {
        // Fill the rest of the destination register with 0xFF bytes.
        if (reg1.reg(index) >= 16) {
            immreg(Insn::LDI, reg1.reg(index), 0xFF);
        } else {
            unsigned char high_reg = immtemp(0xFF);
            tworeg(Insn::MOV, reg1.reg(index), high_reg);
        }
        ++index;
    }
}

/**
 * \brief Performs a logical OR between two registers.
 *
 * \param reg1 The destination register to OR into.
 * \param reg2 The source register to OR from.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will ignored.
 */
void Code::logor(const Reg &reg1, const Reg &reg2)
{
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (int index = 0; index < minsize; ++index) {
        tworeg(Insn::OR, reg1.reg(index), reg2.reg(index));
    }
}

/**
 * \brief Performs a logical OR between a register and an immediate value.
 *
 * \param reg1 The destination register to OR into.
 * \param value The immediate value to OR with.
 */
void Code::logor(const Reg &reg1, unsigned long long value)
{
    for (int index = 0; index < reg1.size(); ++index) {
        unsigned char bvalue = (unsigned char)value;
        if (bvalue == 0xFF) {
            if (reg1.reg(index) >= 16) {
                immreg(Insn::LDI, reg1.reg(index), bvalue);
            } else {
                unsigned char high_reg = immtemp(bvalue);
                tworeg(Insn::MOV, reg1.reg(index), high_reg);
            }
        } else if (bvalue != 0) {
            if (reg1.reg(index) >= 16) {
                immreg(Insn::ORI, reg1.reg(index), bvalue);
            } else {
                unsigned char high_reg = immtemp(bvalue);
                tworeg(Insn::OR, reg1.reg(index), high_reg);
            }
        }
        value >>= 8;
    }
}

/**
 * \brief Performs a logical OR-NOT between two registers.
 *
 * \param reg1 The destination register to OR into.
 * \param reg2 The source register to OR from.
 *
 * The result in reg1 will be set to (reg1 | ~reg2).
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will be set to 0xFF.
 */
void Code::logor_not(const Reg &reg1, const Reg &reg2)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        // OR-NOT all bytes that the two registers have in common.
        tworeg(Insn::MOV, TEMP_REG, reg2.reg(index));
        onereg(Insn::COM, TEMP_REG);
        tworeg(Insn::OR, reg1.reg(index), TEMP_REG);
    }
    while (index < reg1.size()) {
        // Fill the rest of the destination register with 0xFF bytes.
        if (reg1.reg(index) >= 16) {
            immreg(Insn::LDI, reg1.reg(index), 0xFF);
        } else {
            unsigned char high_reg = immtemp(0xFF);
            tworeg(Insn::MOV, reg1.reg(index), high_reg);
        }
        ++index;
    }
}

/**
 * \brief Performs a logical XOR between two registers.
 *
 * \param reg1 The destination register to XOR into.
 * \param reg2 The source register to XOR from.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will ignored.
 */
void Code::logxor(const Reg &reg1, const Reg &reg2)
{
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (int index = 0; index < minsize; ++index) {
        tworeg(Insn::EOR, reg1.reg(index), reg2.reg(index));
    }
}

/**
 * \brief Performs a logical XOR between a register and an immediate value.
 *
 * \param reg1 The destination register to XOR into.
 * \param value The immediate value to XOR with.
 */
void Code::logxor(const Reg &reg1, unsigned long long value)
{
    for (int index = 0; index < reg1.size(); ++index) {
        unsigned char bvalue = (unsigned char)value;
        if (bvalue == 0xFF) {
            onereg(Insn::COM, reg1.reg(index));
        } else if (bvalue != 0) {
            unsigned char high_reg = immtemp(bvalue);
            tworeg(Insn::EOR, reg1.reg(index), high_reg);
        }
        value >>= 8;
    }
}

/**
 * \brief Performs a logical XOR-NOT between two registers.
 *
 * \param reg1 The destination register to XOR into.
 * \param reg2 The source register to XOR from.
 *
 * The result in reg1 will be set to (reg1 ^ ~reg2).
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the high
 * bytes of \a reg1 will be XOR'ed with 0xFF.
 */
void Code::logxor_not(const Reg &reg1, const Reg &reg2)
{
    int index;
    int minsize = reg1.size();
    if (reg2.size() < minsize)
        minsize = reg2.size();
    for (index = 0; index < minsize; ++index) {
        // XOR-NOT all bytes that the two registers have in common.
        tworeg(Insn::MOV, TEMP_REG, reg2.reg(index));
        onereg(Insn::COM, TEMP_REG);
        tworeg(Insn::EOR, reg1.reg(index), TEMP_REG);
    }
    while (index < reg1.size()) {
        // XOR the rest of the destination register with 0xFF bytes.
        onereg(Insn::COM, reg1.reg(index));
        ++index;
    }
}

/**
 * \brief Pops a register from the stack.
 *
 * \param reg The register to pop the values into.
 *
 * The value is popped LSB-first.
 *
 * \sa push()
 */
void Code::pop(const Reg &reg)
{
    for (int index = 0; index < reg.size(); ++index)
        onereg(Insn::POP, reg.reg(index));
}

/**
 * \brief Pushes a register onto the stack.
 *
 * \param reg The register to push.
 *
 * The value is pushed MSB-first.
 *
 * \sa pop()
 */
void Code::push(const Reg &reg)
{
    for (int index = reg.size() - 1; index >= 0; --index)
        onereg(Insn::PUSH, reg.reg(index));
}

/**
 * \brief Rotates the contents of a register left by a number of bits.
 *
 * \param reg The register to rotate.
 * \param bits The number of bits to rotate by.
 *
 * \sa ror(), rol_bytes()
 */
void Code::rol(const Reg &reg, unsigned bits)
{
    if (bits == 0 || reg.size() == 0) {
        // Nothing to do when rotating by zero bits.
        return;
    } else if (bits == 1) {
        // Rotate left by a single bit.
        for (int index = 0; index < reg.size(); ++index) {
            if (index == 0)
                onereg(Insn::LSL, reg.reg(index));
            else
                onereg(Insn::ROL, reg.reg(index));
        }
        tworeg(Insn::ADC, reg.reg(0), ZERO_REG);
    } else if ((bits % 8) == 0) {
        // Rotation is a multiple of 8, so rotate the bytes instead.
        rol_bytes(reg, bits / 8);
    } else if (bits == 4 && reg.size() == 1) {
        // Rotating a single byte by 4 bits is a nibble swap.
        onereg(Insn::SWAP, reg.reg(0));
    } else if ((bits % 8) <= 4) {
        // Rotate left by between 2 and 4 bits, plus byte rotations.
        rol_bytes(reg, bits / 8);
        bits &= 7;
        while (bits > 0) {
            rol(reg, 1);
            --bits;
        }
    } else {
        // Rotate left by between 5 and 7 bits.  We can do this with a
        // right bit rotation by "8 - bits" together with a byte rotation.
        rol_bytes(reg, (bits / 8) + 1);
        ror(reg, 8 - (bits % 8));
    }
}

/**
 * \brief Rotates the contents of a register left by a number of bytes.
 *
 * \param reg The register to rotate.
 * \param count The number of bytes to rotate by.
 *
 * \sa rol(), ror_bytes()
 */
void Code::rol_bytes(const Reg &reg, unsigned count)
{
    if (reg.size() == 0)
        return;
    count %= (unsigned)(reg.size());
    if (count == 0) {
        // Nothing to do for a rotation by zero bytes.
        return;
    } else if (count > (unsigned)(reg.size() / 2)) {
        // Rotating more than half-way so it is more efficient to
        // rotate in the other direction instead.
        ror_bytes(reg, reg.size() - count);
    } else if ((reg.size() % count) == 0) {
        // The register size is a multiple of the rotation, so we can
        // do it in several strips.  For example, for a rotation of
        // 3 on a 9-byte register, rotate bytes 0, 3, and 6; then bytes
        // 1, 4, and 7, and finally bytes 2, 5, and 8.  This way we
        // only need a single temporary register to do the rotation.
        int strip_len = reg.size() / count;
        int from, to;
        for (int strip = 0; strip < (int)count; ++strip) {
            from = (strip + (strip_len - 1) * count) % reg.size();
            tworeg(Insn::MOV, TEMP_REG, reg.reg(from));
            for (int posn = strip_len - 2; posn >= 0; --posn) {
                from = (strip + posn * count) % reg.size();
                to = (strip + (posn + 1) * count) % reg.size();
                tworeg(Insn::MOV, reg.reg(to), reg.reg(from));
            }
            tworeg(Insn::MOV, reg.reg(strip), TEMP_REG);
        }
    } else {
        // We need multiple temporary registers to perform the rotation.
        // If we don't have enough registers free, use the stack instead.
        int index;
        Reg temp = allocateOptionalReg(count - 1);
        for (index = 0; index < (int)count; ++index) {
            int from = reg.size() - count + index;
            if (index == 0)
                tworeg(Insn::MOV, TEMP_REG, reg.reg(from));
            else if ((index - 1) < temp.size())
                tworeg(Insn::MOV, temp.reg(index - 1), reg.reg(from));
            else
                onereg(Insn::PUSH, reg.reg(from));
        }
        for (index = reg.size() - count - 1; index >= 0; --index) {
            tworeg(Insn::MOV, temp.reg(index), reg.reg(index + count));
        }
        for (index = count - 1; index >= 0; --index) {
            if (index == 0)
                tworeg(Insn::MOV, reg.reg(index), TEMP_REG);
            else if ((index - 1) < temp.size())
                tworeg(Insn::MOV, reg.reg(index), temp.reg(index - 1));
            else
                onereg(Insn::POP, reg.reg(index));
        }
        releaseReg(temp);
    }
}

/**
 * \brief Rotates the contents of a register right by a number of bits.
 *
 * \param reg The register to rotate.
 * \param bits The number of bits to rotate by.
 *
 * \sa rol(), ror_bytes()
 */
void Code::ror(const Reg &reg, unsigned bits)
{
    if (bits == 0 || reg.size() == 0) {
        // Nothing to do when rotating by zero bits.
        return;
    } else if (bits == 1) {
        // Rotate right by a single bit.
        bitop(Insn::BST, reg.reg(0), 0);
        for (int index = reg.size() - 1; index >= 0; --index) {
            if (index == (reg.size() - 1))
                onereg(Insn::LSR, reg.reg(index));
            else
                onereg(Insn::ROR, reg.reg(index));
        }
        bitop(Insn::BLD, reg.reg(reg.size() - 1), 7);
    } else if ((bits % 8) == 0) {
        // Rotation is a multiple of 8, so rotate the bytes instead.
        ror_bytes(reg, bits / 8);
    } else if (bits == 4 && reg.size() == 1) {
        // Rotating a single byte by 4 bits is a nibble swap.
        onereg(Insn::SWAP, reg.reg(0));
    } else if ((bits % 8) <= 4) {
        // Rotate right by between 2 and 4 bits, plus byte rotations.
        // We can save some instructions by accumulating the shifted-out
        // bits before OR'ing them back in again at the end.
        ror_bytes(reg, bits / 8);
        bits %= 8;
        tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
        while (bits > 0) {
            onereg(Insn::LSR, reg.reg(reg.size() - 1));
            for (int index = reg.size() - 2; index >= 0; --index)
                onereg(Insn::ROR, reg.reg(index));
            onereg(Insn::ROR, TEMP_REG);
            --bits;
        }
        tworeg(Insn::OR, reg.reg(reg.size() - 1), TEMP_REG);
    } else {
        // Rotate right by between 5 and 7 bits.  We can do this with a
        // left bit rotation by "8 - bits" together with a byte rotation.
        ror_bytes(reg, (bits / 8) + 1);
        rol(reg, 8 - (bits % 8));
    }
}

/**
 * \brief Rotates the contents of a register right by a number of bytes.
 *
 * \param reg The register to rotate.
 * \param count The number of bytes to rotate by.
 *
 * \sa ror(), rol_bytes()
 */
void Code::ror_bytes(const Reg &reg, unsigned count)
{
    if (reg.size() == 0)
        return;
    count %= (unsigned)(reg.size());
    if (count == 0) {
        // Nothing to do for a rotation by zero bytes.
        return;
    } else if (count > (unsigned)(reg.size() / 2)) {
        // Rotating more than half-way so it is more efficient to
        // rotate in the other direction instead.
        rol_bytes(reg, reg.size() - count);
    } else if ((reg.size() % count) == 0) {
        // The register size is a multiple of the rotation, so we can
        // do it in several strips.  For example, for a rotation of
        // 3 on a 9-byte register, rotate bytes 0, 3, and 6; then bytes
        // 1, 4, and 7, and finally bytes 2, 5, and 8.  This way we
        // only need a single temporary register to do the rotation.
        int strip_len = reg.size() / count;
        int from, to;
        for (int strip = 0; strip < (int)count; ++strip) {
            tworeg(Insn::MOV, TEMP_REG, reg.reg(strip));
            for (int posn = 1; posn < strip_len; ++posn) {
                from = (strip + posn * count) % reg.size();
                to = (strip + (posn - 1) * count) % reg.size();
                tworeg(Insn::MOV, reg.reg(to), reg.reg(from));
            }
            to = (strip + (strip_len - 1) * count) % reg.size();
            tworeg(Insn::MOV, reg.reg(to), TEMP_REG);
        }
    } else {
        // We need multiple temporary registers to perform the rotation.
        // If we don't have enough registers free, use the stack instead.
        int index;
        Reg temp = allocateOptionalReg(count - 1);
        for (index = 0; index < (int)count; ++index) {
            if (index == 0)
                tworeg(Insn::MOV, TEMP_REG, reg.reg(index));
            else if ((index - 1) < temp.size())
                tworeg(Insn::MOV, temp.reg(index - 1), reg.reg(index));
            else
                onereg(Insn::PUSH, reg.reg(index));
        }
        for (index = 0; index < (int)(reg.size() - count); ++index) {
            tworeg(Insn::MOV, temp.reg(index), reg.reg(index + count));
        }
        for (index = count - 1; index >= 0; --index) {
            int to = reg.size() - count + index;
            if (index == 0)
                tworeg(Insn::MOV, reg.reg(to), TEMP_REG);
            else if ((index - 1) < temp.size())
                tworeg(Insn::MOV, reg.reg(to), temp.reg(index - 1));
            else
                onereg(Insn::POP, reg.reg(to));
        }
        releaseReg(temp);
    }
}

/**
 * \brief Subtracts two registers with carry in.
 *
 * \param reg1 The destination register to subtract from.
 * \param reg2 The source register to subtract.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the carry
 * will continue to be propagated to the end of \a reg1.
 */
void Code::sbc(const Reg &reg1, const Reg &reg2)
{
    for (int index = 0; index < reg1.size(); ++index) {
        if (index < reg2.size()) {
            tworeg(Insn::SBC, reg1.reg(index), reg2.reg(index));
        } else {
            tworeg(Insn::SBC, reg1.reg(index), ZERO_REG);
        }
    }
}

/**
 * \brief Subtracts two registers with no initial carry in.
 *
 * \param reg1 The destination register to subtract from.
 * \param reg2 The source register to subtract.
 *
 * If \a reg1 is shorter than \a reg2, then the high bytes of \a reg2
 * will be ignored.  If \a reg1 is longer than \a reg2, then the carry
 * will continue to be propagated to the end of \a reg1.
 */
void Code::sub(const Reg &reg1, const Reg &reg2)
{
    if (reg2.size() == 0)
        return; // Subtracting zero from a register means do nothing.
    for (int index = 0; index < reg1.size(); ++index) {
        if (index == 0) {
            tworeg(Insn::SUB, reg1.reg(index), reg2.reg(index));
        } else if (index < reg2.size()) {
            tworeg(Insn::SBC, reg1.reg(index), reg2.reg(index));
        } else {
            tworeg(Insn::SBC, reg1.reg(index), ZERO_REG);
        }
    }
}

/**
 * \brief Adds an immediate value from a register.
 *
 * \param reg1 The destination register to subract from.
 * \param value The immediate value to subtract.
 * \param carryIn Set to true to subtract an immediate value with a carry in.
 */
void Code::sub(const Reg &reg1, unsigned long long value, bool carryIn)
{
    bool haveCarry = carryIn;
    for (int index = 0; index < reg1.size(); ++index) {
        unsigned char bvalue = (unsigned char)value;
        if (bvalue == 0) {
            // Only need to subtract zero if we may have a carry out
            // from the previous byte.  Otherwise skip the byte.
            if (haveCarry)
                tworeg(Insn::SBC, reg1.reg(index), ZERO_REG);
        } else if (bvalue == 1 && !haveCarry && reg1.size() == 1) {
            // Subtracting 1 from a single-byte register can be done with "dec".
            onereg(Insn::DEC, reg1.reg(index));
            haveCarry = true;
        } else if (reg1.reg(index) >= 16) {
            // We can use SBCI or SUBI to perform the subtraction.
            if (haveCarry)
                immreg(Insn::SBCI, reg1.reg(index), bvalue);
            else
                immreg(Insn::SUBI, reg1.reg(index), bvalue);
            haveCarry = true;
        } else {
            // We need a high register to store the immediate byte value.
            unsigned char high_reg = immtemp(bvalue);
            if (haveCarry)
                tworeg(Insn::SBC, reg1.reg(index), high_reg);
            else
                tworeg(Insn::SUB, reg1.reg(index), high_reg);
            haveCarry = true;
        }
        value >>= 8;
    }
}

/**
 * \brief Sets up the function prologue for a key setup function.
 *
 * \param name Name of the key setup function.
 * \param size_locals Number of bytes of local variables that are needed.
 *
 * The generated function will have the following prototype:
 *
 * \code
 * void name(void *schedule, const void *key)
 * \endcode
 *
 * Where "key" points to the encryption key and "schedule" points to
 * the key schedule to be populated.
 *
 * In the generated code, Z will point to "schedule" and X will
 * point to "key" on entry.
 *
 * \sa prologue_encrypt_block()
 */
void Code::prologue_setup_key(const char *name, unsigned size_locals)
{
    m_prologueType = KeySetup;
    m_name = name;
    m_localsSize = size_locals;
}

/**
 * \brief Sets up the function prologue for a block encrypt function.
 *
 * \param name Name of the block encrypt function.
 * \param size_locals Number of bytes of local variables that are needed.
 *
 * The generated function will have the following prototype:
 *
 * \code
 * void name(const void *key, void *output, const void *input)
 * \endcode
 *
 * Where "key" points to the encryption key, or the key schedule if the
 * schedule needs to be set up separately.  The "input" parameter points
 * to the input block to be encrypted.  The "output" parameter points to
 * the output block after encryption.
 *
 * In the generated code, Z will point to "key", X will point to
 * "input" and Y will point to the local variable space.  The code
 * should use load_output_ptr() later to load the "output" address
 * into the X register at the end of the function.
 *
 * This function can also be used to set up a function prologue for a
 * block decrypt function.
 *
 * \sa prologue_setup_key()
 */
void Code::prologue_encrypt_block(const char *name, unsigned size_locals)
{
    m_prologueType = EncryptBlock;
    m_name = name;
    m_localsSize = size_locals;
}

/**
 * \brief Sets up the function prologue for a block encrypt function with an
 * extra tweak parameter.
 *
 * \param name Name of the block encrypt function.
 * \param size_locals Number of bytes of local variables that are needed.
 *
 * \return Returns a reference to the tweak byte.
 *
 * The generated function will have the following prototype:
 *
 * \code
 * void name(const void *key, void *output, const void *input, unsigned char tweak)
 * \endcode
 *
 * Where "key" points to the encryption key, or the key schedule if the
 * schedule needs to be set up separately.  The "input" parameter points
 * to the input block to be encrypted.  The "output" parameter points to
 * the output block after encryption.  The "tweak" parameter is the
 * tweak byte to use.
 *
 * In the generated code, Z will point to "key", X will point to
 * "input" and Y will point to the local variable space.  The code
 * should use load_output_ptr() later to load the "output" address
 * into the X register at the end of the function.
 *
 * This function can also be used to set up a function prologue for a
 * tweakable block decrypt function.
 *
 * \sa prologue_encrypt_block()
 */
Reg Code::prologue_encrypt_block_with_tweak
    (const char *name, unsigned size_locals)
{
    m_prologueType = EncryptBlock;
    m_name = name;
    m_localsSize = size_locals;

    // Output the standard encrypt block header.
    prologue_encrypt_block(name, size_locals);

    // r18 will contain the "tweak" parameter on entry, so allocate it.
    m_allocated |= (1 << 18);
    m_usedRegs |= (1 << 18);
    Reg reg;
    reg.m_regs.push_back(18);
    return reg;
}

/**
 * \brief Sets up the function prologue for a permutation function.
 *
 * \param name Name of the permutation function.
 * \param size_locals Number of bytes of local variables that are needed.
 *
 * The generated function will have the following prototype:
 *
 * \code
 * void name(void *state)
 * \endcode
 *
 * Where "state" points to the state to be permuted by the function.
 * In the generated code, Z will point to "state" and the registers
 * of X will be free for use as temporary variables.
 */
void Code::prologue_permutation(const char *name, unsigned size_locals)
{
    m_prologueType = Permutation;
    m_name = name;
    m_localsSize = size_locals;
    setFlag(TempX);
}

/**
 * \brief Sets up the function prologue for a permutation function.
 *
 * \param name Name of the permutation function.
 * \param size_locals Number of bytes of local variables that are needed.
 *
 * \return A register reference to the count parameter.
 *
 * The generated function will have the following prototype:
 *
 * \code
 * void name(void *state, unsigned char count)
 * \endcode
 *
 * Where "state" points to the state to be permuted by the function
 * and "count" is the number of rounds to perform or some other parameter
 * that controls the number of rounds.  In the generated code,
 * Z will point to "state" and the registers of X will be free for
 * use as temporary variables.
 */
Reg Code::prologue_permutation_with_count
    (const char *name, unsigned size_locals)
{
    // Output the standard permutation header.
    prologue_permutation(name, size_locals);

    // r22 will contain the "count" parameter on entry, so allocate it.
    m_allocated |= (1 << 22);
    m_usedRegs |= (1 << 22);
    Reg reg;
    reg.m_regs.push_back(22);
    return reg;
}

/**
 * \brief Sets up the function prologue for TinyJAMBU.
 *
 * \param name Name of the permutation function.
 * \param key_words Returns a reference to the register that holds the
 * "key_words" parameter.
 * \param rounds Returns a reference to the register that holds the
 * "rounds" parameter.
 *
 * The generated function will have the following prototype:
 *
 * \code
 * void name(void *state, void *key, uint8_t key_words, uint8_t rounds);
 * \endcode
 *
 * The "state" parameter will end up in the X register and the "key"
 * parameter will end up in th "Z" register.
 */
void Code::prologue_tinyjambu(const char *name, Reg &key_words, Reg &rounds)
{
    // Set up the prologue type.
    m_prologueType = TinyJAMBU;
    m_name = name;
    m_localsSize = 0;

    // r20 will contain the "key_words" parameter and r18 will contain
    // the "rounds" parameter on entry, so allocate them.
    m_allocated |= (1 << 20) | (1 << 18);
    m_usedRegs |= (1 << 22) | (1 << 18);
    Reg reg1, reg2;
    reg1.m_regs.push_back(20);
    reg2.m_regs.push_back(18);
    key_words = reg1;
    rounds = reg2;
}

/**
 * \brief Loads the output block pointer for an encrypt operation into X.
 *
 * \sa prologue_encrypt_block()
 */
void Code::load_output_ptr()
{
    // The output pointer is after the locals within the stack frame.
    ldy(Reg::x_ptr(), m_localsSize);
}

/**
 * \brief Doubles a value in a GF field.
 *
 * \param reg The register value to be doubled where the low byte is
 * index 0 in the word.
 * \param feedback The feedback value to XOR with the 1 or 2 low bytes
 * when the high bit is non-zero.
 *
 * The function multiplies \a reg by 2 and then XOR's the low bits
 * with \a feedback if the shifted-out high bit was non-zero.
 *
 * The operation is performed in constant time.
 */
void Code::double_gf(const Reg &reg, unsigned feedback)
{
    if (reg.size() == 0)
        return;
    onereg(Insn::LSL, reg.reg(0));
    for (int index = 1; index < reg.size(); ++index)
        onereg(Insn::ROL, reg.reg(index));
    Reg temp = allocateHighReg(1);
    if (feedback < 0x0100U || reg.size() == 1) {
        // Single byte feedback value.
        tworeg(Insn::MOV, temp.reg(0), ZERO_REG);
        tworeg(Insn::SBC, temp.reg(0), ZERO_REG);
        immreg(Insn::ANDI, temp.reg(0), (unsigned char)feedback);
        tworeg(Insn::EOR, reg.reg(0), temp.reg(0));
    } else {
        // Two byte feedback value.
        tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
        tworeg(Insn::SBC, TEMP_REG, ZERO_REG);
        immreg(Insn::LDI, temp.reg(0), (unsigned char)feedback);
        tworeg(Insn::AND, temp.reg(0), TEMP_REG);
        tworeg(Insn::EOR, reg.reg(0), temp.reg(0));
        immreg(Insn::LDI, temp.reg(0), (unsigned char)(feedback >> 8));
        tworeg(Insn::AND, temp.reg(0), TEMP_REG);
        tworeg(Insn::EOR, reg.reg(1), temp.reg(0));
    }
    releaseReg(temp);
}

void Code::print(const Reg &reg)
{
    if (!hasFlag(Print))
        return;
    for (int index = 0; index < reg.size(); ++index)
        onereg(Insn::PRINT, reg.reg(index));
}

void Code::print(const char *str)
{
    if (!hasFlag(Print))
        return;
    while (str && *str != '\0') {
        immreg(Insn::PRINTCH, 16, (unsigned char)(*str));
        ++str;
    }
}

void Code::println(void)
{
    if (hasFlag(Print))
        bare(Insn::PRINTLN);
}

void Code::bare(Insn::Type type)
{
    if (type == Insn::RET) {
        // Flush temporary immediates when we see a "ret" instruction.
        m_immRegs = 0;
        m_immCount = 0;
    }
    m_insns.push_back(Insn::bare(type));
}

void Code::branch(Insn::Type type, unsigned char &ref)
{
    m_immRegs = 0; // Flush temporary immediates when we see a branch point.
    m_immCount = 0;
    if (ref == 0) {
        if (type == Insn::LABEL)
            m_labels.push_back((int)(m_insns.size()));
        else
            m_labels.push_back(-1);
        ref = m_labels.size();
    } else if (type == Insn::LABEL) {
        if (ref > m_labels.size())
            throw std::invalid_argument("invalid label reference");
        if (m_labels[ref - 1] != -1)
            throw std::invalid_argument("label specified multiple times");
        m_labels[ref - 1] = (int)(m_insns.size());
    } else {
        if (ref > m_labels.size())
            throw std::invalid_argument("invalid label reference");
    }
    m_insns.push_back(Insn::branch(type, ref));
}

void Code::onereg(Insn::Type type, unsigned char reg)
{
    m_insns.push_back(Insn::reg1(type, reg));
    used(reg);
}

void Code::tworeg(Insn::Type type, unsigned char reg1, unsigned char reg2)
{
    m_insns.push_back(Insn::reg2(type, reg1, reg2));
    used(reg1);
    used(reg2);
}

void Code::bitop(Insn::Type type, unsigned char reg, unsigned char bit)
{
    m_insns.push_back(Insn::reg2(type, reg, bit));
    used(reg);
}

void Code::immreg(Insn::Type type, unsigned char reg, unsigned char value)
{
    m_insns.push_back(Insn::imm(type, reg, value));
    used(reg);
}

void Code::memory(Insn::Type type, unsigned char reg, unsigned char offset)
{
    m_insns.push_back(Insn::memory(type, reg, offset));
    used(reg);
}

void Code::resetRegs()
{
    m_regOrder.clear();

    // Allocate some high registers that we don't need to save first.
    m_regOrder.push_back(18);
    m_regOrder.push_back(19);
    m_regOrder.push_back(20);
    m_regOrder.push_back(21);
    m_regOrder.push_back(22);
    m_regOrder.push_back(23);

    // Add the X/Y/Z registers if we are allowed to use them as temporaries.
    if (hasFlag(TempX)) {
        m_regOrder.push_back(26);
        m_regOrder.push_back(27);
    }
    if (hasFlag(TempY)) {
        m_regOrder.push_back(28);
        m_regOrder.push_back(29);
    }
    if (hasFlag(TempZ)) {
        m_regOrder.push_back(30);
        m_regOrder.push_back(31);
    }

    // Low registers that we need to save on the stack if we use them.
    m_regOrder.push_back(2);
    m_regOrder.push_back(3);
    m_regOrder.push_back(4);
    m_regOrder.push_back(5);
    m_regOrder.push_back(6);
    m_regOrder.push_back(7);
    m_regOrder.push_back(8);
    m_regOrder.push_back(9);
    m_regOrder.push_back(10);
    m_regOrder.push_back(11);
    m_regOrder.push_back(12);
    m_regOrder.push_back(13);
    m_regOrder.push_back(14);
    m_regOrder.push_back(15);

    // Other high registers.  We put these last so that hopefully we
    // will always have a few spare high registers for immediates even
    // if the rest of the high registers are already in use.
    m_regOrder.push_back(24);
    m_regOrder.push_back(25);
    m_regOrder.push_back(16);
    m_regOrder.push_back(17);
}

void Code::used(unsigned char reg)
{
    m_usedRegs |= (1 << reg);
}

/**
 * \brief Allocates a spare register.
 *
 * \param high Set to true if the register must be a high register.
 *
 * \return The register number or zero if there are no free registers left.
 */
unsigned char Code::allocateSpare(bool high)
{
    for (unsigned index = 0; index < m_regOrder.size(); ++index) {
        unsigned char reg = m_regOrder[index];
        if (m_allocated & (1 << reg))
            continue;
        if (high && reg < 16)
            continue;
        m_allocated |= (1 << reg);
        m_immRegs &= ~(1 << reg);
        return reg;
    }
    return 0;
}

/**
 * \brief Allocates a pair of spare registers that are contiguous.
 *
 * \param high Set to true if the register pair must be in high registers.
 *
 * \return The register number of the first register in the pair,
 * or zero if there are no free register pairs left.
 *
 * This function is intended to optimize for using MOVW instructions later.
 */
unsigned char Code::allocateSparePair(bool high)
{
    for (unsigned index = 0; index < (m_regOrder.size() - 1); ++index) {
        unsigned char reg1 = m_regOrder[index];
        unsigned char reg2 = m_regOrder[index + 1];
        if ((reg1 % 2) != 0 || reg2 != (reg1 + 1))
            continue;
        if (m_allocated & (1 << reg1))
            continue;
        if (m_allocated & (1 << reg2))
            continue;
        if (high && reg1 < 16)
            continue;
        m_allocated |= (1 << reg1) | (1 << reg2);
        m_immRegs &= ~((1 << reg1) | (1 << reg2));
        return reg1;
    }
    return 0;
}

Reg Code::allocateRegInternal(unsigned size, bool high, bool optional)
{
    Reg result;
    while (size > 0) {
        unsigned char reg;
        if ((result.m_regs.size() % 2) == 0 && size >= 2) {
            // Try allocating a register pair in this position.
            reg = allocateSparePair(high);
            if (reg != 0) {
                result.m_regs.push_back(reg);
                result.m_regs.push_back(reg + 1);
                size -= 2;
                continue;
            }
        }
        reg = allocateSpare(high);
        if (reg == 0) {
            if (optional)
                break;
            releaseReg(result);
            throw std::overflow_error("too many registers in use");
        }
        result.m_regs.push_back(reg);
        --size;
    }
    return result;
}

unsigned char Code::immtemp(unsigned char value)
{
    int index;

    // Do we already have a high register with the immediate value in it?
    for (index = 16; index < 32; ++index) {
        if (m_immRegs & (1 << index)) {
            if (m_immValues[index - 16] == value)
                return index;
        }
    }

    // If we are at the maximum immediate count, then reuse an existing.
    // This avoids allocating too many registers to immediates.
    if (m_immCount >= 4) {
        for (index = 16; index < 32; ++index) {
            if (m_immRegs & (1 << index)) {
                m_immValues[index - 16] = value;
                immreg(Insn::LDI, index, value);
                return index;
            }
        }
    }

    // Find a free high register that isn't already used as an immediate.
    // Start from the end of the register pool so as to avoid clashes
    // with normal register allocation from the start of the register pool.
    for (index = 31; index >= 16; --index) {
        if (std::find(m_regOrder.begin(), m_regOrder.end(),
                      (unsigned char)index) == m_regOrder.end())
            continue; // Not an allocatable register.
        if (!(m_allocated & (1 << index)) && !(m_immRegs & (1 << index))) {
            m_immRegs |= (1 << index);
            m_immValues[index - 16] = value;
            immreg(Insn::LDI, index, value);
            return index;
        }
    }

    // Try finding any high register, reusing immediates if we have to.
    unsigned char reg = allocateSpare(true);
    if (reg == 0)
        throw std::overflow_error("too many registers in use");
    m_allocated &= ~(1 << reg); // Not really allocated.
    m_immRegs |= (1 << reg);
    m_immValues[reg - 16] = value;
    immreg(Insn::LDI, reg, value);
    return reg;
}

void Code::add_ptr(unsigned char reg, int offset)
{
    if (offset == 0) {
        return;
    } else if (offset > 0 && offset <= 63 && hasFlag(MoveWord)) {
        immreg(Insn::ADIW, reg, (unsigned char)offset);
    } else if (offset < 0 && offset >= -63 && hasFlag(MoveWord)) {
        immreg(Insn::SBIW, reg, (unsigned char)(-offset));
    } else {
        offset = -offset;
        unsigned char low = (unsigned char)offset;
        unsigned char high = (unsigned char)(offset >> 8);
        if (low != 0) {
            immreg(Insn::SUBI, reg, low);
            if (high != 0)
                immreg(Insn::SBCI, reg + 1, high);
            else
                tworeg(Insn::SBC, reg + 1, ZERO_REG);
        } else {
            immreg(Insn::SUBI, reg + 1, high);
        }
    }
}

/**
 * \brief Loads or stores a register to a memory offset relative to X, Y, or Z.
 *
 * \param reg The register to store.
 * \param type The type of memory instruction, LD_X, LD_Y, LD_Z,
 * ST_X, ST_Y, or ST_Z.
 * \param offset An offset between 0 and 63, PRE_DEC, or POST_INC.
 *
 * \sa ld_st_long()
 */
void Code::ld_st(const Reg &reg, Insn::Type type, unsigned char offset)
{
    if (offset == PRE_DEC) {
        // Decrement the pointer and load/store from last register down.
        for (int index = reg.size() - 1; index >= 0; --index)
            memory(type, reg.reg(index), PRE_DEC);
    } else if (offset == POST_INC) {
        // Increment the pointer and load/store from first register up.
        for (int index = 0; index < reg.size(); ++index)
            memory(type, reg.reg(index), POST_INC);
    } else {
        // Access an arbitrary offset relative to X, Y, or Z.
        ld_st_long(reg, type, offset);
    }
}

/**
 * \brief Loads or stores a register to a memory offset relative to X, Y, or Z.
 *
 * \param reg The register to load or store.
 * \param type The type of memory instruction, LD_X, LD_Y, LD_Z,
 * ST_X, ST_Y, or ST_Z.
 * \param offset An offset between 0 and 65355.
 *
 * This function is able to address data that is further away from
 * the base of the pointer than simple offsets 0 to 63.
 *
 * \sa ld_st()
 */
void Code::ld_st_long(const Reg &reg, Insn::Type type, unsigned offset)
{
    if (reg.size() == 0) {
        // Nothing to do to load/store an empty register.
    } else if (type == Insn::LD_X && (offset != 0 || reg.size() > 1)) {
        // X pointer does not support non-zero offsets so we need
        // to add the offset to X, perform the store, and then
        // subtract the offset from X.
        add_ptr(26, offset);
        for (int index = 0; index < reg.size() - 1; ++index)
            memory(type, reg.reg(index), POST_INC);
        memory(type, reg.reg(reg.size() - 1), 0);
        add_ptr(26, -(offset + reg.size() - 1));
    } else if ((((int)offset) + reg.size()) <= 64) {
        // Store direct to the pointer register with an offset < 64.
        for (int index = 0; index < reg.size(); ++index)
            memory(type, reg.reg(index), offset + index);
    } else {
        // Too far away, so adjust the Y or Z pointer before/after accessing.
        if (type == Insn::LD_Y || type == Insn::ST_Y)
            add_ptr(28, offset);
        else
            add_ptr(30, offset);
        for (int index = 0; index < reg.size() - 1; ++index)
            memory(type, reg.reg(index), POST_INC);
        memory(type, reg.reg(reg.size() - 1), 0);
        if (type == Insn::LD_Y || type == Insn::ST_Y)
            add_ptr(28, -(offset + reg.size() - 1));
        else
            add_ptr(30, -(offset + reg.size() - 1));
    }
}

/**
 * \brief XOR's a register and a memory offset relative to X, Y, or Z.
 *
 * \param reg The register to XOR.
 * \param type The type of memory instruction, LD_Y or LD_Z.
 * \param offset An offset between 0 and 65355.
 *
 * This function is handy when XOR'ing against a key schedule word.
 */
void Code::ld_xor(const Reg &reg, Insn::Type type, unsigned offset)
{
    if (reg.size() == 0) {
        // Nothing to do to XOR an empty register.
    } else if ((((int)offset) + reg.size()) <= 64) {
        // Load direct from the pointer and XOR with the register.
        for (int index = 0; index < reg.size(); ++index) {
            memory(type, TEMP_REG, offset + index);
            tworeg(Insn::EOR, reg.reg(index), TEMP_REG);
        }
    } else {
        // Too far away, so adjust the Y or Z pointer before/after accessing.
        if (type == Insn::LD_Y)
            add_ptr(28, offset);
        else
            add_ptr(30, offset);
        for (int index = 0; index < reg.size() - 1; ++index) {
            memory(type, TEMP_REG, POST_INC);
            tworeg(Insn::EOR, reg.reg(index), TEMP_REG);
        }
        memory(type, TEMP_REG, 0);
        tworeg(Insn::EOR, reg.reg(reg.size() - 1), TEMP_REG);
        if (type == Insn::LD_Y)
            add_ptr(28, -(offset + reg.size() - 1));
        else
            add_ptr(30, -(offset + reg.size() - 1));
    }
}
