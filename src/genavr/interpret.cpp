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

// This file provides a simple interpreter for AVR instructions that
// supports testing of generated code on a desktop machine.  It isn't
// particularly fast or even a complete AVR simulation.

#include "code.h"
#include <stdexcept>
#include <cstring>
#include <iostream>

#define MEM_SIZE 4096

struct AVRState
{
    unsigned char r[34]; // r0 .. r31 plus stack low and stack high.
    unsigned char c;
    unsigned char z;
    unsigned char t;
    unsigned char memory[MEM_SIZE];
    unsigned used;
    int pc;
    Sbox sbox;

    AVRState()
    {
        memset(r, 0x55, sizeof(r));
        r[1] = 0x00; // Register that must be zero.
        c = 0;
        z = 0;
        t = 0;
        memset(memory, 0xAA, sizeof(memory));
        used = 0x01F2; // First address to allocate via alloc_buffer().
        pc = 0;
        setPair(32, MEM_SIZE); // Initial stack pointer.
    }

    unsigned pair(int reg) const
    {
        return ((unsigned)(r[reg + 1])) * 256U + r[reg];
    }

    void setPair(int reg, unsigned value)
    {
        r[reg]     = (unsigned char)value;
        r[reg + 1] = (unsigned char)(value >> 8);
    }

    unsigned char *ptr(int reg, unsigned char offset);
    unsigned char *ptr_x(unsigned char offset) { return ptr(26, offset); }
    unsigned char *ptr_y(unsigned char offset) { return ptr(28, offset); }
    unsigned char *ptr_z(unsigned char offset) { return ptr(30, offset); }
    unsigned char *ptr_sp(unsigned char offset) { return ptr(32, offset); }

    unsigned alloc_buffer(unsigned len);
    unsigned alloc_buffer(const void *data, unsigned len);

    void push16(unsigned value)
    {
        *ptr_sp(PRE_DEC) = (unsigned char)(value >> 8);
        *ptr_sp(PRE_DEC) = (unsigned char)value;
    }
};

unsigned char *AVRState::ptr(int reg, unsigned char offset)
{
    int address = (((int)(r[reg + 1])) << 8) | r[reg];
    if (offset == PRE_DEC) {
        --address;
        r[reg]     = (unsigned char)address;
        r[reg + 1] = (unsigned char)(address >> 8);
    } else if (offset == POST_INC) {
        r[reg]     = (unsigned char)(address + 1);
        r[reg + 1] = (unsigned char)((address + 1) >> 8);
    } else {
        address += offset;
    }
    if (address < 0 || address >= MEM_SIZE) {
        throw std::invalid_argument("invalid memory address");
    }
    return &(memory[address]);
}


// Allocate space for a memory buffer in RAM.
unsigned AVRState::alloc_buffer(unsigned len)
{
    unsigned result = used;
    used += len;
    return result;
}

// Allocate space for a memory buffer in RAM and populate it.
unsigned AVRState::alloc_buffer(const void *data, unsigned len)
{
    unsigned result = alloc_buffer(len);
    memcpy(&(memory[result]), data, len);
    return result;
}

// Executes a single instruction.
static void exec_insn(AVRState &s, const Code &code, const Insn &insn)
{
    static char const hex[] = "0123456789abcdef";
    unsigned temp;
    switch (insn.type()) {
    case Insn::ADC:
        // Add with carry in.
        temp = s.r[insn.reg1()];
        temp += s.c;
        temp += s.r[insn.reg2()];
        s.r[insn.reg1()] = (unsigned char)temp;
        s.c = (temp >= 0x0100);
        s.z = ((temp & 0xFF) == 0x00);
        break;
    case Insn::ADD:
        // Add with no carry in.
        temp = s.r[insn.reg1()];
        temp += s.r[insn.reg2()];
        s.r[insn.reg1()] = (unsigned char)temp;
        s.c = (temp >= 0x0100);
        s.z = ((temp & 0xFF) == 0x00);
        break;
    case Insn::ADIW:
        // Add immediate to word.
        temp = s.pair(insn.reg1());
        temp += insn.value();
        s.setPair(insn.reg1(), temp);
        s.c = (temp >= 0x10000);
        s.z = ((temp & 0xFFFF) == 0x0000);
        break;
    case Insn::AND:
        // AND registers.
        s.r[insn.reg1()] &= s.r[insn.reg2()];
        s.z = (s.r[insn.reg1()] == 0x00);
        break;
    case Insn::ANDI:
        // AND with immediate.
        s.r[insn.reg1()] &= insn.value();
        s.z = (s.r[insn.reg1()] == 0x00);
        break;
    case Insn::ASR:
        // Arithmetic shift right.
        temp = s.r[insn.reg1()];
        s.c = (temp & 0x01);
        temp = (temp >> 1) | (temp & 0x80);
        s.z = (temp == 0x00);
        s.r[insn.reg1()] = (unsigned char)temp;
        break;
    case Insn::BLD: {
        // Loads the contents of T into a register bit.
        unsigned char bit = (1 << insn.value());
        unsigned char t = (s.t ? bit : 0);
        s.r[insn.reg1()] = (s.r[insn.reg1()] & ~bit) | t;
        break; }
    case Insn::BST: {
        // Stores the contents of a register bit into T.
        unsigned char bit = (1 << insn.value());
        s.t = ((s.r[insn.reg1()] & bit) != 0);
        break; }
    case Insn::BRCC:
        // Branch if carry clear.
        if (!s.c)
            s.pc = code.getLabel(insn.label());
        break;
    case Insn::BRCS:
        // Branch if carry set.
        if (s.c)
            s.pc = code.getLabel(insn.label());
        break;
    case Insn::BREQ:
        // Branch if equal / zero.
        if (s.z)
            s.pc = code.getLabel(insn.label());
        break;
    case Insn::BRNE:
        // Branch if not equal.
        if (!s.z)
            s.pc = code.getLabel(insn.label());
        break;
    case Insn::CALL:
        // Call a local subroutine.
        s.push16(s.pc);
        s.pc = code.getLabel(insn.label());
        break;
    case Insn::COM:
        // NOT a register.
        s.r[insn.reg1()] ^= 0xFF;
        s.z = (s.r[insn.reg1()] == 0x00);
        break;
    case Insn::CP: {
        // Compare without carry in.
        int cmp = ((int)(s.r[insn.reg1()])) - s.r[insn.reg2()];
        s.c = (cmp < 0);
        s.z = (cmp == 0);
        break; }
    case Insn::CPC: {
        // Compare with carry in.
        int cmp = ((int)(s.r[insn.reg1()])) - s.r[insn.reg2()] - s.c;
        s.c = (cmp < 0);
        s.z = (cmp == 0);
        break; }
    case Insn::CPI: {
        // Compare with immediate.
        int cmp = ((int)(s.r[insn.reg1()])) - insn.value();
        s.c = (cmp < 0);
        s.z = (cmp == 0);
        break; }
    case Insn::CPSE:
        // Compare and skip if equal.
        if (s.r[insn.reg1()] == s.r[insn.reg2()])
            ++(s.pc);
        break;
    case Insn::DEC:
        // Decrement a register.
        temp = (s.r[insn.reg1()] - 1) & 0xFF;
        s.r[insn.reg1()] = (unsigned char)temp;
        s.z = (temp == 0x00);
        break;
    case Insn::EOR:
        // EOR registers.
        s.r[insn.reg1()] ^= s.r[insn.reg2()];
        s.z = (s.r[insn.reg1()] == 0x00);
        break;
    case Insn::INC:
        // Increment a register.
        temp = (s.r[insn.reg1()] + 1) & 0xFF;
        s.r[insn.reg1()] = (unsigned char)temp;
        s.z = (temp == 0x00);
        break;
    case Insn::JMP:
        // Unconditional jump to a label.
        s.pc = code.getLabel(insn.label());
        break;
    case Insn::LABEL:
        // Label - nothing to do.
        break;
    case Insn::LD_X:
        // Load from an X pointer offset.
        s.r[insn.reg1()] = *s.ptr_x(insn.offset());
        break;
    case Insn::LD_Y:
        // Load from a Y pointer offset.
        s.r[insn.reg1()] = *s.ptr_y(insn.offset());
        break;
    case Insn::LD_Z:
        // Load from a Z pointer offset.
        s.r[insn.reg1()] = *s.ptr_z(insn.offset());
        break;
    case Insn::LDI:
        // Load immediate into register.
        s.r[insn.reg1()] = insn.value();
        break;
    case Insn::LPM_SBOX:
        // Load a value from an S-box table in program memory.
        s.r[insn.reg1()] = s.sbox.lookup(s.r[insn.reg2()]);
        break;
    case Insn::LPM_SETUP:
        // Set up the S-box.
        s.sbox = code.sbox_get(insn.value());

        // Destroy the Z register.  Normally this will point to the
        // S-box in program memory but we don't do it that way here.
        s.setPair(30, 0xBEEF);

        // Push a fake RAMPZ value on the stack to check for stacking
        // errors later when we do the cleanup.
        *s.ptr_sp(PRE_DEC) = 0xBA;
        break;
    case Insn::LPM_SWITCH:
        // Switch to a different S-box.
        s.sbox = code.sbox_get(insn.value());
        break;
    case Insn::LPM_CLEAN:
        // Pop the RAMPZ value, which we expect to be 0xBA.
        temp = *s.ptr_sp(POST_INC);
        if (temp != 0xBA)
            throw std::invalid_argument("RAMPZ stacking error");
        break;
    case Insn::LSL:
        // Logical shift left.
        temp = s.r[insn.reg1()];
        s.c = ((temp & 0x80) != 0);
        temp = temp << 1;
        s.z = ((temp & 0xFF) == 0x00);
        s.r[insn.reg1()] = (unsigned char)temp;
        break;
    case Insn::LSR:
        // Logical shift right.
        temp = s.r[insn.reg1()];
        s.c = (temp & 0x01);
        temp = temp >> 1;
        s.z = ((temp & 0xFF) == 0x00);
        s.r[insn.reg1()] = (unsigned char)temp;
        break;
    case Insn::MOV:
        // Move the contents of a register.
        s.r[insn.reg1()] = s.r[insn.reg2()];
        break;
    case Insn::MOVW:
        // Move the contents of a register pair.
        s.r[insn.reg1()]     = s.r[insn.reg2()];
        s.r[insn.reg1() + 1] = s.r[insn.reg2() + 1];
        break;
    case Insn::NEG:
        // Negate a register.
        temp = s.r[insn.reg1()];
        s.c = (temp != 0x00);
        temp = -temp;
        s.r[insn.reg1()] = (unsigned char)temp;
        s.z = ((temp & 0xFF) == 0x00);
        break;
    case Insn::NOP:
        // No operation - nothing to do.
        break;
    case Insn::OR:
        // OR registers.
        s.r[insn.reg1()] |= s.r[insn.reg2()];
        s.z = (s.r[insn.reg1()] == 0x00);
        break;
    case Insn::ORI:
        // OR with immediate.
        s.r[insn.reg1()] |= insn.value();
        s.z = (s.r[insn.reg1()] == 0x00);
        break;
    case Insn::POP:
        // Pop from the stack.
        s.r[insn.reg1()] = *s.ptr_sp(POST_INC);
        break;
    case Insn::PUSH:
        // Push onto the stack.
        *s.ptr_sp(PRE_DEC) = s.r[insn.reg1()];
        break;
    case Insn::PRINT:
        // Print a register as a hex byte.
        temp = s.r[insn.reg1()];
        std::cout << hex[(temp >> 4) & 0x0F];
        std::cout << hex[temp & 0x0F];
        std::cout << ' ';
        break;
    case Insn::PRINTCH:
        // Print a single character.
        std::cout << (char)(insn.value());
        break;
    case Insn::PRINTLN:
        // Print an end of line sequence.
        std::cout << std::endl;
        break;
    case Insn::RET:
        // Return from a subroutine.
        s.pc = *s.ptr_sp(POST_INC);
        s.pc |= ((int)(*s.ptr_sp(POST_INC))) << 8;
        break;
    case Insn::ROL:
        // Bitwise rotate left.
        temp = (((unsigned)(s.r[insn.reg1()])) << 1) | s.c;
        s.c = ((temp & 0xFF00) != 0);
        s.z = ((temp & 0x00FF) == 0);
        s.r[insn.reg1()] = (unsigned char)temp;
        break;
    case Insn::ROR:
        // Bitwise rotate right.
        temp = (s.r[insn.reg1()] >> 1) | (s.c << 7);
        s.c = ((s.r[insn.reg1()] & 0x01) != 0);
        s.z = ((temp & 0x00FF) == 0);
        s.r[insn.reg1()] = (unsigned char)temp;
        break;
    case Insn::SBC: {
        // Subtract registers with carry.
        int result = ((int)(s.r[insn.reg1()])) - s.r[insn.reg2()] - s.c;
        s.c = (result < 0);
        s.z = (result == 0);
        s.r[insn.reg1()] = (unsigned char)result;
        break; }
    case Insn::SUB: {
        // Subtract registers.
        int result = ((int)(s.r[insn.reg1()])) - s.r[insn.reg2()];
        s.c = (result < 0);
        s.z = (result == 0);
        s.r[insn.reg1()] = (unsigned char)result;
        break; }
    case Insn::SBCI: {
        // Subtract immediate with carry.
        int result = ((int)(s.r[insn.reg1()])) - insn.value() - s.c;
        s.c = (result < 0);
        s.z = (result == 0);
        s.r[insn.reg1()] = (unsigned char)result;
        break; }
    case Insn::SUBI: {
        // Subtract immediate.
        int result = ((int)(s.r[insn.reg1()])) - insn.value();
        s.c = (result < 0);
        s.z = (result == 0);
        s.r[insn.reg1()] = (unsigned char)result;
        break; }
    case Insn::SBIW:
        // Subtract immediate from word.
        temp = s.pair(insn.reg1()) - insn.value();
        s.c = ((temp & ~0xFFFF) != 0);
        s.z = ((temp & 0xFFFF) == 0);
        s.setPair(insn.reg1(), temp);
        break;
    case Insn::ST_X:
        // Store to an X pointer offset.
        *s.ptr_x(insn.offset()) = s.r[insn.reg1()];
        break;
    case Insn::ST_Y:
        // Store to a Y pointer offset.
        *s.ptr_y(insn.offset()) = s.r[insn.reg1()];
        break;
    case Insn::ST_Z:
        // Store to a Z pointer offset.
        *s.ptr_z(insn.offset()) = s.r[insn.reg1()];
        break;
    case Insn::SWAP:
        // Swap the nibbles in a register.
        temp = s.r[insn.reg1()];
        temp = ((temp << 4) & 0xF0) | ((temp >> 4) & 0x0F);
        s.r[insn.reg1()] = (unsigned char)temp;
        break;
    }
}

/**
 * \brief Executes the code in this object as a key setup function.
 *
 * \param schedule Points to the output buffer for the schedule.
 * \param schedule_len Length of the schedule output buffer.
 * \param key Points to the input buffer for the key.
 * \param key_len Length of the key input buffer.
 */
void Code::exec_setup_key(void *schedule, unsigned schedule_len,
                          const void *key, unsigned key_len)
{
    AVRState s;
    unsigned schedule_address = s.alloc_buffer(schedule_len);
    unsigned key_address = s.alloc_buffer(key, key_len);
    s.setPair(30, schedule_address);    // Z = schedule
    s.setPair(26, key_address);         // X = key
    s.push16(0xFFFF);                   // return address
    unsigned fp = s.pair(32) - m_localsSize;
    s.setPair(28, fp);                  // Y = frame pointer
    s.setPair(32, fp);
    while (s.pc != (int)m_insns.size()) {
        if (s.pc < 0 || s.pc > (int)m_insns.size())
            throw std::invalid_argument("program counter out of range");
        Insn insn = m_insns[(s.pc)++];
        exec_insn(s, *this, insn);
    }
    if (s.r[1] != 0x00 && !hasFlag(TempR1))
        throw std::invalid_argument("r1 is non-zero at the end of the code");
    if (s.pair(32) != fp)
        throw std::invalid_argument("stack size is incorrect on code exit");
    memcpy(schedule, &(s.memory[schedule_address]), schedule_len);
}

/**
 * \brief Executes the code in this object as a block encrypt function.
 *
 * \param key Points to the buffer for the key (or key schedule).
 * \param key_len Length of the key buffer.
 * \param output Points to the buffer for the output block.
 * \param output_len Length of the output block buffer.
 * \param input Points to the buffer for the input block.
 * \param input_len Length of the input block buffer.
 * \param tweak Tweak value for tweakable block ciphers.
 */
void Code::exec_encrypt_block(const void *key, unsigned key_len,
                              void *output, unsigned output_len,
                              const void *input, unsigned input_len,
                              unsigned tweak)
{
    AVRState s;
    unsigned key_address = s.alloc_buffer(key, key_len);
    unsigned output_address = s.alloc_buffer(output_len);
    unsigned input_address = s.alloc_buffer(input, input_len);
    s.setPair(26, input_address);   // X = input
    s.setPair(30, key_address);     // Z = key
    s.push16(0xFFFF);               // return address
    s.push16(output_address);       // output address in a local variable
    unsigned fp = s.pair(32) - m_localsSize;
    s.setPair(28, fp);              // Y = frame pointer
    s.setPair(32, fp);
    s.setPair(18, tweak);
    while (s.pc != (int)m_insns.size()) {
        if (s.pc < 0 || s.pc > (int)m_insns.size())
            throw std::invalid_argument("program counter out of range");
        Insn insn = m_insns[(s.pc)++];
        exec_insn(s, *this, insn);
    }
    if (s.r[1] != 0x00 && !hasFlag(TempR1))
        throw std::invalid_argument("r1 is non-zero at the end of the code");
    if (s.pair(32) != fp)
        throw std::invalid_argument("stack size is incorrect on code exit");
    memcpy(output, &(s.memory[output_address]), output_len);
}

/**
 * \brief Executes the code in this object as a permutation function.
 *
 * \param state Points to the buffer containing the state on input and output.
 * \param state_len Length of the state buffer.
 * \param count Count parameter for the number of rounds to perform.
 */
void Code::exec_permutation
    (void *state, unsigned state_len, unsigned char count)
{
    AVRState s;
    unsigned state_address = s.alloc_buffer(state, state_len);
    s.setPair(30, state_address);   // Z = state
    s.push16(0xFFFF);               // return address
    unsigned fp = s.pair(32) - m_localsSize;
    s.setPair(28, fp);              // Y = frame pointer
    s.setPair(32, fp);
    s.setPair(22, count);           // Pass the count parameter in r22:r23
    while (s.pc != (int)m_insns.size()) {
        if (s.pc < 0 || s.pc > (int)m_insns.size())
            throw std::invalid_argument("program counter out of range");
        Insn insn = m_insns[(s.pc)++];
        exec_insn(s, *this, insn);
    }
    if (s.r[1] != 0x00 && !hasFlag(TempR1))
        throw std::invalid_argument("r1 is non-zero at the end of the code");
    if (s.pair(32) != fp)
        throw std::invalid_argument("stack size is incorrect on code exit");
    memcpy(state, &(s.memory[state_address]), state_len);
}

/**
 * \brief Executes the code in this object as a TinyJAMBI keyed permutation.
 *
 * \param state Points to the buffer containing the state on input and output.
 * \param state_len Length of the state buffer.
 * \param key Points to the buffer containing the key on input.
 * \param key_len Length of the key in bytes.
 * \param rounds Number of rounds to perform; e.g. 1024.
 */
void Code::exec_tinyjambu
    (void *state, unsigned state_len, const void *key,
     unsigned key_len, unsigned rounds)
{
    AVRState s;
    unsigned state_address = s.alloc_buffer(state, state_len);
    unsigned key_address = s.alloc_buffer(key, key_len);
    s.setPair(26, state_address);   // X = state
    s.setPair(30, key_address);     // Z = key
    s.setPair(20, key_len / 4);     // key_words
    s.setPair(18, rounds / 128);    // TINYJAMBU_ROUNDS(rounds)
    s.push16(0xFFFF);               // return address
    unsigned fp = s.pair(32) - m_localsSize;
    s.setPair(28, fp);              // Y = frame pointer
    s.setPair(32, fp);
    while (s.pc != (int)m_insns.size()) {
        if (s.pc < 0 || s.pc > (int)m_insns.size())
            throw std::invalid_argument("program counter out of range");
        Insn insn = m_insns[(s.pc)++];
        exec_insn(s, *this, insn);
    }
    if (s.r[1] != 0x00 && !hasFlag(TempR1))
        throw std::invalid_argument("r1 is non-zero at the end of the code");
    if (s.pair(32) != fp)
        throw std::invalid_argument("stack size is incorrect on code exit");
    memcpy(state, &(s.memory[state_address]), state_len);
}
