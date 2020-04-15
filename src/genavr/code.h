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

#ifndef GENAVR_CODE_H
#define GENAVR_CODE_H

#include <vector>
#include <string>
#include <ostream>

class Code;

/**
 * \brief Holds information about a single AVR instruction.
 */
class Insn
{
public:
    enum Type
    {
        ADC,        /**< Add with carry */
        ADD,        /**< Add without carry */
        ADIW,       /**< Add immediate to word register pair (r24/26/28/30) */
        AND,        /**< Logical AND */
        ANDI,       /**< Logical AND with immediate (high reg only) */
        ASR,        /**< Arithmetic shift right */
        BLD,        /**< Bit load from T into a register */
        BST,        /**< Bit store from a register into T */
        BRCC,       /**< Conditional branch if carry clear */
        BRCS,       /**< Conditional branch if carry set */
        BREQ,       /**< Conditional branch if equal */
        BRNE,       /**< Conditional branch if not equal */
        CALL,       /**< Call a subroutine */
        COM,        /**< One's complement of a register (logical NOT) */
        CP,         /**< Compare two registers */
        CPC,        /**< Compare two registers with carry */
        CPI,        /**< Compare register with immediate (high reg only) */
        CPSE,       /**< Compare and skip if equal (usually followed by JMP) */
        DEC,        /**< Decrement */
        EOR,        /**< Exclusive-OR */
        INC,        /**< Increment */
        JMP,        /**< Unconditional jump */
        LABEL,      /**< Outputs a branch label at this point */
        LD_X,       /**< Load indirect using X pointer (no offsets allowed) */
        LD_Y,       /**< Load indirect using Y pointer (0-63 offset allowed) */
        LD_Z,       /**< Load indirect using Z pointer (0-63 offset allowed) */
        LDI,        /**< Load immediate into register (high reg only) */
        LPM,        /**< Load from a table in program memory */
        LPM_SBOX,   /**< Load from a table in program memory with an index */
        LPM_SETUP,  /**< Set up to perform sbox lookups using "lpm" */
        LPM_CLEAN,  /**< Clean up after sbox lookups using "lpm" */
        LSL,        /**< Logical shift left */
        LSR,        /**< Logical shift right */
        MOV,        /**< Move register */
        MOVW,       /**< Move register pair */
        NEG,        /**< Negate */
        NOP,        /**< No operation */
        OR,         /**< Logical OR */
        ORI,        /**< Logical OR with immediate (high reg only) */
        POP,        /**< Pop register from stack */
        PUSH,       /**< Push register onto stack */
        PRINT,      /**< Print a hex byte for diagnostic purposes */
        PRINTCH,    /**< Print a character for diagnostic purposes */
        PRINTLN,    /**< Print an end of line for diagnostic purposes */
        RET,        /**< Return from subroutine */
        ROL,        /**< Rotate left through carry */
        ROR,        /**< Rotate right through carry */
        SBC,        /**< Subtract with carry */
        SUB,        /**< Subtract without carry */
        SBCI,       /**< Subtract immediate with carry (high reg only) */
        SUBI,       /**< Subtract immediate without carry (high reg only) */
        SBIW,       /**< Subtract immediate from register pair (r24/26/28/30) */
        ST_X,       /**< Store indirect using X pointer (no offsets allowed) */
        ST_Y,       /**< Store indirect using Y pointer (0-63 offset allowed) */
        ST_Z,       /**< Store indirect using Z pointer (0-63 offset allowed) */
        SWAP        /**< Swap nibbles */
    };

    Insn() : m_type(NOP), m_reg1(0), m_reg2(0) {}
    Insn(const Insn &insn)
        : m_type(insn.m_type), m_reg1(insn.m_reg1), m_reg2(insn.m_reg2) {}
    ~Insn() {}

    Insn &operator=(const Insn &insn)
    {
        m_type = insn.m_type;
        m_reg1 = insn.m_reg1;
        m_reg2 = insn.m_reg2;
        return *this;
    }

    Type type() const { return m_type; }
    unsigned char reg1() const { return m_reg1; }
    unsigned char reg2() const { return m_reg2; }
    unsigned char value() const { return m_reg2; }
    unsigned char label() const { return m_reg1; }
    unsigned char offset() const { return m_reg2; }

    // Note: The functions below may throw an exception if the arguments
    // are inconsistent with the instruction type; e.g. using a low register
    // with an instruction that only accepts high registers.

    /**
     * \brief Constructs a bare instruction with no arguments.
     *
     * \param type Type of instruction.
     *
     * \return The instruction.
     */
    static Insn bare(Type type);

    /**
     * \brief Cosntructs an instruction with a single register argument.
     *
     * \param type Type of instruction.
     * \param reg The register to operate on.
     *
     * \return The instruction.
     */
    static Insn reg1(Type type, unsigned char reg);

    /**
     * \brief Cosntructs an instruction with two register arguments.
     *
     * \param type Type of instruction.
     * \param reg1 First register to operate on.
     * \param reg2 Second register to operate on.
     *
     * \return The instruction.
     */
    static Insn reg2(Type type, unsigned char reg1, unsigned char reg2);

    /**
     * \brief Cosntructs an instruction with register and immediate arguments.
     *
     * \param type Type of instruction.
     * \param reg The register to operate on.
     * \param value The immediate value to use.
     *
     * \return The instruction.
     */
    static Insn imm(Type type, unsigned reg, unsigned char value);

    /**
     * \brief Constructs a branch instruction.
     *
     * \param type Type of instruction.
     * \param ref Reference number of the label to branch to.
     *
     * \return The instruction.
     */
    static Insn branch(Type type, unsigned char ref);

    /**
     * \brief Constructs a label instruction.
     *
     * \param ref Reference number of the label.
     *
     * This isn't a real instruction.  Instead it outputs a location in
     * the code where branches can jump to.
     */
    static Insn label(unsigned char ref);

    #define PRE_DEC 0xFE    /**< Pre-decrement during memory operation */
    #define POST_INC 0xFF   /**< Post-increment during memory operation */

    /**
     * \brief Constructs a memory LD or ST instruction.
     *
     * \param type Type of instruction.
     * \param reg The register to operate on.
     * \param offset Offset for the memory operation, which may be one of
     * the special values PRE_DEC or POST_INC.
     *
     * \return The instruction.
     */
    static Insn memory(Type type, unsigned char reg, unsigned char offset);

    /**
     * \brief Writes an instruction to an output stream.
     *
     * \param ostream The output stream to write to.
     * \param code The code block that contains this instruction.
     * \param offset The offset into the code block of this instruction.
     */
    void write(std::ostream &ostream, const Code &code, int offset) const;

private:
    Type m_type;
    unsigned char m_reg1;
    unsigned char m_reg2;

    Insn(Type type, unsigned char reg1, unsigned char reg2)
        : m_type(type), m_reg1(reg1), m_reg2(reg2) {}
};

/**
 * \brief Representation of a multi-byte register.
 */
class Reg
{
public:
    Reg() {}
    Reg(const Reg &other) : m_regs(other.m_regs) {}
    Reg(const Reg &other, unsigned char offset, unsigned char count = 0);
    ~Reg() {}

    Reg &operator=(const Reg &other)
    {
        m_regs = other.m_regs;
        return *this;
    }

    /**
     * \brief Gets the number of low-level byte registers in this register.
     *
     * \param The number of bytes.
     */
    int size() const { return m_regs.size(); }

    /**
     * \brief Gets the low-level byte register at a specific index.
     *
     * \param index The index between 0 and size() - 1.
     *
     * \return The register number at \a index.
     */
    unsigned char reg(int index) const { return m_regs[index]; }

    /**
     * \brief Gets a byte-reversed version of this register.
     *
     * \return The byte-reversed version of this register.
     *
     * This can be used to modify whether the register's value is interpreted
     * as little-endian or big-endian.  The default is little-endian.
     */
    Reg reversed() const;

    /**
     * \brief Shuffles the bytes in this register.
     *
     * \param pattern Pattern to shuffle with.  Byte 0 of the output comes
     * from offset 0 of \a pattern; byte 1 of the output comes from offset a
     * of \pattern; and so on.
     *
     * \return The shuffled version of this register.
     */
    Reg shuffle(const unsigned char *pattern) const;

    /**
     * \brief Shuffles the bytes in a 32-bit register.
     *
     * \param offset0 Offset of the byte in this register that becomes
     * byte 0 in the shuffled result.
     * \param offset1 Offset of the byte in this register that becomes
     * byte 1 in the shuffled result.
     * \param offset2 Offset of the byte in this register that becomes
     * byte 2 in the shuffled result.
     * \param offset3 Offset of the byte in this register that becomes
     * byte 3 in the shuffled result.
     *
     * \return The shuffled version of this register.
     */
    Reg shuffle(unsigned char offset0, unsigned char offset1,
                unsigned char offset2, unsigned char offset3);

    /**
     * \brief Shuffles the bytes in a 64-bit register.
     *
     * \param offset0 Offset of the byte in this register that becomes
     * byte 0 in the shuffled result.
     * \param offset1 Offset of the byte in this register that becomes
     * byte 1 in the shuffled result.
     * \param offset2 Offset of the byte in this register that becomes
     * byte 2 in the shuffled result.
     * \param offset3 Offset of the byte in this register that becomes
     * byte 3 in the shuffled result.
     * \param offset4 Offset of the byte in this register that becomes
     * byte 4 in the shuffled result.
     * \param offset5 Offset of the byte in this register that becomes
     * byte 5 in the shuffled result.
     * \param offset6 Offset of the byte in this register that becomes
     * byte 6 in the shuffled result.
     * \param offset7 Offset of the byte in this register that becomes
     * byte 7 in the shuffled result.
     *
     * \return The shuffled version of this register.
     */
    Reg shuffle(unsigned char offset0, unsigned char offset1,
                unsigned char offset2, unsigned char offset3,
                unsigned char offset4, unsigned char offset5,
                unsigned char offset6, unsigned char offset7);

    /**
     * \brief Gets a reference to the X pointer.
     *
     * \return A reference to r26 and r27.
     */
    static Reg x_ptr();

    /**
     * \brief Gets a reference to the Y pointer.
     *
     * \return A reference to r28 and r29.
     */
    static Reg y_ptr();

    /**
     * \brief Gets a reference to the Z pointer.
     *
     * \return A reference to r30 and r31.
     */
    static Reg z_ptr();

private:
    std::vector<unsigned char> m_regs;

    friend class Code;
};

#define TEMP_REG 0  /**< AVR register number for the temporary register */
#define ZERO_REG 1  /**< AVR register number for the zero register */

class Code
{
public:
    Code();
    ~Code();

    /**
     * \brief Flags that affect how the code is generated.
     *
     * If the code won't be using "X" or "Z", then the registers can
     * be added to the allocation list for temporaries by specifying
     * the TempX and TempZ flags.
     *
     * If the code won't be using local variables, then TempY can
     * be specified to add "Y" to the list of temporaries as well.
     */
    enum Flag
    {
        MoveWord = 0x0001,      /**< Core supports the "MOVW" instruction */
        TempX    = 0x0002,      /**< X pointer can be used as a temporary */
        TempY    = 0x0004,      /**< Y pointer can be used as a temporary */
        TempZ    = 0x0008,      /**< Z pointer can be used as a temporary */
        Print    = 0x0010,      /**< Use diagnostic printing */
        NoLocals = 0x0020,      /**< No locals and Y will not be touched */
        TempR0   = 0x0040,      /**< "r0" can be used as a temporary */
        TempR1   = 0x0080,      /**< "r1" can be used as a temporary */
    };

    /**
     * \brief Clears all instructions from this object.
     */
    void clear();

    /**
     * \brief Gets the number of instructions in this object.
     *
     * \return The number of instructions in this object.
     */
    int size() const { return m_insns.size(); }

    /**
     * \brief Fetches the instruction at a specific index in this object.
     *
     * \param index The index to fetch.
     *
     * \return The instruction at \a index.
     */
    Insn operator[](int index) { return m_insns[index]; }

    /**
     * \brief Gets the offset of a specific label.
     *
     * \param ref The reference to the label.
     *
     * \return The offset of the label.  Throws an exception if the
     * reference is not valid.
     */
    int getLabel(unsigned char ref) const;

    /**
     * \brief Returns a mask with the list of registers that were used.
     *
     * \return The used registers.
     */
    unsigned usedRegs() const { return m_usedRegs; }

    /**
     * \brief Sets a flag that affects the generated output code.
     *
     * \param flag The flag to set.
     */
    void setFlag(Flag flag) { m_flags |= flag; resetRegs(); }

    /**
     * \brief Clears a flag that affects the generated output code.
     *
     * \param flag The flag to clear.
     */
    void clearFlag(Flag flag) { m_flags &= ~flag; resetRegs(); }

    /**
     * \brief Determine if a flag is set.
     *
     * \param flag The flag to test.
     *
     * \return Returns true if \a flag is set, false if clear.
     */
    bool hasFlag(Flag flag) const { return (m_flags & flag) == flag; }

    Reg allocateReg(unsigned size);
    Reg allocateHighReg(unsigned size);
    Reg allocateOptionalReg(unsigned size);
    void releaseReg(const Reg &reg);

    // Helper functions to add instructions of various types to the code.
    void adc(const Reg &reg1, const Reg &reg2);
    void adc(const Reg &reg1, unsigned long long value) { add(reg1, value, true); }
    void add(const Reg &reg1, const Reg &reg2);
    void add(const Reg &reg1, unsigned long long value, bool carryIn = false);
    void add_ptr_x(int offset) { add_ptr(26, offset); }
    void add_ptr_y(int offset) { add_ptr(28, offset); }
    void add_ptr_z(int offset) { add_ptr(30, offset); }
    void asr(const Reg &reg);
    void bit_get(const Reg &reg, int bit);
    void bit_put(const Reg &reg, int bit);
    void bit_permute(const Reg &reg, const unsigned char *perm, int size, bool inverse = false);
    void brcc(unsigned char &label) { branch(Insn::BRCC, label); }
    void brcs(unsigned char &label) { branch(Insn::BRCS, label); }
    void breq(unsigned char &label) { branch(Insn::BREQ, label); }
    void brne(unsigned char &label) { branch(Insn::BRNE, label); }
    void call(unsigned char &label) { branch(Insn::CALL, label); }
    void clr(const Reg &reg);
    void compare(const Reg& reg1, const Reg& reg2);
    void compare(const Reg& reg1, unsigned long long value);
    void compare_and_loop
        (const Reg& reg1, unsigned long long value, unsigned char &label);
    void compare_and_set
        (const Reg &regout, const Reg& reg1, const Reg& reg2,
         unsigned char set);
    void dec(const Reg &reg) { sub(reg, 1); }
    void inc(const Reg &reg) { add(reg, 1); }
    void jmp(unsigned char &label) { branch(Insn::JMP, label); }
    void label(unsigned char &label) { branch(Insn::LABEL, label); }
    void ldx(const Reg &reg, unsigned char offset) { ld_st(reg, Insn::LD_X, offset); }
    void ldy(const Reg &reg, unsigned char offset) { ld_st(reg, Insn::LD_Y, offset); }
    void ldz(const Reg &reg, unsigned char offset) { ld_st(reg, Insn::LD_Z, offset); }
    void ldx_long(const Reg &reg, unsigned offset) { ld_st_long(reg, Insn::LD_X, offset); }
    void ldy_long(const Reg &reg, unsigned offset) { ld_st_long(reg, Insn::LD_Y, offset); }
    void ldz_long(const Reg &reg, unsigned offset) { ld_st_long(reg, Insn::LD_Z, offset); }
    void ldy_xor(const Reg &reg, unsigned offset) { ld_xor(reg, Insn::LD_Y, offset); }
    void ldz_xor(const Reg &reg, unsigned offset) { ld_xor(reg, Insn::LD_Z, offset); }
#if 0
    void lpm(unsigned char reg) { onereg(Insn::LPM, reg); }
#endif
    void lsl(const Reg &reg, unsigned bits);
    void lsl_bytes(const Reg &reg, unsigned count);
    void lsr(const Reg &reg, unsigned bits);
    void lsr_bytes(const Reg &reg, unsigned count);
    void move(const Reg &reg1, const Reg &reg2, bool zeroFill = false);
    void move(const Reg &reg1, unsigned long long value);
    void moveHighFirst(const Reg &reg1, const Reg &reg2);
    void neg(const Reg &reg);
    void logand(const Reg &reg1, const Reg &reg2);
    void logand(const Reg &reg1, unsigned long long value);
    void logand_not(const Reg &reg1, const Reg &reg2);
    void lognot(const Reg &reg);
    void lognot(const Reg &reg1, const Reg &reg2);
    void logor(const Reg &reg1, const Reg &reg2);
    void logor(const Reg &reg1, unsigned long long value);
    void logor_not(const Reg &reg1, const Reg &reg2);
    void logxor(const Reg &reg1, const Reg &reg2);
    void logxor(const Reg &reg1, unsigned long long value);
    void logxor_not(const Reg &reg1, const Reg &reg2);
    void logxor_and(const Reg &reg1, const Reg &reg2, const Reg &reg3);
    void logxor_or(const Reg &reg1, const Reg &reg2, const Reg &reg3);
    void pop(const Reg &reg);
    void push(const Reg &reg);
    void ret() { bare(Insn::RET); }
    void rol(const Reg &reg, unsigned bits);
    void rol_bytes(const Reg &reg, unsigned count);
    void ror(const Reg &reg, unsigned bits);
    void ror_bytes(const Reg &reg, unsigned count);
    void sbc(const Reg &reg1, const Reg &reg2);
    void sbc(const Reg &reg1, unsigned long long value) { add(reg1, value, true); }
    void sub(const Reg &reg1, const Reg &reg2);
    void sub(const Reg &reg1, unsigned long long value, bool carryIn = false);
    void sub_ptr_x(int offset) { add_ptr_x(-offset); }
    void sub_ptr_y(int offset) { add_ptr_y(-offset); }
    void sub_ptr_z(int offset) { add_ptr_z(-offset); }
    void stx(const Reg &reg, unsigned char offset) { ld_st(reg, Insn::ST_X, offset); }
    void sty(const Reg &reg, unsigned char offset) { ld_st(reg, Insn::ST_Y, offset); }
    void stz(const Reg &reg, unsigned char offset) { ld_st(reg, Insn::ST_Z, offset); }
    void stx_long(const Reg &reg, unsigned offset) { ld_st_long(reg, Insn::ST_X, offset); }
    void sty_long(const Reg &reg, unsigned offset) { ld_st_long(reg, Insn::ST_Y, offset); }
    void stz_long(const Reg &reg, unsigned offset) { ld_st_long(reg, Insn::ST_Z, offset); }
    void swap(const Reg &reg1, const Reg &reg2);

    // Function prologue management.
    void prologue_setup_key(const char *name, unsigned size_locals);
    void prologue_encrypt_block(const char *name, unsigned size_locals);
    void prologue_decrypt_block(const char *name, unsigned size_locals)
        { prologue_encrypt_block(name, size_locals); }
    Reg prologue_encrypt_block_with_tweak(const char *name, unsigned size_locals);
    Reg prologue_decrypt_block_with_tweak(const char *name, unsigned size_locals)
        { return prologue_encrypt_block_with_tweak(name, size_locals); }
    void prologue_permutation(const char *name, unsigned size_locals);
    Reg prologue_permutation_with_count(const char *name, unsigned size_locals);
    void prologue_tinyjambu(const char *name, Reg &key_words, Reg &rounds);
    void load_output_ptr();

    // Execute generated code in the interpreter.
    void exec_setup_key(void *schedule, unsigned schedule_len,
                        const void *key, unsigned key_len);
    void exec_encrypt_block(const void *key, unsigned key_len,
                            void *output, unsigned output_len,
                            const void *input, unsigned input_len,
                            unsigned tweak = 0);
    void exec_decrypt_block(const void *key, unsigned key_len,
                            void *output, unsigned output_len,
                            const void *input, unsigned input_len,
                            unsigned tweak = 0)
        { exec_encrypt_block(key, key_len, output, output_len,
                             input, input_len, tweak); }
    void exec_permutation
        (void *state, unsigned state_len, unsigned char count = 0);
    void exec_tinyjambu
        (void *state, unsigned state_len, const void *key,
         unsigned key_len, unsigned rounds);

    // Speciality instructions for cryptography.
    void double_gf(const Reg &reg, unsigned feedback);

    // Diagnostics for desktop testing.
    void print(const Reg &reg);
    void print(const char *str);
    void println(void);

    // Low-level functions for creating single instructions.  It is better
    // to use the functions above that can deal with higher-level types.
    void bare(Insn::Type type);
    void branch(Insn::Type type, unsigned char &ref);
    void onereg(Insn::Type type, unsigned char reg);
    void tworeg(Insn::Type type, unsigned char reg1, unsigned char reg2);
    void bitop(Insn::Type type, unsigned char reg, unsigned char bit);
    void immreg(Insn::Type type, unsigned char reg, unsigned char value);
    void memory(Insn::Type type, unsigned char reg, unsigned char offset);
    void zeroreg(unsigned char reg, bool sideEffects = true);
    void zeroreg_no_cc(unsigned char reg) { zeroreg(reg, false); }

    /**
     * \brief Writes the code in this object to an output stream.
     *
     * \param ostream The output stream to write to.
     */
    void write(std::ostream &ostream) const;

private:
    enum PrologueType {
        EncryptBlock,
        KeySetup,
        Permutation,
        TinyJAMBU
    };
    std::vector<Insn> m_insns;
    std::vector<int> m_labels;
    std::vector<unsigned char> m_regOrder;
    unsigned m_allocated;
    unsigned m_usedRegs;
    unsigned m_immRegs;
    unsigned m_flags;
    unsigned char m_immValues[16];
    unsigned m_immCount;
    PrologueType m_prologueType;
    unsigned m_localsSize;
    std::string m_name;

    void resetRegs();
    void used(unsigned char reg);
    unsigned char allocateSpare(bool high);
    unsigned char allocateSparePair(bool high);
    Reg allocateRegInternal(unsigned size, bool high, bool optional);
    unsigned char immtemp(unsigned char value);
    unsigned char tempreg();
    bool have_tempreg();
    void add_ptr(unsigned char reg, int offset);
    void ld_st(const Reg &reg, Insn::Type type, unsigned char offset);
    void ld_st_long(const Reg &reg, Insn::Type type, unsigned offset);
    void ld_xor(const Reg &reg, Insn::Type type, unsigned offset);
};

#endif
