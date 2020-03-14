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

static void Insn_write_reg(std::ostream &ostream, unsigned char reg)
{
    static const char * const reg_names[] = {
        "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"
    };
    if (reg >= 32)
        throw std::invalid_argument("invalid register number");
    ostream << reg_names[reg];
}

static void Insn_write_bare(std::ostream &ostream, const char *name)
{
    ostream << "\t";
    ostream << name;
    ostream << " ";
    ostream << std::endl;
}

static void Insn_write_onereg
    (std::ostream &ostream, const char *name, const Insn &insn)
{
    ostream << "\t";
    ostream << name;
    ostream << " ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << std::endl;
}

static void Insn_write_tworeg
    (std::ostream &ostream, const char *name, const Insn &insn)
{
    ostream << "\t";
    ostream << name;
    ostream << " ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",";
    Insn_write_reg(ostream, insn.reg2());
    ostream << std::endl;
}

static void Insn_write_immreg
    (std::ostream &ostream, const char *name, const Insn &insn)
{
    ostream << "\t";
    ostream << name;
    ostream << " ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",";
    ostream << (int)insn.value();
    ostream << std::endl;
}

static void Insn_write_bitop
    (std::ostream &ostream, const char *name, const Insn &insn)
{
    ostream << "\t";
    ostream << name;
    ostream << " ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",";
    ostream << (int)insn.value();
    ostream << std::endl;
}

static void Insn_write_load
    (std::ostream &ostream, const char *ptr_reg, const Insn &insn)
{
    unsigned char offset = insn.offset();
    ostream << "\t";
    if (offset == PRE_DEC) {
        ostream << "ld ";
        Insn_write_reg(ostream, insn.reg1());
        ostream << ",-";
        ostream << ptr_reg;
    } else if (offset == POST_INC) {
        ostream << "ld ";
        Insn_write_reg(ostream, insn.reg1());
        ostream << ",";
        ostream << ptr_reg;
        ostream << "+";
    } else if (offset == 0) {
        ostream << "ld ";
        Insn_write_reg(ostream, insn.reg1());
        ostream << ",";
        ostream << ptr_reg;
    } else {
        ostream << "ldd ";
        Insn_write_reg(ostream, insn.reg1());
        ostream << ",";
        ostream << ptr_reg;
        ostream << "+";
        ostream << (int)offset;
    }
    ostream << std::endl;
}

static void Insn_write_store
    (std::ostream &ostream, const char *ptr_reg, const Insn &insn)
{
    unsigned char offset = insn.offset();
    ostream << "\t";
    if (offset == PRE_DEC) {
        ostream << "st -";
        ostream << ptr_reg;
    } else if (offset == POST_INC) {
        ostream << "st ";
        ostream << ptr_reg;
        ostream << "+";
    } else if (offset == 0) {
        ostream << "st ";
        ostream << ptr_reg;
    } else {
        ostream << "std ";
        ostream << ptr_reg;
        ostream << "+";
        ostream << (int)offset;
    }
    ostream << ",";
    Insn_write_reg(ostream, insn.reg1());
    ostream << std::endl;
}

static void Insn_write_br
    (std::ostream &ostream, const char *name, const char *namerev,
     const Code &code, int offset, const Insn &insn)
{
    // Determine if we need to do a long or short jump as it
    // will modify the instruction sequence that we need to use.
    int target = code.getLabel(insn.label());
    bool forward = true;
    bool long_jump = false;
    if (target > offset) {
        if ((target - (offset + 1)) > 50)
            long_jump = true;
    } else {
        if (((offset + 1) - target) > 50)
            long_jump = true;
        forward = false;
    }
    if (long_jump && insn.type() != Insn::JMP && insn.type() != Insn::CALL) {
        // We need to jump a long way, so output the reverse branch as a
        // skip and then perform an "rjmp" instruction to jump to where
        // we really want to go.  We assume that the function we are assembling
        // is smaller than 4K in size so that "rjmp" can reach any location.
        ostream << "\t";
        ostream << namerev;
        ostream << " ";
        ostream << 5000 + offset;
        ostream << "f";
        ostream << std::endl;

        ostream << "\trjmp ";
        ostream << target;
        if (forward)
            ostream << "f";
        else
            ostream << "b";
        ostream << std::endl;

        ostream << 5000 + offset;
        ostream << ":";
        ostream << std::endl;
    } else {
        ostream << "\t";
        ostream << name;
        ostream << " ";
        ostream << target;
        if (forward)
            ostream << "f";
        else
            ostream << "b";
        ostream << std::endl;
    }
}

static void Insn_write_label(std::ostream &ostream, int offset)
{
    ostream << offset;
    ostream << ":";
    ostream << std::endl;
}

static void Insn_write_lpm(std::ostream &ostream, const Insn &insn, bool sbox)
{
    // Different chips within the AVR family have different "lpm" instructions.
    const char *ptr_reg = "Z";
    if (sbox) {
        // Load the element that we want to look up into the low
        // byte of the Z pointer.  We assume that the table is
        // aligned on a 256-byte boundary in flash memory.
        if (insn.reg2() != 30) {
            ostream << "\tmov r30,";
            Insn_write_reg(ostream, insn.reg2());
            ostream << std::endl;
        }
    } else if (insn.reg2() == POST_INC) {
        ptr_reg = "Z+";
    }
    ostream << "#if defined(RAMPZ)" << std::endl;
    ostream << "\telpm ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",";
    ostream << ptr_reg;
    ostream << "#elif defined(__AVR_HAVE_LPMX__)" << std::endl;
    ostream << "\tlpm ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",";
    ostream << ptr_reg;
    ostream << "#elif defined(__AVR_TINY__)" << std::endl;
    ostream << "\tld ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",";
    ostream << ptr_reg;
    ostream << "#else" << std::endl;
    ostream << "\tlpm" << std::endl;
    if (insn.reg1() != 0) {
        ostream << "\tmov ";
        Insn_write_reg(ostream, insn.reg1());
        ostream << ",r0";
        ostream << std::endl;
    }
    if (insn.reg2() == POST_INC) {
        // We need to increment Z but the instruction doesn't support it.
        // Do the increment ourselves with "adiw" after the fact.
        ostream << "\tadiw r30,1" << std::endl;
    }
    ostream << "#endif" << std::endl;
}

static void Insn_write_lpm_setup(std::ostream &ostream, const Insn &insn)
{
    // Set up the Z and RAMPZ registers with the pointer to the sbox.
    // The value() parameter of the instruction is the sbox number,
    // which indicates which global program memory label to reference.
    // The reg1() parameter is a temporary high register for loading RAMPZ.
    int table = insn.value();
    ostream << "\tldi r30,low(sbox_";
    ostream << table;
    ostream << " * 2)" << std::endl;
    ostream << "\tldi r31,high(sbox_";
    ostream << table;
    ostream << " * 2)" << std::endl;
    ostream << "#if defined(RAMPZ)" << std::endl;
    ostream << "\tin r0,_SFR_IO_ADDR(RAMPZ)" << std::endl;
    ostream << "\tpush r0" << std::endl;
    ostream << "\tldi ";
    Insn_write_reg(ostream, insn.reg1());
    ostream << ",byte3(sbox_";
    ostream << table;
    ostream << " * 2)" << std::endl;
    ostream << "\tout _SFR_IO_ADDR(RAMPZ),";
    Insn_write_reg(ostream, insn.reg1());
    ostream << std::endl;
    ostream << "#endif" << std::endl;
}

static void Insn_write_lpm_clean(std::ostream &ostream)
{
    // Pop the previous state of the RAMPZ register.
    ostream << "#if defined(RAMPZ)" << std::endl;
    ostream << "\tpop r0" << std::endl;
    ostream << "\tout _SFR_IO_ADDR(RAMPZ),r0" << std::endl;
    ostream << "#endif" << std::endl;
}

void Insn::write(std::ostream &ostream, const Code &code, int offset) const
{
    switch (m_type) {
    case ADC:       Insn_write_tworeg(ostream, "adc", *this); break;
    case ADD:       Insn_write_tworeg(ostream, "add", *this); break;
    case ADIW:      Insn_write_immreg(ostream, "adiw", *this); break;
    case AND:       Insn_write_tworeg(ostream, "and", *this); break;
    case ANDI:      Insn_write_immreg(ostream, "andi", *this); break;
    case ASR:       Insn_write_onereg(ostream, "asr", *this); break;
    case BLD:       Insn_write_bitop(ostream, "bld", *this); break;
    case BST:       Insn_write_bitop(ostream, "bst", *this); break;
    case BRCC:
        Insn_write_br(ostream, "brcc", "brcs", code, offset, *this); break;
    case BRCS:
        Insn_write_br(ostream, "brcs", "brcc", code, offset, *this); break;
    case BREQ:
        Insn_write_br(ostream, "breq", "brne", code, offset, *this); break;
    case BRNE:
        Insn_write_br(ostream, "brne", "breq", code, offset, *this); break;
    case CALL:
        Insn_write_br(ostream, "rcall", "rcall", code, offset, *this); break;
    case COM:       Insn_write_onereg(ostream, "com", *this); break;
    case CP:        Insn_write_tworeg(ostream, "cp", *this); break;
    case CPC:       Insn_write_tworeg(ostream, "cpc", *this); break;
    case CPI:       Insn_write_immreg(ostream, "cpi", *this); break;
    case CPSE:      Insn_write_tworeg(ostream, "cpse", *this); break;
    case DEC:       Insn_write_onereg(ostream, "dec", *this); break;
    case EOR:       Insn_write_tworeg(ostream, "eor", *this); break;
    case INC:       Insn_write_onereg(ostream, "inc", *this); break;
    case JMP:
        Insn_write_br(ostream, "rjmp", "rjmp", code, offset, *this); break;
    case LABEL:     Insn_write_label(ostream, offset); break;
    case LD_X:      Insn_write_load(ostream, "X", *this); break;
    case LD_Y:      Insn_write_load(ostream, "Y", *this); break;
    case LD_Z:      Insn_write_load(ostream, "Z", *this); break;
    case LDI:       Insn_write_immreg(ostream, "ldi", *this); break;
    case LPM:       Insn_write_lpm(ostream, *this, false); break;
    case LPM_SBOX:  Insn_write_lpm(ostream, *this, true); break;
    case LPM_SETUP: Insn_write_lpm_setup(ostream, *this); break;
    case LPM_CLEAN: Insn_write_lpm_clean(ostream); break;
    case LSL:       Insn_write_onereg(ostream, "lsl", *this); break;
    case LSR:       Insn_write_onereg(ostream, "lsr", *this); break;
    case MOV:       Insn_write_tworeg(ostream, "mov", *this); break;
    case MOVW:      Insn_write_tworeg(ostream, "movw", *this); break;
    case NEG:       Insn_write_onereg(ostream, "neg", *this); break;
    case NOP:       Insn_write_bare(ostream, "nop"); break;
    case OR:        Insn_write_tworeg(ostream, "or", *this); break;
    case ORI:       Insn_write_immreg(ostream, "ori", *this); break;
    case POP:       Insn_write_onereg(ostream, "pop", *this); break;
    case PUSH:      Insn_write_onereg(ostream, "push", *this); break;
    case PRINT:     break; // Print is for diagnostics on the desktop only.
    case PRINTCH:   break;
    case PRINTLN:   break;
    case RET:       Insn_write_bare(ostream, "ret"); break;
    case ROL:       Insn_write_onereg(ostream, "rol", *this); break;
    case ROR:       Insn_write_onereg(ostream, "ror", *this); break;
    case SBC:       Insn_write_tworeg(ostream, "sbc", *this); break;
    case SUB:       Insn_write_tworeg(ostream, "sub", *this); break;
    case SBCI:      Insn_write_immreg(ostream, "sbci", *this); break;
    case SUBI:      Insn_write_immreg(ostream, "subi", *this); break;
    case SBIW:      Insn_write_immreg(ostream, "sbiw", *this); break;
    case ST_X:      Insn_write_store(ostream, "X", *this); break;
    case ST_Y:      Insn_write_store(ostream, "Y", *this); break;
    case ST_Z:      Insn_write_store(ostream, "Z", *this); break;
    case SWAP:      Insn_write_onereg(ostream, "swap", *this); break;
    }
}

void Code::write(std::ostream &ostream) const
{
    // Registers that need to be saved if used: r2-r17.  We also need
    // to save r28:r29 but that is already handled in the common code.
    unsigned saved = 0x0003FFFC;

    // Output the function header.
    ostream << std::endl;
    ostream << "\t.text" << std::endl;
    ostream << ".global " << m_name << std::endl;
    ostream << "\t.type " << m_name << ", @function" << std::endl;
    ostream << m_name << ":" << std::endl;

    // Push registers that we need to save on the stack.
    unsigned saved_regs = 2;
    ostream << "\tpush r28" << std::endl; // Push Y
    ostream << "\tpush r29" << std::endl;
    for (int reg = 0; reg < 32; ++reg) {
        if ((saved & (1 << reg)) != 0 && (m_usedRegs & (1 << reg)) != 0) {
            Insn::reg1(Insn::PUSH, reg).write(ostream, *this, 0);
            ++saved_regs;
        }
    }

    // Create a new stack frame and copy the parameters into X, Z, or locals.
    unsigned extras = 0;
    switch (m_prologueType) {
    case EncryptBlock:
        ostream << "\tpush r23" << std::endl;
        ostream << "\tpush r22" << std::endl;
        extras = 2;
        if (hasFlag(MoveWord)) {
            ostream << "\tmovw r30,r24" << std::endl;
            ostream << "\tmovw r26,r20" << std::endl;
        } else {
            ostream << "\tmov r30,r24" << std::endl;
            ostream << "\tmov r31,r25" << std::endl;
            ostream << "\tmov r26,r20" << std::endl;
            ostream << "\tmov r27,r21" << std::endl;
        }
        break;

    case KeySetup:
        if (hasFlag(MoveWord)) {
            ostream << "\tmovw r30,r24" << std::endl;
            ostream << "\tmovw r26,r22" << std::endl;
        } else {
            ostream << "\tmov r30,r24" << std::endl;
            ostream << "\tmov r31,r25" << std::endl;
            ostream << "\tmov r26,r22" << std::endl;
            ostream << "\tmov r27,r23" << std::endl;
        }
        break;

    case Permutation:
        if (hasFlag(MoveWord)) {
            ostream << "\tmovw r30,r24" << std::endl;
        } else {
            ostream << "\tmov r30,r24" << std::endl;
            ostream << "\tmov r31,r25" << std::endl;
        }
        break;
    }
    unsigned locals = m_localsSize;
    if (locals <= 6) {
        // Push some zeroes on the stack to create the locals as this
        // will involve less instructions than arithmetic on Y and SP.
        for (unsigned temp = 0; temp < locals; ++temp)
            ostream << "\tpush r1" << std::endl;
        ostream << "\tin r28,0x3d" << std::endl;    // Y = SP
        ostream << "\tin r29,0x3e" << std::endl;
    } else {
        ostream << "\tin r28,0x3d" << std::endl;    // Y = SP
        ostream << "\tin r29,0x3e" << std::endl;
        if ((locals % 256) == 0) {
            ostream << "\tsubi r29," << (locals / 256) << std::endl;
        } else if (locals > 63 || !hasFlag(MoveWord)) {
            ostream << "\tsubi r28," << (locals % 256) << std::endl;
            ostream << "\tsbci r29," << (locals / 256) << std::endl;
        } else {
            ostream << "\tsbiw r28," << locals << std::endl;
        }
        ostream << "\tin r0,0x3f" << std::endl;     // r0 = SREG
        ostream << "\tcli" << std::endl;            // Disable ints
        ostream << "\tout 0x3e,r29" << std::endl;   // SPH = YH
        ostream << "\tout 0x3f,r0" << std::endl;    // SREG = r0 (Enable ints)
        ostream << "\tout 0x3d,r28" << std::endl;   // SPL = YL
    }
    ostream << ".L__stack_usage = "
            << (locals + extras + saved_regs) << std::endl;

    // Output all instructions in the function.
    for (unsigned index = 0; index < m_insns.size(); ++index)
        m_insns[index].write(ostream, *this, index);

    // Pop the stack frame.
    locals += extras; // Also pop the local for the "output" pointer.
    if (locals <= 6) {
        // Pop the values directly from the stack because it will
        // involve less instructions than arithmetic on Y and SP.
        while (locals > 0) {
            ostream << "\tpop r0" << std::endl;
            --locals;
        }
    } else if (locals > 0) {
        if (hasFlag(TempY)) {
            // Y was destroyed by the code so we need to restore it from SP.
            // We assume that the code has popped any extra stack positions
            // that it used before we get to here.
            ostream << "\tin r28,0x3d" << std::endl;
            ostream << "\tin r29,0x3e" << std::endl;
        }
        if (locals <= 63 && hasFlag(MoveWord)) {
            ostream << "\tadiw r28," << locals << std::endl;
        } else {
            // It is more efficient to subtract the negative.
            locals = -locals;
            if ((locals % 256) == 0) {
                ostream << "\tsubi r29," << (locals / 256) << std::endl;
            } else {
                ostream << "\tsubi r28," << (locals % 256) << std::endl;
                ostream << "\tsbci r29," << (locals / 256) << std::endl;
            }
        }
        ostream << "\tin r0,0x3f" << std::endl;     // r0 = SREG
        ostream << "\tcli" << std::endl;            // Disable ints
        ostream << "\tout 0x3e,r29" << std::endl;   // SPH = YH
        ostream << "\tout 0x3f,r0" << std::endl;    // SREG = r0 (Enable ints)
        ostream << "\tout 0x3d,r28" << std::endl;   // SPL = YL
    }

    // Restore the call-saved registers and return.
    for (int reg = 31; reg >= 0; --reg) {
        if ((saved & (1 << reg)) != 0 && (m_usedRegs & (1 << reg)) != 0) {
            Insn::reg1(Insn::POP, reg).write(ostream, *this, 0);
        }
    }
    ostream << "\tpop r29" << std::endl;            // Pop Y
    ostream << "\tpop r28" << std::endl;
    ostream << "\tret" << std::endl;

    // Output the function footer.
    ostream << "\t.size " << m_name;
    ostream << ", .-" << m_name << std::endl;
}
