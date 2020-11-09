import sys
import idaapi
from idaapi import *

# For Version 7
from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_offset import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *
import ida_frame
import idc


# ----------------------------------------------------------------------
# Auxiliary functions bits and sign manupilation
#

# Extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, high, low):
    return (val >> low) & ((1 << (high - low + 1)) - 1)


# Extract one bit
def BIT(val, bit):
    return (val >> bit) & 1


# Aign extend b low bits in x from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


# ----------------------------------------------------------------------
# IDP specific information
#

# Global pointer index
GP_IDX = 1


# ----------------------------------------------------------------------
# CH340 processor module class
#

class ch340_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 340

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 16

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['ch340']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['W.CH340 (little endian)']

    # size of a segment register in bytes
    segreg_size = 0

    # icode of the first instruction
    instruc_start = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #   real_width[0] - number of digits for short floats (only PDP-11 has them)
    #   real_width[1] - number of digits for "float"
    #   real_width[2] - number of digits for "double"
    #   real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # only one assembler is supported
    assembler = {
        # flag
        'flag': ASH_HEXF3 | ASD_DECF0 | AS_UNEQU | AS_COLON | ASB_BINF0 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag': 0,

        # Assembler name (displayed in menus)
        'name': "W.CH340 (little endian)",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': [".CH340"],

        # org directive
        'origin': ".org",

        # end directive
        'end': ".end",

        # comment string (see also cmnt2)
        'cmnt': "#",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #   Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".ascii",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".word",

        # remove if not allowed
        'a_dword': ".dword",

        # float; 4bytes; remove if not allowed
        'a_float': ".float",

        # double; 8bytes; NULL if not allowed
        'a_double': ".double",

        # array keyword. the following
        # sequences may appear:
        #   #h - header
        #   #d - size
        #   #v - value
        #   #s(b,w,l,q,f,d,o) - size specifiers
        #                       for byte,word,
        #                           dword,qword,
        #                           float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        #
        # translation to use in character and string constants.
        # usually 1:1, i.e. trivial translation
        # If specified, must be 256 chars long
        # (optional)
        #   'XlatAsciiOutput': "".join([chr(x) for x in xrange(256)]),

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"    name keyword. NULL-gen default, ""-do not generate
        'a_weak': ".weak",

        # "extrn" name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # % mod assembler time operation
        'a_mod': "%",

        # & bit and assembler time operation
        'a_band': "&",

        # | bit or assembler time operation
        'a_bor': "|",

        # ^ bit xor assembler time operation
        'a_xor': "^",

        # ~ bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': ".size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "%lo",
        'high16': "%hi",

        # the include directive (format string) (optional)
        'a_include_fmt': ".include %s",

        # if a named item is a structure and displayed in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 3-byte data (optional)
        'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    }  # Assembler

    # ----------------------------------------------------------------------
    # Special flags used by the decoder, emulator and output
    #
    FL_SIGNED = 0x01  # value/address is signed; output as such

    # Global Pointer Node Definition
    GlobalPointerNode = None

    # Global Pointer Value
    GlobalPointer = BADADDR

    # ----------------------------------------------------------------------
    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
            return self.instruc[insn.itype]['cmt']

    def can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return True

    # ----------------------------------------------------------------------
    # Global pointer manipulations, init, save, load
    #

    def notify_init(self, idp_file):
        self.GlobalPointerNode = idaapi.netnode("$ Global Pointer", 0, True)
        return 1

    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        self.GlobalPointer = self.GlobalPointerNode.altval(GP_IDX)
        pass

    def notify_savebase(self):
        """The database is being saved. Processor module should save its local data"""
        self.GlobalPointerNode.altset(GP_IDX, self.GlobalPointer)
        pass

    # ----------------------------------------------------------------------
    # Output to screen functions
    #

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by the emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type
        SignedFlag = OOF_SIGNED if op.specflag1 & self.FL_SIGNED != 0 else 0

        if optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_imm:
            ctx.out_symbol('#')
            ctx.out_value(op, OOFW_IMM | OOFW_8 | SignedFlag)
        #       if optype == o_reg:
        #           ctx.out_register(self.reg_names[op.reg])
        #           if ctx.insn.itype == self.itype_jmp and get_switch_info_ex(ctx.insn.ea) == None:
        #               JumpOff = get_first_fcref_from(ctx.insn.ea)
        #               ctx.out_symbol(' ')
        #               ctx.out_symbol('#')
        #               ctx.out_symbol(' ')
        #               r = ctx.out_name_expr(op, JumpOff, BADADDR)
        #               if not r:
        #                   ctx.out_tagon(COLOR_ERROR)
        #                   ctx.out_btoa(op.addr, 16)
        #                   ctx.out_tagoff(COLOR_ERROR)
        #                   remember_problem(PR_NONAME, ctx.insn.ea)
        #       elif optype == o_displ:
        #           ctx.out_value(op, OOF_ADDR | OOFW_16 | SignedFlag)
        #           ctx.out_symbol('(')
        #           ctx.out_register(self.reg_names[op.reg])
        #           ctx.out_symbol(')')
        #           if op.specflag1 & self.FL_VAL32:
        #               if isEnabled(op.specval) == False:
        #                   ctx.out_symbol(' ')
        #                   ctx.out_symbol('#')
        #                   ctx.out_symbol(' ')
        #                   ctx.out_btoa(op.specval, 16)
        return True

    def out_mnem(self, ctx):
        postfix = ""
        ctx.out_mnem(12, postfix)

    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()
        msg("out_mnemonic()\n")
        if ctx.insn.Op1.type != o_void:
            msg("out_one_operand(0)\n")
            ctx.out_one_operand(0)
        for i in xrange(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)
        ctx.set_gen_cmt()  # generate comment at the next call to MakeLine()
        ctx.flush_outbuf()

    # ----------------------------------------------------------------------
    # Operand handling
    #

    def handle_operand(self, insn, op, isRead):
        uFlag = get_flags(insn.ea)
        is_offs = is_off(uFlag, op.n)
        is_stroffs = is_stroff(uFlag, op.n)
        dref_flag = dr_R if isRead else dr_W
        def_arg = is_defarg(uFlag, op.n)
        optype = op.type
        if optype == o_near:
            if insn.get_canon_feature() & CF_CALL:
                XrefType = fl_CN
            else:
                XrefType = fl_JN
            insn.add_cref(op.addr, op.offb, XrefType)

    # ----------------------------------------------------------------------
    # Instruction emulator
    #

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        Feature = insn.get_canon_feature()
        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, 1)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, 0)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, 1)
        if Feature & CF_CHG2:
            self.handle_operand(insn, insn.Op2, 0)
        if Feature & CF_USE3:
            self.handle_operand(insn, insn.Op3, 1)
        if Feature & CF_CHG3:
            self.handle_operand(insn, insn.Op3, 0)
        if Feature & CF_USE4:
            self.handle_operand(insn, insn.Op4, 1)
        if Feature & CF_CHG4:
            self.handle_operand(insn, insn.Op4, 0)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        if (Feature & CF_STOP == 0):
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return 1

        # ----------------------------------------------------------------------
        # Instruction decoder
        #

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn.
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        InstructionCode = get_16bit(insn.ea)
        insn.size += 1
        #        InstructionCode = insn.get_next_word()     # get_next_word() only works with 8-bit program words
        if BITS(InstructionCode, 13, 8) == 0x01:
            insn.itype = self.itype_jmp
            insn.Op1.addr = BITS(InstructionCode, 10, 0)
            insn.Op1.type = o_near
        elif BITS(InstructionCode, 13, 11) == 0b110:
            insn.itype = self.itype_call_110
            insn.Op1.addr = BITS(InstructionCode, 10, 0)
            insn.Op1.type = o_near
        elif BITS(InstructionCode, 13, 11) == 0b111:
            insn.itype = self.itype_call_111
            insn.Op1.addr = BITS(InstructionCode, 10, 0)
            insn.Op1.type = o_near
        elif BITS(InstructionCode, 13, 8) == 0x10:
            insn.itype = self.itype_usbtx
            insn.Op1.value = BITS(InstructionCode, 7, 0)
            insn.Op1.type = o_imm
        elif BITS(InstructionCode, 13, 0) == 0x2FA4:
            insn.itype = self.itype_ifret_cond1
        elif BITS(InstructionCode, 13, 0) == 0x2F24:
            insn.itype = self.itype_ifelseret_cond2
        else:
            return 0

        return insn.size

    # ----------------------------------------------------------------------
    # Classes for instruction decoding
    #

    def init_instructions(self):

        class idef:
            def __init__(self, name, cf, comment=''):
                self.name = name
                self.cf = cf
                self.comment = comment

        itable = []
        itable.append(idef('jmp', CF_USE1))
        itable.append(idef('call_110', CF_USE1 | CF_CALL))
        itable.append(idef('call_111', CF_USE1 | CF_CALL))
        itable.append(idef('usbtx', CF_USE1))
        itable.append(idef('ifret_cond1', 0))
        itable.append(idef('ifelseret_cond2', 0))
        itable.append(idef('ret', CF_STOP))

        Instructions = []
        i = 0
        for x in itable:
            d = dict(name=x.name, feature=x.cf)
            if x.comment != None:
                d['cmt'] = x.comment
            Instructions.append(d)
            setattr(self, 'itype_' + x.name, i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(Instructions)

        # Array of instructions
        self.instruc = Instructions

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_ret

    # ----------------------------------------------------------------------
    # Registers definition
    #

    def init_registers(self):
        """This function parses the
        register table and creates
        corresponding ireg_XXX constants"""
        # register names
        self.reg_names = [
            # General-Purpose Registers
            "r0",  # aka r0
            "r1",  # aka r1
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "r7",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "r16",
            "r17",
            "r18",
            "r19",
            "r20",
            "r21",
            "r22",
            "r23",
            "r24",
            "r25",
            "r26",
            "r27",
            "r28",
            "r29",
            "r30",
            "r31",
            # Fake segment registers
            "CS",
            "DS"
        ]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg = self.ireg_DS

        # You should define 2 virtual segment registers for CS and DS.

        # number of CS register
        self.reg_code_sreg = self.ireg_CS
        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()


# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return ch340_processor_t()
