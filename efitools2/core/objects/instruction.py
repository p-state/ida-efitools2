import re
from builtins import int

import idautils
from itertools import count
from idc import get_operand_value, get_operand_type, o_void, o_phrase, o_displ, o_reg
from idc import print_insn_mnem, print_operand, generate_disasm_line

from .register import Register


class Instruction(object):
    def __init__(self, ea):
        self.__ea = ea

    def __getitem__(self, item):
        if get_operand_type(self.__ea, item) not in [o_void, -1]:
            return _Operand(self.__ea, item)
        return None

    def __str__(self):
        return "%s @ 0x%X" % (generate_disasm_line(self.__ea, 0).split(";")[0], self.__ea)

    def __repr__(self):
        return "Instruction(0x%X)" % self.__ea

    def __hash__(self):
        return self.__ea

    def __eq__(self, other):
        if isinstance(other, Instruction):
            return self.__ea == other.__ea
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other

    @property
    def ea(self):
        return self.__ea

    @property
    def insn(self):
        return idautils.DecodeInstruction(self.__ea)

    @property
    def mnem(self):
        return print_insn_mnem(self.__ea)

    @property
    def operands_num(self):
        if get_operand_type(self.__ea, 0) == o_void:
            return 0
        if get_operand_type(self.__ea, 1) == o_void:
            return 1
        return 2

    def operands(self):
        for op_n in count():
            op = self[op_n]
            if op is not None:
                yield op
            else:
                break


class _Operand(object):
    def __init__(self, ea, n):
        self.__ea = ea
        self.__n = n

    def __str__(self):
        return print_operand(self.__ea, self.__n)

    def __repr__(self):
        return "_Operand(0x%X, %d)" % (self.__ea, self.__n)

    def __hash__(self):
        return hash(self.__ea)

    @property
    def ea(self):
        return self.__ea

    @property
    def n(self):
        return self.__n

    @property
    def type(self):
        return _OperandType(get_operand_type(self.__ea, self.__n))

    @property
    def value(self):
        # operand is an immediate value  => immediate value
        # operand has a displacement     => displacement
        # operand is a direct memory ref => memory address
        # operand is a register          => register number
        # operand is a register phrase   => phrase number
        # otherwise                      => -1
        value = get_operand_value(self.__ea, self.__n)
        if value == -1:
            raise Exception("get_operand_value() for %s has failed" % self)
        return value

    @property
    def reg(self):
        if self.type == o_reg and str(self) != "":
            return Register(str(self))
        elif self.type in [o_phrase, o_displ] and str(self) != "":
            name = _REG_FROM_DISPL_RE.match(str(self)).group(1)
            return Register(name)
        else:
            return None

    @property
    def displ(self):
        if self.type == o_displ:
            return self.value
        elif self.type == o_phrase:
            return 0
        else:
            return None

    @property
    def index_reg(self):
        if "(" in str(self):
            return None
        try:
            return _INDEX_REG_FROM_PHRASE_RE.match(str(self)).group(1)
        except AttributeError:
            return None

    @property
    def displ_str(self):
        if "(" in str(self):
            return None
        try:
            return _DISPL_STR_FROM_DISPL_RE.match(str(self)).group(2)
        except AttributeError:
            return None


class _OperandType(object):
    def __init__(self, op_type):
        self.__op_type = op_type

    def __str__(self):
        return _OP_TYPE_STR[self.__op_type]

    def __repr__(self):
        return "_OperandType(%d)" % self.__op_type

    def __hash__(self):
        return self.__op_type

    def __eq__(self, other):
        if isinstance(other, _OperandType):
            return self.__op_type == other.__op_type
        elif isinstance(other, int):
            return self.__op_type == other
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other


_REG_FROM_DISPL_RE = re.compile(r".*\[([a-z0-9]*)")
_INDEX_REG_FROM_PHRASE_RE = re.compile(r".*\[[a-z0-9]*([\+\-].*?)[\+\-]+")
_DISPL_STR_FROM_DISPL_RE = re.compile(r".*?\[\w*([\+\-0-9A-F]*h)?[\+\-]?(.*)?\]")

_OP_TYPE_STR = {
    0: "o_void",
    1: "o_reg",
    2: "o_mem",
    3: "o_phrase",
    4: "o_displ",
    5: "o_imm",
    6: "o_far",
    7: "o_near",
}
