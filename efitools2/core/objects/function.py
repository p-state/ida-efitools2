from itertools import takewhile, dropwhile
from builtins import int

from ida_idaapi import BADADDR
from ida_struct import get_struc_name
from idautils import FuncItems
from idc import first_func_chunk, find_func_end, get_func_name, get_func_attr
from idc import set_frame_size, get_first_member, get_member_flag, get_next_offset
from idc import FUNCATTR_FRAME, FUNCATTR_FRSIZE, FUNCATTR_FRREGS

from .instruction import Instruction
from .structure import Structure, StructureMember


class Function(object):
    def __init__(self, ea):
        self.__start = first_func_chunk(ea)
        if self.__start == BADADDR:
            raise ValueError("Can't get the first function chunk of the specified function")

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Function(0x%X)" % self.__start

    def __hash__(self):
        return self.__start

    def __eq__(self, other):
        if isinstance(other, Function):
            return self.start == other.start
        elif isinstance(other, int):
            return self.start == other
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other

    @property
    def start(self):
        return self.__start

    @property
    def frame(self):
        frame_id = get_func_attr(self.__start, FUNCATTR_FRAME)
        if frame_id is not None:
            return FunctionFrame(get_struc_name(frame_id), create_new=False)

    @property
    def name(self):
        return get_func_name(self.__start)

    def args(self):
        lvar_size = get_func_attr(self.__start, FUNCATTR_FRSIZE) - 8  # exclude return address
        return iter(takewhile(lambda x: x.offset < lvar_size, self.frame))

    def lvars(self):
        lvar_size = get_func_attr(self.__start, FUNCATTR_FRSIZE)  # exclude return address
        return iter(dropwhile(lambda x: x.offset < lvar_size + 8, self.frame))

    def items(self, start=0, stop=None):
        if stop is None:
            stop = find_func_end(self.__start)
        for item_ea in dropwhile(lambda x: x < start, FuncItems(self.__start)):
            if item_ea >= stop:
                break
            yield Instruction(item_ea)

    def grow_frame(self, lvsize=None, argregs=None, argsize=None):
        new_lvsize = get_func_attr(self.__start, FUNCATTR_FRSIZE) if lvsize is None else lvsize
        new_argregs = get_func_attr(self.__start, FUNCATTR_FRREGS) if argregs is None else argregs
        new_argsize = get_func_attr(self.__start, FUNCATTR_FRREGS) if argsize is None else argsize

        if set_frame_size(self.__start, new_lvsize, new_argregs, new_argsize) == -1:
            raise Exception(
                "set_frame_size(0x%X, 0x%X, 0x%X, 0x%X) has failed"
                % (self.__start, new_lvsize, new_argregs, new_argsize)
            )


class FunctionFrame(Structure):
    def __iter__(self):
        m_off = get_first_member(self._sid)
        while m_off != BADADDR and m_off != -1:
            if get_member_flag(self._sid, m_off) != -1:
                yield LocalVariable(self._sid, m_off)
            m_off = get_next_offset(self._sid, m_off)


class LocalVariable(StructureMember):
    pass
