from ida_idaapi import BADADDR
from ida_netnode import BADNODE
from idautils import Segments
from ida_segment import getseg, SEG_DATA
from ida_bytes import is_struct, get_full_flags
from ida_struct import get_struc_id, get_struc_name, get_struc_size
from idc import import_type, guess_type, get_type, SetType
from idc import FF_BYTE, FF_DATA, FF_WORD, FF_DWORD, FF_QWORD
from idc import add_struc, add_struc_member, del_struc_member, get_next_offset
from idc import get_first_member, get_member_offset, get_member_flag, get_member_qty
from idc import set_member_name, get_member_name, get_member_id, next_head, get_segm_end

from .pointer import Pointer


class Structure(object):
    def __init__(self, name=None, sid=None, create_new=True):
        self._create_new = create_new

        if name is None or name == "":
            raise ValueError("name")

        self._sid = get_struc_id(name)

        if self._sid == BADNODE:
            self._sid = import_type(0, name)

        if self._sid == BADNODE:
            if not create_new:
                raise Exception("Unknown strucure type: %s" % name)
            else:
                self._sid = add_struc(-1, name, 0)
                add_struc_member(self._sid, "Dummy", 0, FF_BYTE | FF_DATA, -1, 1)

        if self._sid == BADNODE:
            raise Exception(
                "Can't define structure type because of bad "
                "structure name: the name is ill-formed "
                "or is already used in the program."
            )

    def __getitem__(self, item):
        if type(item) is str:
            return StructureMember(get_member_offset(self.__sid, item))
        raise NotImplementedError

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Structure('%s')" % self.name

    def __iter__(self):
        # Check structure consistency
        return self.members()

    def __hash__(self):
        return self._sid

    def __eq__(self, other):
        if isinstance(other, Structure):
            return self._sid == other.__sid
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other

    @property
    def name(self):
        return get_struc_name(self._sid)

    @property
    def sid(self):
        return self._sid

    @property
    def members_num(self):
        return get_member_qty(self._sid)

    @property
    def size(self):
        return get_struc_size(self._sid)

    @property
    def dummy(self):
        return self.members_num == 1 and next(self.members()).name == "Dummy"

    def members(self):
        m_off = get_first_member(self._sid)
        while m_off != BADADDR and m_off != -1:
            if get_member_flag(self._sid, m_off) != -1:
                yield StructureMember(self._sid, m_off)
            m_off = get_next_offset(self._sid, m_off)

    def ptrs(self):
        for seg_beg in filter(lambda x: getseg(x).type == SEG_DATA, Segments()):
            seg_end = get_segm_end(seg_beg)
            head = seg_beg
            while True:
                head = next_head(head, seg_end)
                if head == BADADDR:
                    break
                head_ptr = Pointer(head)
                if head_ptr.type.rstrip(" *") == self.name:
                    yield head_ptr

    def add_member(self, offset, name, size):
        if get_member_name(self._sid, 0) == "Dummy":
            del_struc_member(self._sid, 0)
        flag = {1: FF_BYTE, 2: FF_WORD, 4: FF_DWORD, 8: FF_QWORD}.get(size)
        if flag is None:
            raise ValueError("size")
        err_code = add_struc_member(self._sid, name, offset, flag | FF_DATA, -1, size)
        if err_code != 0:
            raise Exception("err_code = %d" % err_code)

    def guess_dummy_type(self, interface_ea):
        if self.dummy:
            if is_struct(get_full_flags(interface_ea)):
                return

            t = guess_type(interface_ea)
            if t is not None:
                next(self.members()).type = t


class StructureMember(object):
    def __init__(self, sid, offset):
        self._sid = sid
        self._offset = offset

        if self.mid == -1:
            raise ValueError("Bad structure type ID is passed or there is no member at the specified offset")

    def __str__(self):
        return "%s.%s @ 0x%X" % (get_struc_name(self._sid), self.name, self.offset)

    def __repr__(self):
        return "StructureMember(%s, 0x%X)" % (get_struc_name(self._sid), self._offset)

    def __hash__(self):
        return self.mid

    def __eq__(self, other):
        if isinstance(other, StructureMember):
            return self.mid == other.mid
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other

    @property
    def name(self):
        return get_member_name(self._sid, self._offset)

    @name.setter
    def name(self, value):
        if set_member_name(self._sid, self._offset, value) == 0:
            print("set_member_name(0x%X, 0x%X, '%s') has failed" % (self._sid, self._offset, value))

    @property
    def offset(self):
        return self._offset

    @property
    def type(self):
        return get_type(self.mid)

    @type.setter
    def type(self, value):
        if value is None or value == "":
            raise ValueError("value: %s" % value)
        if SetType(self.mid, value) == 0:
            raise Exception("SetType() has failed")

    @property
    def gap(self):
        return self.name is None

    @property
    def mid(self):
        return get_member_id(self._sid, self._offset)
