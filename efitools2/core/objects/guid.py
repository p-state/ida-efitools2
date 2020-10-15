from uuid import UUID

from .pointer import Pointer
from .structure import Structure

from ida_bytes import del_items, DELIT_SIMPLE

GUID_TYPENAME = "EFI_GUID"


class GUID(object):
    def __init__(self, addr=None, name=None, ptr=None):
        if addr is not None and name is not None:
            del_items(addr, DELIT_SIMPLE, 16)
            self.__ptr = Pointer(addr, name)
        elif ptr is not None:
            self.__ptr = ptr
        else:
            raise ValueError()
        if self.__ptr.type != GUID_TYPENAME:
            self.__ptr.type = Structure(GUID_TYPENAME).name

    @property
    def name(self):
        return self.__ptr.name

    @property
    def data(self):
        return self.__ptr.get_bytes(16)

    @property
    def ptr(self):
        return self.__ptr

    def as_uuid(self):
        return UUID(bytes_le=self.data)

    def __str__(self):
        return "{%s} %s" % (self.as_uuid(), self.name)

    def __hash__(self):
        return hash(self.data)

    def __eq__(self, other):
        if isinstance(other, GUID):
            return self.data == other.data
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other
