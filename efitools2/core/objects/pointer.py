from idc import get_name_ea_simple, get_name, get_type, SetType, del_items, get_bytes
from ida_name import GN_VISIBLE, force_name


class Pointer(object):
    def __init__(self, addr=None, name=None):
        if addr is not None:
            self.__ea = addr
            if name is not None:
                self.name = name
        elif name:
            self.__ea = get_name_ea_simple(name)
        else:
            raise ValueError

    def __hash__(self):
        return self.__ea

    def __eq__(self, other):
        if isinstance(other, Pointer):
            return self.addr == other.addr
        return False

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return "%X %s" % (self.__ea, self.name)

    def __repr__(self):
        return "Pointer(0x%X, '%s')" % (self.__ea, self.name)

    @property
    def addr(self):
        return self.__ea

    @property
    def name(self):
        return get_name(self.__ea, GN_VISIBLE)

    @name.setter
    def name(self, value):
        if force_name(self.__ea, value) != 1:
            print("force_name(0x%X, '%s') has failed" % (self.__ea, value))

    @property
    def type(self):
        type = get_type(self.__ea)
        if type is None:
            type = ""
        return type

    @type.setter
    def type(self, value):
        if value is None or value == "":
            raise ValueError("value: %s" % value)
        if SetType(self.__ea, "%s %s" % (value, self.name)) == 0:
            del_items(self.__ea, 0)
            if SetType(self.__ea, "%s %s" % (value, self.name)) == 0:
                print('SetType(0x{:x}, "{} {}") has failed'.format(self.__ea, value, self.name))

    def get_bytes(self, cnt):
        return get_bytes(self.__ea, cnt)
