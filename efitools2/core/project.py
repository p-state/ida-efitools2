from builtins import range

import idc
import ida_typeinf
import os.path

# from core.logger import logger
from core.objects import ImportProtocol, ExportProtocol

IMPORT_PROTOCOL = 0
EXPORT_PROTOCOL = 1


class ProtocolsList(object):
    def __init__(self):
        self.__protocols = {}

    def __iter__(self):
        return iter(self.__protocols.values())

    def __len__(self):
        return len(self.__protocols.values())

    def is_registered(self, guid):
        return guid in self.__protocols

    def find(self, guid):
        return self.__protocols.get(guid)

    def register(self, guid, struc, interface_ptr, introduced_at, type):
        if self.is_registered(guid):
            raise Exception("Attempt to register already registered protocol: %s" % struc.name)
        if type == IMPORT_PROTOCOL:
            protocol_class = ImportProtocol
        elif type == EXPORT_PROTOCOL:
            protocol_class = ExportProtocol
        else:
            raise ValueError(type)
        protocol = protocol_class(guid, struc, interface_ptr, introduced_at)
        self.__protocols[guid] = protocol
        return protocol


import_protocol_name_prefix = "UNKNOWN"
export_protocol_name_prefix = "UNKNOWN"
autogen_struct_prefix = "UNKNOWN"


def load_til(path_to_til):
    if not ida_typeinf.load_til(path_to_til, os.path.dirname(path_to_til)):
        raise Exception("load_til('%s') has failed" % (path_to_til))

    # Fix UINTN to be the actual word size if we can determine it
    idc.Til2Idb(-1, "UINTN")
    entry = idc.GetEntryPoint(idc.GetEntryOrdinal(0))
    if entry != idc.BADADDR:
        typedef = "typedef UINT" + str(16 << idc.GetSegmentAttr(entry, idc.SEGATTR_BITNESS)) + " UINTN;"
        for i in range(0, idc.GetMaxLocalType()):
            if idc.GetLocalTypeName(i) == "UINTN":
                idc.SetLocalType(idc.SetLocalType(i, "", 0), typedef, 0)


def load_project(path):
    pass
