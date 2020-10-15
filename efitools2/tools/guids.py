from itertools import repeat
from uuid import UUID

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

from idautils import Segments
from ida_segment import getseg
from idc import get_segm_end, get_bytes

from core.objects import GUID


def update_guids(path_to_db, seg_types=None):
    _load_guids_db(path_to_db)
    if seg_types:

        def filter_expr(x):
            return getseg(x).type in seg_types

    else:
        filter_expr = None
    for seg_beg in filter(filter_expr, Segments()):
        seg_end = get_segm_end(seg_beg)
        _process_segment(seg_beg, seg_end)


def _process_segment(seg_beg, seg_end):
    for addr in range(seg_beg, seg_end, 4):
        guid_bytes_le = get_bytes(addr, _GUID_SIZE)
        if guid_bytes_le != _zero_guid_bytes and guid_bytes_le != _ffff_guid_bytes:
            guid_name = _guids_db.get(guid_bytes_le, None)
            if guid_name:
                # Just marks it as a GUID structure
                guid = GUID(addr=addr, name=guid_name)
                print("Found %s @ 0x%X" % (guid, addr))


_zero_guid_bytes = b"".join(repeat(b"\x00", 16))
_ffff_guid_bytes = b"".join(repeat(b"\xFF", 16))
_guids_db = dict()

_GUID_SIZE = 16


def _load_guids_db(path_to_db):
    parser = ConfigParser()

    if not parser.read(path_to_db):
        raise IOError("Can not read %s" % path_to_db)

    for section in parser.sections():
        for guid_name, guid_hex in parser.items(section):
            _guids_db.update({UUID(hex=guid_hex).bytes_le: str(guid_name).upper()})
