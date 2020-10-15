import string

from idc import import_type
from ida_struct import get_struc_id, get_struc_idx
from ida_idaapi import BADADDR
from ida_netnode import BADNODE

PTR_SIZE_BITS = {
    "qword ptr": 64,
    "dword ptr": 32,
    "word ptr": 16,
    "byte ptr": 8,
}


def filter_objects(objects_list, **attrs):
    for object in objects_list:
        for attr_name, attr_value in attrs.items():
            if getattr(object, attr_name) != attr_value:
                break
        else:
            yield object


def find_object(objects_list, **attrs):
    if objects_list is None:
        return None
    try:
        return next(filter_objects(objects_list, **attrs))
    except StopIteration:
        return None


def filter_objects_ex(objects_list, **attrs):
    for object in objects_list:
        for attr_name, attr_value in attrs.items():
            if getattr(object, attr_name) != attr_value:
                break
        else:
            yield object
    raise StopIteration


def find_object_ex(objects_list, **attrs):
    return next(filter_objects(objects_list, **attrs))


def underscore_to_global(name):
    return "g" + "".join(list(s.capitalize() for s in name.lower().split("_")))


def global_to_underscore(name):
    s = ""

    for c in name:
        if c in string.ascii_uppercase:
            s += "_"
        s += c.upper()

    return s[1:]


def is_structure_type(type):
    if type is None or type == "":
        return False

    sid = get_struc_id(type)
    if sid != BADNODE:
        return True

    sid = import_type(0, type)
    if sid != BADNODE:
        if get_struc_idx(sid) == BADADDR:
            raise Exception("Bad structure type ID")
        return True

    return False


def strip_end(text, suffix):
    if suffix == "" or not text.endswith(suffix):
        return text
    return text[: -len(suffix)]
