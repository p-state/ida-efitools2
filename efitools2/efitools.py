from __future__ import print_function
import os
import time

from idautils import Segments
from ida_nalt import get_imagebase
from ida_entry import get_entry_qty, get_entry_ordinal, get_entry
from ida_idaapi import get_inf_structure
from ida_segment import rebase_program, MSF_FIXONCE
from idc import get_segm_name, set_segm_name, set_segm_class, set_segm_attr, SEGATTR_PERM
from ida_typeinf import cvar, set_compiler_id, add_til, parse_decls, ADDTIL_DEFAULT, HTI_FIL

import tools
from core.objects import Structure

EFITOOLS_DIR = os.path.dirname(os.path.realpath(__file__))

# applied only if current base is 0
DEFAULT_IMAGE_BASE = 0x80000000

# set .text segment RWE permissions
FIX_CODE_SEGMENT_PERMISSIONS = True

# import headers from 'types' folder
IMPORT_EXTERNAL_TYPES = True


class EfiTools(object):
    base_dir = EFITOOLS_DIR
    types_dir = os.path.join(EFITOOLS_DIR, "types")

    @staticmethod
    def image_rebase():
        if get_imagebase() == 0:
            rebase_program(DEFAULT_IMAGE_BASE, MSF_FIXONCE)

    @staticmethod
    def set_text_segment_rwe():
        """
        Update name, class, permissions of CODE segment to resolve elimination of "dead" code.
        Also set compiler to VC++.
        """
        for seg in Segments():
            if get_segm_name(seg) == ".text":
                set_segm_name(seg, ".code")
                set_segm_class(seg, "DATA")
                set_segm_attr(seg, SEGATTR_PERM, 0b111)  # RWE

                print(
                    "Updating segment at "
                    + hex(seg)
                    + ":\nsegment name .text -> .code"
                    + "\nsegment class = DATA"
                    + "\nsegment permissions = RWE"
                )

                break

        set_compiler_id(1)  # Visual C++

    @staticmethod
    def import_types():
        """
        Import external types from 'types' directory
        """

        # just in case uefi type library is not loaded
        add_til("uefi64" if get_inf_structure().is_64bit() else "uefi", ADDTIL_DEFAULT)

        types_dir = EfiTools.types_dir

        for type_file in os.listdir(types_dir):
            print("Importing types from %s... " % type_file, end="")

            file_path = os.path.join(types_dir, type_file)
            errors = parse_decls(cvar.idati, file_path, None, HTI_FIL)

            if errors != 0:
                print("some types were not imported correctly!")
            else:
                print()

    @staticmethod
    def do_the_magic():

        start_time = time.time()

        # Turn any known GUIDs found into GUID structures
        print("Updating GUIDs...")
        tools.update_guids(os.path.join(EfiTools.base_dir, "guids", "db.ini"))
        tools.update_guids(os.path.join(EfiTools.base_dir, "guids", "custom.ini"))

        for idx in range(0, get_entry_qty()):
            entry = get_entry(get_entry_ordinal(idx))

            print("Performing initial structure updates starting at entry point ({:#x})...".format(entry))
            tools.update_structs_from_regs(entry, rdx=Structure("EFI_SYSTEM_TABLE"))

        print("Updating structures from xrefs...")
        tools.update_structs_from_xrefs()

        print("Searching for EFI protocols...")
        protocols = tools.update_protocols()

        print("Updating structures from lvars...")
        tools.update_structs_from_lvars(protocols)

        print("Updating structures from xrefs...")
        tools.update_structs_from_xrefs()

        print("Searching for EFI protocols...")
        protocols = tools.update_protocols()

        print("Updating structures from lvars...")
        tools.update_structs_from_lvars(protocols)

        for protocol in protocols:
            print(protocol.name)
            print("  GUID          : %s" % protocol.guid.as_uuid())
            print("  Interface     : %s" % protocol.interface)
            print("  Introduced at : 0x%X" % protocol.introduced_at)
            print("  Class         : %s" % str(protocol.__class__).split(".")[-1])

        print("Finished in %f seconds" % (time.time() - start_time))


if __name__ == "__main__":
    """
    Running as standalone idapython script.
    """
    EfiTools.image_rebase()

    if FIX_CODE_SEGMENT_PERMISSIONS:
        EfiTools.set_text_segment_rwe()

    if IMPORT_EXTERNAL_TYPES:
        EfiTools.import_types()

    EfiTools.do_the_magic()
