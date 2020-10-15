import os
import sys
from uuid import UUID
from struct import pack
from builtins import bytes  # add bytes semantics from py3 to py2

from ida_funcs import get_func
from ida_idaapi import PLUGIN_KEEP, plugin_t
from idc import get_bytes, o_displ, o_phrase, o_imm
from ida_kernwin import action_handler_t, action_desc_t, register_action, unregister_action
from ida_kernwin import get_screen_ea, attach_action_to_popup
from ida_kernwin import AST_ENABLE_FOR_WIDGET, AST_DISABLE_FOR_WIDGET
from ida_kernwin import BWN_DISASM, BWN_LOCTYPS

# this eliminates package name 'efitools2' from class paths
# efitools2.core.objects.Structure != core.objects.Structure
EFITOOLS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "efitools2")
sys.path.append(EFITOOLS_DIR)

from efitools import EfiTools, FIX_CODE_SEGMENT_PERMISSIONS, IMPORT_EXTERNAL_TYPES
from core.objects import Function


# customize hotkeys here
RUN_PLUGIN_HOTKEY = "Ctrl-Alt-E"
PRINT_EFI_GUID_HOTKEY = "Ctrl-Alt-G"
SYNC_LOCAL_TYPES_HOTKEY = "F5"


def extract_guid(ea):
    function = Function(ea)
    guidname = None
    fields = dict()

    for item in function.items(ea):
        if item.mnem == "mov" and item.operands_num == 2:
            displ = item[0]
            imm = item[1]

            if displ.type in (o_displ, o_phrase) and imm.type == o_imm:
                if ".Data" not in displ.displ_str:
                    continue

                lvar, field = displ.displ_str.split(".")

                if guidname is None:
                    guidname = lvar

                if lvar == guidname:
                    fields[field] = imm.value & (1 << 32) - 1

                if len(fields) == 4:
                    break
    else:
        raise LookupError("unable to find all EFI_GUID fields")

    return guidname, pack("<IIII", fields["Data1"], fields["Data2"], fields["Data4"], fields["Data4+4"])


class PrintEfiGuid(action_handler_t):
    name = "my:PrintEfiGuid"
    description = "Print EFI_GUID at current location"
    hotkey = PRINT_EFI_GUID_HOTKEY

    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        ea = get_screen_ea()

        if get_func(ea) is None:
            print("address = " + hex(ea))

            data = get_bytes(ea, 16)
            guid = str(UUID(bytes_le=data))
        else:
            name, data = extract_guid(ea)
            guid = str(UUID(bytes_le=data))

            print("Local variable EFI_GUID extraction for " + name)

        print("data = " + " ".join("%02x" % x for x in bytes(data)))
        print("guid = " + guid)

        try:
            import clipboard

            clipboard.copy(guid)
        except ImportError:
            print("clipboard module is not available.")

    def update(self, ctx):
        if ctx.widget_type == BWN_DISASM:
            attach_action_to_popup(ctx.widget, None, self.name)
            return AST_ENABLE_FOR_WIDGET
        return AST_DISABLE_FOR_WIDGET


class SyncLocalTypes(action_handler_t):
    name = "my:SyncLocalTypes"
    description = "Synchronize with external types"
    hotkey = SYNC_LOCAL_TYPES_HOTKEY

    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        EfiTools.import_types()

    def update(self, ctx):
        if ctx.widget_type == BWN_LOCTYPS:
            attach_action_to_popup(ctx.widget, None, self.name)
            return AST_ENABLE_FOR_WIDGET
        return AST_DISABLE_FOR_WIDGET


class EfiToolsPlugin(plugin_t):
    flags = 0
    comment = "Plugin for augmenting UEFI reverse engineering capabilities"
    help = ""
    wanted_name = "efitools2"
    wanted_hotkey = RUN_PLUGIN_HOTKEY
    executed = False

    @staticmethod
    def register_action(action, *args):
        register_action(action_desc_t(action.name, action.description, action(*args), action.hotkey))

    @staticmethod
    def init():
        EfiToolsPlugin.register_action(SyncLocalTypes)
        EfiToolsPlugin.register_action(PrintEfiGuid)

        return PLUGIN_KEEP

    @staticmethod
    def run(arg):
        if not EfiToolsPlugin.executed:
            EfiTools.image_rebase()

            if IMPORT_EXTERNAL_TYPES:
                EfiTools.import_types()

            # arg = 1 means running in batch mode
            # BinExport requires CODE segment to be R+E
            if arg != 1 and FIX_CODE_SEGMENT_PERMISSIONS:
                EfiTools.set_text_segment_rwe()

            EfiToolsPlugin.executed = True

        EfiTools.do_the_magic()

    @staticmethod
    def term():
        unregister_action(SyncLocalTypes.name)
        unregister_action(PrintEfiGuid.name)


def PLUGIN_ENTRY():
    return EfiToolsPlugin()
