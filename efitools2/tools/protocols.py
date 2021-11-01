from builtins import range

from idautils import Functions
from ida_name import is_uname
from ida_segment import get_segm_qty, getnseg, SEG_CODE
from idc import get_segm_name, get_wide_dword, o_displ, o_phrase, o_reg, o_mem

from core import project
from core.objects import Function, Pointer, GUID, Structure, Interface
from core.utils import strip_end, underscore_to_global, find_object

protocols = project.ProtocolsList()


def update_protocols():
    for n in range(get_segm_qty()):
        seg = getnseg(n)

        if seg.type == SEG_CODE or get_segm_name(seg.start_ea) == ".code":
            seg_beg = seg.start_ea
            seg_end = seg.end_ea
            for function in map(lambda x: Function(x), Functions(seg_beg, seg_end)):
                _process_function(function)

    return protocols


def _process_function(function):
    for item in filter(lambda x: x.mnem in ["call", "jmp"], function.items()):
        if item[0].type in [o_displ, o_phrase]:
            displ = item[0].displ_str
            if displ is None:
                print("Unable to parse displacement string of %s" % item)
                continue

            displ = displ.strip("_")
            if displ in _PROTOCOL_IMPORT_EXPORT_HANDLERS:
                method_handler, guid_reg, interface_reg, protocol_type = _PROTOCOL_IMPORT_EXPORT_HANDLERS[displ]
                method_handler(function, item, guid_reg, interface_reg, protocol_type)


def _process_single_call(function, call_instr, guid_reg, interface_reg, protocol_type):
    reg_args = _get_call_lea_args(function, call_instr, guid_reg, interface_reg)

    if reg_args[guid_reg] is None:
        print("Can not determine GUID ptr: %s" % call_instr)
        return

    if reg_args[interface_reg] is None:
        print("No interface argument found: %s" % call_instr)

    guid = _prepare_guid(reg_args[guid_reg], project.export_protocol_name_prefix)
    if guid is None:
        return

    struc = _prepare_struc(guid)
    if struc is None:
        return

    interface = None
    if reg_args[interface_reg] is not None:
        interface = _prepare_interface(reg_args[interface_reg], struc, function, call_instr.ea, protocol_type)

    protocol = protocols.find(guid)
    if protocol is None:
        protocols.register(guid, struc, interface, call_instr.ea, protocol_type)

    return protocol


def _process_install_multiple_call(function, call_instr, guid_reg, interface_reg, protocol_type):
    pass


def _get_call_lea_args(function, call_instr, *regs):
    reg_args = dict((reg, None) for reg in regs)
    mov_regs = reg_args.copy()

    for item in function.items(stop=call_instr.ea):
        if item.operands_num > 0 and item[0].type == o_reg and item[0].reg and item[0].reg.name_ex in reg_args:
            if item.mnem == "lea":
                reg_args[item[0].reg.name_ex] = item[1]
            elif item.mnem == "mov" and item[1].type == o_reg:
                mov_regs[item[0].reg.name_ex] = item[1].reg.name_ex
            elif item.mnem not in ["cmp", "test"]:
                reg_args[item[0].reg.name_ex] = None

    for reg, value in reg_args.items():
        if value is None and mov_regs[reg]:
            r = mov_regs[reg]
            moved_regs = _get_call_lea_args(function, call_instr, r)
            if moved_regs[r]:
                reg_args[reg] = moved_regs[r]

    return reg_args


def _prepare_guid(op, prefix):
    if op.type == o_mem:
        guid_ptr = Pointer(op.value)
        if guid_ptr.type != "EFI_GUID" or not is_uname(guid_ptr.name) or guid_ptr.name in ["Protocol", "HandlerType"]:
            guid_data1 = str("%.8x" % get_wide_dword(op.value)).upper()
            guid_ptr.name = "%s_PROTOCOL_%s_GUID" % (prefix, guid_data1)
    else:
        print("Do not know how to extract GUID ptr from %s at 0x%X" % (op, op.ea))
        return

    guid = None
    try:
        guid = GUID(ptr=guid_ptr)
    except Exception as e:
        print("Error: %s" % repr(e))

    return guid


def _prepare_struc(guid):
    if project.autogen_struct_prefix:
        struc_name = strip_end(guid.name.rstrip("_0123456789"), "_GUID")
    else:
        struc_name = strip_end(guid.name, "_GUID")

    if struc_name == "Protocol":
        return None

    struc = None
    try:
        struc = Structure(name=struc_name)
    except Exception as e:
        print("Error: %s" % repr(e))

    return struc


def _prepare_interface(op, struc, function, bind_point, protocol_type):
    if op.type == o_mem:
        ptr = Pointer(op.value)
        ptr.name = underscore_to_global(struc.name)

        if protocol_type == project.IMPORT_PROTOCOL:
            ptr.type = struc.name + " *"
        else:  # EXPORT_PROTOCOL
            struc.guess_dummy_type(op.value)
            ptr.type = struc.name

        return Interface(ptr, bind_point)
    elif op.type == o_displ:
        lvar_name = op.displ_str
        if lvar_name is not None:
            lvar = find_object(function.frame, name=lvar_name)
            if lvar is not None:
                lvar.name = underscore_to_global(struc.name).lstrip("g")
                lvar.type = struc.name + " *"
                return Interface(lvar, bind_point)
            else:
                print("Lvar %s not found in function %s frame" % (lvar_name, function))
        else:
            print("Can not extract lvar name from %s at 0x%X" % (op, op.ea))
    else:
        print("Do not know how to extract interface from %s at 0x%X" % (op, op.ea))


_PROTOCOL_IMPORT_EXPORT_HANDLERS = {

    "EFI_SMM_SYSTEM_TABLE2.SmmLocateProtocol":
        (_process_single_call, 'rcx', 'r8', project.IMPORT_PROTOCOL),
    "EFI_BOOT_SERVICES.LocateProtocol":
        (_process_single_call, 'rcx', 'r8', project.IMPORT_PROTOCOL),
    "EFI_SMM_RUNTIME_PROTOCOL.LocateProtocol":
        (_process_single_call, 'rcx', 'r8', project.IMPORT_PROTOCOL),
    "EFI_SMM_SYSTEM_TABLE2.SmmHandleProtocol":
        (_process_single_call, 'rdx', 'r8', project.IMPORT_PROTOCOL),
    "EFI_BOOT_SERVICES.HandleProtocol":
        (_process_single_call, 'rdx', 'r8', project.IMPORT_PROTOCOL),
    "EFI_BOOT_SERVICES.OpenProtocol":
        (_process_single_call, 'rdx', 'r8', project.IMPORT_PROTOCOL),
    "EFI_BOOT_SERVICES.InstallProtocolInterface":
        (_process_single_call, 'rdx', 'r9', project.EXPORT_PROTOCOL),
    "EFI_SMM_SYSTEM_TABLE2.SmmInstallProtocolInterface":
        (_process_single_call, 'rdx', 'r9', project.EXPORT_PROTOCOL),
    "EFI_SMM_RUNTIME_PROTOCOL.InstallProtocolInterface":
        (_process_single_call, 'rdx', 'r9', project.EXPORT_PROTOCOL),
    "EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces":
        (_process_install_multiple_call, None, None, project.EXPORT_PROTOCOL),
    "EFI_SMM_RUNTIME_PROTOCOL.InstallMultipleProtocolInterfaces":
        (_process_install_multiple_call, None, None, project.EXPORT_PROTOCOL),
}
