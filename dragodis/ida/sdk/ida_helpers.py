"""
This package contains miscellaneous helper functions that are to be run natively in IDA.
These are usually implemented here to improve performance or deal with weird
function callback mechanics.
(This is not a real module in the IDA SDK.)
"""
import logging
import re
from typing import Iterable, Tuple, List, Optional

import idc
import ida_ida
import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_name
import ida_typeinf
import ida_ua
import idautils


logger = logging.getLogger(__name__)


def iter_imports(_target=None) -> Iterable[Tuple[int, Optional[int], str, str]]:
    """
    Iterates the imports, returning the address function name and namespace
    for the import.

    :param _target: Internally used to extract a specific import.

    :yields: (address, thunk_address or None, func_name, namespace)
    """
    for i in range(ida_nalt.get_import_module_qty()):
        namespace = ida_nalt.get_import_module_name(i)

        entries = []

        def callback(addr, name, ordinal):
            if name:
                # Name will include a "__imp_" prefix if the import is accessed through
                # a thunk function.
                # Pull the address of the thunk function as well.
                thunk_addr = None
                raw_name = ida_name.get_name(addr)
                if raw_name.startswith("__imp_"):
                    for xref in idautils.XrefsTo(addr):
                        func = ida_funcs.get_func(xref.frm)
                        if func and func.flags & ida_funcs.FUNC_THUNK:
                            # Pull thunk address and swap name for a better one without the "__imp_" prefix.
                            thunk_addr = func.start_ea
                            name = ida_funcs.get_func_name(thunk_addr)
                            break
                    else:
                        raise RuntimeError(f"Failed to find a thunk for {name} at 0x{addr:08X}")

                if _target and name != _target:
                    return True  # continue enumeration
                entries.append((addr, thunk_addr, name))
                if _target and name == _target:
                    return False  # target found, stop enumeration

            return True  # continue enumeration

        ida_nalt.enum_import_names(i, callback)

        for addr, thunk_addr, name in entries:
            yield addr, thunk_addr, name, namespace


def get_import(name: str) -> Optional[Tuple[int, int, str, str]]:
    """
    Gets import for given name.
    """
    for address, thunk_address, import_name, namespace in iter_imports(_target=name):
        return address, thunk_address, import_name, namespace


def iter_exports() -> Iterable[Tuple[int, str]]:
    """
    Iterate API exports.

    :yield: (ea, name)
    """
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        yield ea, name


def get_byte_chunks(address: int, size: int) -> Iterable[Tuple[int, int]]:
    """
    Iterates the chunks of defined bytes found within the given address range.

    :param address: Starting address.
    :param size: Size of address range.
    :yields: Tuples of chunks of (address, size)
    """
    if size == 0:
        return
    elif size < 0:
        raise ValueError(f"Size must be positive. Got {size}")

    start = address
    end = start + size

    if not ida_bytes.is_loaded(address):
        address = ida_bytes.next_inited(address, end)

    chunk_start = address
    while address != idc.BADADDR:
        prev_address = address
        # Get the next address that has a byte with is_loaded() == True
        address = ida_bytes.next_inited(address, end)
        if address != prev_address + 1:
            # Found a hole.
            yield chunk_start, prev_address - chunk_start + 1
            chunk_start = address


def get_all_byte_chunks() -> Iterable[Tuple[int, int]]:
    """
    Iterates all chunks of defined bytes in the sample.
    """
    start = ida_ida.inf_get_min_ea()
    end = ida_ida.inf_get_max_ea()
    yield from get_byte_chunks(start, end - start)


def get_bytes(address: int, size: int, default: int = 0) -> bytes:
    """
    Obtains bytes from given address.
    Replaces non-loaded data with 0 byte.

    :param address: Address to pull bytes from.
    :param size: Number of bytes to pull.
    :param default: Default byte to provide if not loaded.
    :returns: obtained bytes
    """
    if default == 0:
        data = bytearray(size)
    else:
        data = bytearray([default] * size)

    start = address
    for address, size in get_byte_chunks(address, size):
        offset = address - start
        data[offset:offset + size] = ida_bytes.get_bytes(address, size)

    return bytes(data)


def revert_bytes(address: int, size: int):
    """
    Reverts patched bytes back to the underlying data.

    :param address: Address to start reverting bytes.
    :param size: Number of bytes to revert.
    """
    for offset in range(address, address + size):
        ida_bytes.revert_byte(offset)


def is_loaded(address: int, size: int) -> bool:
    """
    Checks if all bytes are loaded.

    :param address: Address of first byte.
    :param size: Number of bytes to check.
    """
    return all(ida_bytes.is_loaded(offset) for offset in range(address, address + size))


def get_instruction(address: int) -> ida_ua.insn_t:
    """
    Obtains insn_t object for instruction.
    """
    insn_t = ida_ua.insn_t()
    if ida_ua.decode_insn(insn_t, address):
        return insn_t


def get_operands(address: int) -> List[Tuple[int, ida_ua.op_t]]:
    """
    Obtains operands for instruction at given address.
    """
    insn = get_instruction(address)

    ret = []
    ops = insn.ops
    o_void = ida_ua.o_void
    for index, op in enumerate(ops):
        if op.type == o_void:
            break  # no more operands

        ret.append((index, op))

    return ret


def _get_tif_with_hex_rays(address: int) -> Optional[ida_typeinf.tinfo_t]:
    """
    Attempt to get the tinfo_t object for the function using the Hex-Rays decompiler plugin.

    :raises: RuntimeError on failure.
    :returns: tinfo_t object on success.
    """
    decompiled = decompiled_code(address)
    if not decompiled:
        return None
    tif = ida_typeinf.tinfo_t()
    decompiled.get_func_type(tif)
    return tif


def _get_tif_with_guess_type(address: int) -> Optional[ida_typeinf.tinfo_t]:
    """
    Attempt to get the tinfo_t object for the function using the "guess_type" function.

    :raises: RuntimeError on failure.
    :returns: tinfo_t object on success.
    """
    guessed_type = idc.guess_type(address)
    if guessed_type is None:
        return None

    func_name = idc.get_func_name(address)
    if func_name is None:
        return None

    # Documentation states the type must be ';' terminated, also the function name must be inserted
    guessed_type = re.sub(r"\(", f" {func_name}(", f"{guessed_type};")
    set_type_result = idc.SetType(address, guessed_type)
    if not set_type_result:
        logger.warning(
            f"Failed to SetType for function at 0x{address:X} with guessed type {guessed_type!r}"
        )

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, address):
        return None
    return tif


_seen_func_types = set()

def get_func_type_info(address: int, operand: Tuple[int, int] = None) -> Tuple[ida_typeinf.func_type_data_t, ida_typeinf.tinfo_t]:
    """
    Obtain a idaapi.func_type_data_t object for the function with the provided start address.

    :param address: start address of the function
    :param operand: Optional address and index pair for an operand containing the function address in its value.
        This can be provided when function is dynamically generated at runtime. (e.g. call eax)

    :return: ida_typeinf.func_type_data_t object, ida_typeinf.tinfo_t object

    :raise RuntimeError: if func_type_data_t object cannot be obtained
    """
    func_type = idc.get_type(address)

    # First see if it's a type we already set before.
    if func_type and address in _seen_func_types:
        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tif, address)

    # Otherwise, try to use the Hexrays decompiler to determine function signature.
    # (It's better than IDA's guess_type)
    else:
        # First try to get type information from the decompiled code produced
        # by the Hex Rays plugin.
        tif = _get_tif_with_hex_rays(address)

        if not tif:
            # Otherwise, if IDA's disassembler set it already, go with that.
            if func_type:
                tif = ida_typeinf.tinfo_t()
                ida_nalt.get_tinfo(tif, address)

            # Finally, see if we can obtain it with guess_type()
            else:
                tif = _get_tif_with_guess_type(address)

    if tif:
        func_type_data = ida_typeinf.func_type_data_t()

        # In IDA 7.6, imported functions are now function pointers.
        # To handle this, check if we need to pull out a pointed object first
        if tif.is_funcptr():
            tif = tif.get_pointed_object()

        success = tif.get_func_details(func_type_data)
        if success:
            # record that we have processed this function before. (and that we can grab it from the offset)
            _seen_func_types.add(address)
            func_type_data, tif = apply_func_type_data(address, func_type_data)
            return func_type_data, tif

    # If we have still failed, we have one more trick under our sleeve.
    # Try to pull the type information from the operand of the call instruction.
    # This could be set if the function has been dynamically created.
    if operand:
        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_op_tinfo(tif, operand.address, operand.index)
        func_type_data = ida_typeinf.func_type_data_t()
        success = tif.get_func_details(func_type_data)
        if success:
            func_type_data, tif = apply_func_type_data(address, func_type_data)
            return func_type_data, tif

    raise RuntimeError(f"Failed to obtain func_type_data_t object for offset 0x{address:X}")


def apply_func_type_data(address: int, func_type_data: ida_typeinf.func_type_data_t) -> Tuple[ida_typeinf.func_type_data_t, ida_typeinf.tinfo_t]:
    """
    Applies given func_type_data_t to function pointed by given address.

    :param address: Address of function.
    :param func_type_data: Type information to apply to function.

    :return: Tuple containing newly created func_type_data_t and tinfo_t objects. (Toss the old one)
    """
    # Create new tif and apply.
    tif = ida_typeinf.tinfo_t()
    success = tif.create_func(func_type_data)
    if not success:
        raise RuntimeError(f"Failed to create new function tinfo object.")
    success = ida_typeinf.apply_tinfo(address, tif, ida_typeinf.TINFO_DEFINITE)
    if not success:
        raise RuntimeError(f"Failed to apply function signatures changes.")

    # We also need to create a new func_type_data, because the old one gets
    # borked for some reason.
    func_type_data = ida_typeinf.func_type_data_t()
    success = tif.get_func_details(func_type_data)
    if not success:
        raise RuntimeError(f"Failed to generate new func_type_data object.")

    return func_type_data, tif


def decompiled_code(address: int, _visited=None) -> Optional[ida_hexrays.cfuncptr_t]:
    """
    Generates IDA object representing the decompiled code for the given address.

    :param address: Start address of the function.

    :returns: cfuncptr_t object or None on failure.
    """
    if _visited is None:
        _visited = set()

    attempted_before = address in _visited
    _visited.add(address)

    # This requires Hexrays decompiler, load it and make sure it's available before continuing.
    if not ida_hexrays.init_hexrays_plugin():
        idc.load_and_run_plugin("hexrays", 0) or idc.load_and_run_plugin("hexx64", 0)
    if not ida_hexrays.init_hexrays_plugin():
        logger.debug("Unable to load Hexrays decompiler.")
        return None
    fail_obj = ida_hexrays.hexrays_failure_t()
    try:
        code = ida_hexrays.decompile(address, fail_obj)
    except ida_hexrays.DecompilationFailure as e:
        logger.warning(f"Failed to decompile function: {e}")
        return None
    if code and not fail_obj.code:
        return code

    if not fail_obj:
        logger.warning(f"Unable to decompile function at {hex(address)}")
        return None

    # Cannot possibly recover from call analysis failure.
    if fail_obj.code == -12:
        logger.warning(f"Unable to decompile function at {hex(address)}: call analysis failed")
        return None

    # We may be able to still recover from this by first trying to decompile
    # the called function that caused the failure.
    # If we've attempted this before, ensure we don't try a third time
    # and cause an infinite loop.
    if not attempted_before:
        failed_address = fail_obj.errea
        if ida_ua.ua_mnem(failed_address) == "call":
            call_address = idc.get_operand_value(failed_address, 0)
            if decompiled_code(_visited=_visited) is not None:
                return decompiled_code(address, visited=_visited)

    # TODO: Observed this message pops up with fail_obj.code == 0... unsure if that is actually an error.
    logger.debug(f"Unable to decompile function at {hex(address)}: {fail_obj.code}")
    return None


def get_function_by_name(name: str, ignore_underscore: bool = False) -> Optional[ida_funcs.func_t]:
    """
    Gets function by name (if it exists.)
    """
    for ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(ea)
        if ignore_underscore:
            func_name = func_name.strip("_")
        if func_name == name:
            return ida_funcs.get_func(ea)
