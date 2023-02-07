
from __future__ import annotations
import logging
import re
from typing import TYPE_CHECKING, List, Union, Optional

from dragodis.ida.data_type import IDADataType
from dragodis.ida.function_argument_location import (
    IDAArgumentLocation, IDAStaticLocation, IDARegisterLocation,
    IDAStackLocation, IDARegisterPairLocation, IDARelativeRegisterLocation
)
from dragodis.interface.function_signature import FunctionSignature, FunctionParameter
from dragodis.exceptions import NotExistError, UnsupportedError

if TYPE_CHECKING:
    import ida_typeinf
    from dragodis.ida.flat import IDAFlatAPI

logger = logging.getLogger(__name__)


class IDAFunctionSignature(FunctionSignature):

    # pulled from ida_typeinf.CM_CC_* constants
    _cc_map = {
        0x10: "__unknown",
        0x20: "__voidarg",
        0x30: "__cdecl",
        0x40: "__ellipsis",
        0x50: "__stdcall",
        0x60: "__Pascal",
        0x70: "__fastcall",
        0x80: "__thiscall",
        0xB0: "__golang",
        0xD0: "__usercall",
        0xE0: "__userpurge",
        0xF0: "__usercall",
    }
    # _cc_map_inv will end up with __usercall as 0xf0, which is the more sensible default
    _cc_map_inv = {name: opcode for opcode, name in _cc_map.items()}

    def __init__(self, ida: IDAFlatAPI, address: int):
        self._address = address
        self._ida = ida
        try:
            self._func_type_data, self._tif = ida._ida_helpers.get_func_type_info(address)
        except RuntimeError:
            raise NotExistError(f"A function signature does not exist at 0x{address:08X}")
        self._parameters: Optional[List[IDAFunctionParameter]] = None

    @property
    def name(self) -> str:
        idc = self._ida._idc

        # (Using get_name() over get_func_name() so it also works for imported functions)
        func_name = idc.get_name(self._address)
        # Demangle name if necessary:
        demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled_name:
            # Strip off the extra junk: 'operator new(uint)' -> 'new'
            match = re.search(r"([^ :]*)\(", demangled_name)
            if not match:
                logger.debug(f"Unable to demangle function name: {demangled_name}")
            else:
                logger.debug(f"Demangled function name {demangled_name} -> {match.group(1)}")
                demangled_name = match.group(1)
            func_name = demangled_name
        return func_name

    @property
    def declaration(self) -> str:
        # There is no way to get the full function declaration directly from IDA with
        # the function name intact. So we have to recreate it.
        # If function doesn't have a name (usually because the function was dynamically created
        # within a register), then we are just going to call it "no_name" so we can still get the
        # function typing to still work.
        return re.sub(r'\(', f' {self.name or "no_name"}(', f'{str(self._tif)};')

    @property
    def calling_convention(self) -> str:
        cc = self._func_type_data.cc & self._ida._ida_typeinf.CM_CC_MASK
        try:
            return self._cc_map[cc]
        except KeyError:
            raise RuntimeError(f"{self} has unexpected calling convention: {hex(cc)}")

    @calling_convention.setter
    def calling_convention(self, name: str):
        if not name.startswith("__"):
            name = f"__{name}"
        name = name.lower()
        try:
            cc = self._cc_map_inv[name]
        except KeyError:
            raise ValueError(f"Invalid calling convention name: {name}")
        # Set calling convention part of cm_t flags.
        cc |= self._func_type_data.cc & (self._ida._ida_typeinf.CM_CC_MASK ^ 0xff)
        self._func_type_data.cc = cc
        self._apply()
        self._parameters = None

    @property
    def return_type(self) -> IDADataType:
        return IDADataType(self._ida, self._func_type_data.rettype)

    @return_type.setter
    def return_type(self, data_type: Union[IDADataType, str]):
        if isinstance(data_type, str):
            data_type = self._ida.get_data_type(data_type)
        self._func_type_data.rettype = data_type._tinfo
        self._apply()

    @property
    def parameters(self) -> List[IDAFunctionParameter]:
        if self._parameters is None:
            self._parameters = [
                IDAFunctionParameter(self, i) for i in range(self._func_type_data.size())
            ]
            if len(self._parameters) <= 1:
                return self._parameters
            if self.calling_convention in ("__usercall", "__userpurge"):
                self._parameters = sorted(self._parameters, key=lambda parameter: parameter.location)
        return self._parameters

    def _apply(self):
        """
        Applies changes to func_type_data back to the IDB database.
        """
        self._func_type_data, self._tif = self._ida._ida_helpers.apply_func_type_data(self._address, self._func_type_data)

    def replace_parameters(self, data_types: List[str]):
        # Easiest way to replace all parameters is to set the function type itself.
        # Since IDA doesn't give us names, we are just going to name the arguments ourselves
        # as "a1" where 1 is the index of the parameter.
        parameters = [f"{data_type} a{i}" for i, data_type in enumerate(data_types, start=1)]
        declaration = re.sub(r"\(.*\)", f"({','.join(parameters)})", self.declaration)

        ida_typeinf = self._ida._ida_typeinf
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        func_type_data = ida_typeinf.func_type_data_t()
        ida_typeinf.parse_decl(tif, til, declaration, ida_typeinf.PT_SIL)
        tif.get_func_details(func_type_data)
        self._tif = tif
        self._func_type_data = func_type_data
        self._apply()

        # Reset cache
        self._parameters = None

    def add_parameter(self, data_type: str) -> IDAFunctionParameter:
        # Create new parameter in func_type_data
        data_type = self._ida.get_data_type(data_type)
        new_param = self._ida._ida_typeinf.funcarg_t()
        new_param.type = data_type._tinfo
        self._func_type_data.push_back(new_param)
        self._apply()

        # Update _parameters cache.
        if self._parameters is not None:
            new_param = IDAFunctionParameter(self, len(self._parameters))
            self._parameters.append(new_param)
            return new_param
        else:
            return self.parameters[-1]

    def remove_parameter(self, ordinal: int):
        num_parameters = self._func_type_data.size()
        if ordinal < 0:
            ordinal += num_parameters
        if ordinal not in range(num_parameters):
            raise NotExistError(f"Parameter doesn't exist at ordinal: {ordinal}")
        self._func_type_data.erase(self._func_type_data[ordinal])
        self._apply()

        # Update parameters cache.
        if self._parameters is not None:
            del self._parameters[ordinal]

    def insert_parameter(self, ordinal: int, data_type: str) -> IDAFunctionParameter:
        num_parameters = self._func_type_data.size()
        if ordinal < 0:
            ordinal += num_parameters
        if ordinal not in range(num_parameters):
            raise ValueError(f"Invalid ordinal for parameter insertion: {ordinal}")

        if self.calling_convention in ("__usercall", "__userpurge"):
            raise UnsupportedError("Cannot insert a parameter into a usercall function")

        data_type = self._ida.get_data_type(data_type)
        new_param = self._ida._ida_typeinf.funcarg_t()
        new_param.type = data_type._tinfo
        # Getting an element actually gives back a funcarg_t iterator currently
        # pointing at the element, which is what we want to be able to use the
        # C++ vector object.
        it = self._func_type_data[ordinal]
        self._func_type_data.insert(it, new_param)
        self._apply()

        # Update parameters cache.
        if self._parameters is not None:
            new_param = IDAFunctionParameter(self, ordinal)
            self._parameters.insert(ordinal, new_param)
            for i, param in enumerate(self._parameters):
                param._ordinal = i
            return new_param
        else:
            return self.parameters[ordinal]


class IDAFunctionParameter(FunctionParameter):
    """
    Interface for a parameter from a FunctionSignature
    """

    def __init__(self, signature: IDAFunctionSignature, ordinal: int):
        # NOTE: While it may look weird that there is no argument specific stuff here, that
        # is because the signature will keep track of the ordinal for us, which gives
        # us the information to obtain everything else.
        # This allows us to dynamically change the ordinal of the parameter based on signature.
        super().__init__(signature)
        self._ida = signature._ida
        self._ordinal = ordinal

    @property
    def _funcarg(self) -> "ida_typeinf.funcarg_t":
        return self.signature._func_type_data[self.ordinal]

    @property
    def name(self) -> str:
        return self._funcarg.name

    @name.setter
    def name(self, new_name: str):
        self._funcarg.name = new_name
        self.signature._apply()

    @property
    def ordinal(self) -> int:
        return self._ordinal

    @property
    def data_type(self) -> IDADataType:
        return IDADataType(self._ida, self._funcarg.type)

    @data_type.setter
    def data_type(self, new_type: Union[str, IDADataType]):
        if isinstance(new_type, str):
            new_type = self._ida.get_data_type(new_type)
        self._funcarg.type = new_type._tinfo
        self.signature._apply()

    @property
    def declaration(self) -> str:
        return f"{self._funcarg.type} {self._funcarg.name}"

    @property
    def location(self) -> IDAArgumentLocation:
        argloc = self._funcarg.argloc
        if argloc.is_stkoff():
            return IDAStackLocation(self._ida, argloc, self.data_type.size)
        elif argloc.is_reg1():
            return IDARegisterLocation(self._ida, argloc, self.data_type.size)
        elif argloc.is_reg2():
            return IDARegisterPairLocation(self._ida, argloc, self.data_type.size)
        elif argloc.is_rrel():
            return IDARelativeRegisterLocation(self._ida, argloc, self.data_type.size)
        elif argloc.is_ea():
            return IDAStaticLocation(self._ida, argloc, self.data_type.size)
        else:
            raise ValueError(f"Unsupported argument location type: {argloc.atype()}")
