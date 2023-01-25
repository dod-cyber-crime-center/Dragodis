
from __future__ import annotations
from typing import List, Union, TYPE_CHECKING

from dragodis.ghidra.data_type import GhidraDataType
from dragodis.ghidra.function_argument_location import (
    GhidraArgumentLocation, GhidraStackLocation,
    GhidraRegisterLocation, GhidraRegisterPairLocation, GhidraRelativeRegisterLocation, GhidraStaticLocation
)
from dragodis.interface.function_signature import FunctionSignature, FunctionParameter
from dragodis.exceptions import NotExistError

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra.flat import GhidraFlatAPI


class GhidraFunctionSignature(FunctionSignature):

    def __init__(self, ghidra: GhidraFlatAPI, function: "ghidra.program.model.listing.Function"):
        self._ghidra = ghidra
        self._function = function
        if not self._is_fully_defined():
            self._complete_function_signature()

    @property
    def name(self) -> str:
        return self._function.getSignature().getName()

    @property
    def declaration(self) -> str:
        # Including calling convention to be consistent with IDA.
        return self._function.getSignature().getPrototypeString(True)

    @property
    def calling_convention(self) -> str:
        cc = self._function.getCallingConvention()
        if cc is None:
            return ""
        return cc.getName()

    @calling_convention.setter
    def calling_convention(self, name: str):
        if not name.startswith("__"):
            name = f"__{name}"
        from ghidra.util.exception import InvalidInputException
        try:
            self._function.setCallingConvention(name.lower())
        except InvalidInputException as e:
            raise ValueError(e)

    @property
    def return_type(self) -> GhidraDataType:
        return GhidraDataType(self._function.getReturnType())

    @return_type.setter
    def return_type(self, data_type: Union[GhidraDataType, str]):
        from ghidra.program.model.symbol import SourceType
        if isinstance(data_type, str):
            data_type = self._ghidra.get_data_type(data_type)
        self._function.setReturnType(data_type._data_type, SourceType.USER_DEFINED)

    @property
    def parameters(self) -> List[FunctionParameter]:
        return [
            GhidraFunctionParameter(self, parameter)
            for parameter in self._function.getParameters()
        ]

    def _generate_parameter(self, data_type: str) -> "ghidra.program.model.listing.Parameter":
        """
        Generates a Ghidra Parameter objects from declaration.
        """
        from ghidra.program.model.listing import ParameterImpl
        from ghidra.program.model.symbol import SourceType

        data_type = self._ghidra.get_data_type(data_type)._data_type
        return ParameterImpl(
            "",
            data_type,
            self._function.getEntryPoint(),
            self._ghidra._program,
            SourceType.USER_DEFINED
        )

    def replace_parameters(self, data_types: List[str]):
        parameters = [self._generate_parameter(data_type) for data_type in data_types]
        self._set_parameters(parameters)

    def _set_parameters(self, parameters: List["ghidra.program.model.listing.Parameter"]):
        from ghidra.program.model.listing.Function import FunctionUpdateType
        from ghidra.program.model.symbol import SourceType
        self._function.replaceParameters(
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            False,
            SourceType.USER_DEFINED,
            parameters,
        )

    def add_parameter(self, data_type: str) -> GhidraFunctionParameter:
        from ghidra.program.model.symbol import SourceType
        new_param = self._generate_parameter(data_type)
        new_param = self._function.addParameter(new_param, SourceType.USER_DEFINED)
        return GhidraFunctionParameter(self, new_param)

    def remove_parameter(self, ordinal: int):
        num_parameters = self._function.getParameterCount()
        if ordinal < 0:
            ordinal += num_parameters
        if ordinal not in range(num_parameters):
            raise NotExistError(f"Invalid ordinal for parameter deletion: {ordinal}")
        self._function.removeParameter(ordinal)

    def insert_parameter(self, ordinal: int, data_type: str) -> GhidraFunctionParameter:
        num_parameters = self._function.getParameterCount()
        if ordinal < 0:
            ordinal += num_parameters
        if ordinal not in range(num_parameters):
            raise ValueError(f"Invalid ordinal for parameter insertion: {ordinal}")
        from ghidra.program.model.symbol import SourceType
        new_param = self._generate_parameter(data_type)
        new_param = self._function.insertParameter(ordinal, new_param, SourceType.USER_DEFINED)
        return GhidraFunctionParameter(self, new_param)

    def _is_fully_defined(self):
        """
        Checks if the function signature has already been set
        """
        from ghidra.program.model.symbol import SourceType
        source = self._function.getSignatureSource()
        return source.isHigherPriorityThan(SourceType.DEFAULT)

    def _complete_function_signature(self):
        """
        Decompiles the function to detect and add any missing arguments.
        Function arguments are usually missing when a custom calling convention
        is used or when the function signature has not been committed.
        """
        decomp = self._decompile()
        if decomp is None or not decomp.decompileCompleted():
            return

        from ghidra.program.model.data import Undefined
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        unresolved_params = [p for p in self._get_unresolved_parameters(decomp)]

        program = self._ghidra._program

        params = []

        # collect the existing parameters
        high_proto = decomp.getHighFunction().getFunctionPrototype()
        for i in range(high_proto.getNumParams()):
            sym = high_proto.getParam(i)
            storage = sym.getStorage()
            dt = Undefined.getUndefinedDataType(sym.getSize())
            param = ParameterImpl(None, dt, storage, program)
            params.append(GhidraFunctionParameter(self, param))

        if not unresolved_params:
            # no custom storage
            # set the parameters and return
            self._set_parameters([param._parameter for param in params])
            return

        # add the detected missing parameters to the signature
        for unresolved_param in unresolved_params:
            storage = unresolved_param.getStorage()
            dt = Undefined.getUndefinedDataType(unresolved_param.getSize())
            param = ParameterImpl(None, dt, storage, program)
            params.append(GhidraFunctionParameter(self, param))

        # sort them so parameter ordering is consistent
        params.sort(key=lambda param: param.location)

        # fetch the original Ghidra parameter types
        params = [param._parameter for param in params]

        CUSTOM_STORAGE = Function.FunctionUpdateType.CUSTOM_STORAGE
        self._function.setCustomVariableStorage(True)
        self._function.replaceParameters(CUSTOM_STORAGE, True, SourceType.USER_DEFINED, *params)

    def _decompile(self):
        ghidra = self._ghidra
        return ghidra._decomp_api.decompiler.decompileFunction(self._function, 0, ghidra._monitor)

    def _get_unresolved_parameters(self, decomp):
        high_function = decomp.getHighFunction()
        if not high_function:
            return
        for sym in high_function.getLocalSymbolMap().getSymbols():
            name = sym.getName()

            # unaff_ may be problematic and may indicate an unconventional output somewhere
            if not (name.startswith("in_") or name.startswith("unaff_")):
                continue
            if name in ("in_FS_OFFSET", "in_GS_OFFSET"):
                # these are pseudo registers and are never parameters
                continue
            yield sym


# TODO: Parameter should have an option to get a "Variable" object which represents the location?
class GhidraFunctionParameter(FunctionParameter):

    def __init__(self, signature: GhidraFunctionSignature, parameter: "ghidra.program.model.listing.Parameter"):
        super().__init__(signature)
        self.signature: GhidraFunctionSignature
        self._ghidra = signature._ghidra
        self._parameter = parameter
        self._function = signature._function

    def __eq__(self, other):
        return (
            isinstance(other, GhidraFunctionParameter)
            and self._parameter.isEquivalent(other._parameter)
        )

    @property
    def name(self) -> str:
        return self._parameter.getName()

    @name.setter
    def name(self, new_name: str):
        from ghidra.program.model.symbol import SourceType
        self._parameter.setName(new_name, SourceType.USER_DEFINED)

    @property
    def ordinal(self) -> int:
        return self._parameter.getOrdinal()

    @property
    def size(self) -> int:
        return self._parameter.getLength()

    @property
    def data_type(self) -> GhidraDataType:
        return GhidraDataType(self._parameter.getDataType())

    @data_type.setter
    def data_type(self, new_type: Union[str, GhidraDataType]):
        from ghidra.program.model.symbol import SourceType
        if isinstance(new_type, str):
            new_type = self._ghidra.get_data_type(new_type)
        self._parameter.setDataType(new_type._data_type, SourceType.USER_DEFINED)

    @property
    def declaration(self) -> str:
        return str(self._parameter)

    @property
    def location(self) -> GhidraArgumentLocation:
        storage = self._parameter.getVariableStorage()

        if storage.isStackStorage():
            return GhidraStackLocation(self._function, storage)
        elif storage.isRegisterStorage():
            return GhidraRegisterLocation(self._function, storage)
        elif storage.isCompoundStorage() and len(storage.getRegisters()) == 2:
            return GhidraRegisterPairLocation(self._function, storage)
        # TODO: I'm guessing on this one, need to find a sample to test this.
        elif (
            storage.isCompoundStorage()
            and storage.getVarnodeCount() == 2
            and storage.getFirstVarnode().isRegister()
            and storage.getLastVarnode().isConstant()
        ):
            return GhidraRelativeRegisterLocation(self._function, storage)
        elif storage.isMemoryStorage():
            return GhidraStaticLocation(self._function, storage)
        else:
            raise ValueError(f"Unsupported argument location type: {storage}")
