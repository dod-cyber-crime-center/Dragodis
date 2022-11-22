
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

    @property
    def name(self) -> str:
        return self._function.getSignature().getName()

    @property
    def declaration(self) -> str:
        # Including calling convention to be consistent with IDA.
        return self._function.getSignature().getPrototypeString(True)

    @property
    def calling_convention(self) -> str:
        return self._function.getCallingConvention().getName()

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
            GhidraFunctionParameter(self, self._ghidra, parameter)
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
        return GhidraFunctionParameter(self, self._ghidra, new_param)

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
        return GhidraFunctionParameter(self, self._ghidra, new_param)


# TODO: Parameter should have an option to get a "Variable" object which represents the location?
class GhidraFunctionParameter(FunctionParameter):

    def __init__(self, signature: GhidraFunctionSignature, ghidra: GhidraFlatAPI,  parameter: "ghidra.program.model.listing.Parameter"):
        super().__init__(signature)
        self.signature: GhidraFunctionSignature
        self._ghidra = ghidra
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
