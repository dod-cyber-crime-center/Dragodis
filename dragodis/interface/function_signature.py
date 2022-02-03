
from __future__ import annotations
import abc
from typing import List, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from dragodis.interface.data_type import DataType
    from dragodis.interface.function_argument_location import ArgumentLocation


# TODO: Add support for getting return type.
class FunctionSignature(metaclass=abc.ABCMeta):
    """
    Interface for a function signature.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        The demangled name of the function.
        """

    @property
    @abc.abstractmethod
    def declaration(self) -> str:
        """
        The full function declaration.
        """

    @property
    def parameters(self) -> List[FunctionParameter]:
        """
        List of parameters in the function signature.
        """

    @property
    def parameter_types(self) -> List[str]:
        """
        Convenience function for getting the parameter data types.
        This is useful when modifying the parameters.
        """
        return [param.data_type.name for param in self.parameters]

    @abc.abstractmethod
    def replace_parameters(self, data_types: List[str]):
        """
        Replaces the parameters of the signature with the ones given.

        :param data_types: List of strings representing the data types for new parameter.
        """

    @abc.abstractmethod
    def add_parameter(self, data_type: str) -> FunctionParameter:
        """
        Adds a parameter to the end of the signature set to given data type.

        :param data_type: Data type of new parameter.
        :returns: New parameter created.
        """

    @abc.abstractmethod
    def remove_parameter(self, ordinal: int):
        """
        Removes the parameter at the given ordinal.

        :param ordinal: Index of parameter
            (if negative, ordinal is relative to number of parameters)
        :raises NotExistError: If parameter at given ordinal doesn't exist.
        """

    @abc.abstractmethod
    def insert_parameter(self, ordinal: int, data_type: str) -> FunctionParameter:
        """
        Inserts a parameter at the given index set with the given data type.

        :param ordinal: Index of parameter
            (if negative, ordinal is relative to number of parameters)
        :param data_type: Data type of new parameter.
        :raises ValueError: If ordinal is out of range.
        :returns: New parameter created.
        """


class FunctionParameter(metaclass=abc.ABCMeta):
    """
    Interface for a parameter from a FunctionSignature
    """

    def __init__(self, signature: FunctionSignature):
        self.signature = signature

    # TODO: Provide ability to change name?
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Name of the parameter
        """

    @name.setter
    @abc.abstractmethod
    def name(self, new_name: str):
        """
        Sets name for the parameter.
        """

    @property
    @abc.abstractmethod
    def ordinal(self) -> int:
        """
        Index position within the signature.
        """

    @property
    def size(self) -> int:
        """
        The size of the parameter based on data type.
        """
        return self.data_type.size

    @property
    @abc.abstractmethod
    def data_type(self) -> DataType:
        """
        Data type for the parameter.
        """

    @data_type.setter
    @abc.abstractmethod
    def data_type(self, new_type: Union[str, DataType]):
        """
        Sets the data type for the parameter.

        :param new_type: Either a string or DataType object.
        """

    @property
    @abc.abstractmethod
    def declaration(self) -> str:
        """
        The parameter declaration as seen in the function signature.
        """

    @property
    @abc.abstractmethod
    def location(self) -> ArgumentLocation:
        """
        The location where the defined argument would be stored.
        e.g. stack, register, etc.
        """
