'''
Program Variable
'''

from abc import abstractmethod, ABCMeta
from dragodis.interface.data_type import DataType


class Variable(metaclass=ABCMeta):
    """Function Local/Global Variable"""

    @property
    @abstractmethod
    def name(self) -> str:
        """The variable's name"""

    @name.setter
    @abstractmethod
    def name(self, new_name: str):
        """Sets the variable's name"""

    @property
    @abstractmethod
    def size(self) -> int:
        """The variable's size"""

    @property
    @abstractmethod
    def data_type(self) -> DataType:
        """The variable's type"""

    # @data_type.setter
    # @abstractmethod
    # def data_type(self, data_type: DataType):
    #     """Sets the variable's data type"""


class GlobalVariable(Variable, metaclass=ABCMeta):
    """Global variable usually defined in the .data section."""

    @property
    @abstractmethod
    def address(self) -> int:
        """
        Address where the variable data is mapped to.
        """


class StackVariable(Variable, metaclass=ABCMeta):
    """Function Stack/Local Variable"""

    @property
    @abstractmethod
    def stack_offset(self) -> int:
        """
        The stack offset if variable is in a stack frame.
        NOTE: We are considered the stack when initially inside the function.
        ie. stack offset of zero would contain the return address followed by
        the arguments if incrementing.
        """
