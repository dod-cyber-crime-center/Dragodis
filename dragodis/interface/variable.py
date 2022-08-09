'''
Program Variable
'''

from abc import abstractmethod, ABCMeta
from dragodis.interface.data_type import DataType


class Variable(metaclass=ABCMeta):
    """Function Local/Global Variable"""

    def __str__(self) -> str:
        return f"{self.data_type} {self.name}"

    def __repr__(self) -> str:
        return f"<Variable {self} - size={self.size}>"

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

    def __str__(self) -> str:
        return f"0x{self.address:08x}: {super().__str__()}"

    def __repr__(self) -> str:
        return f"<GlobalVariable {self} - size={self.size}>"

    @property
    @abstractmethod
    def address(self) -> int:
        """
        Address where the variable data is mapped to.
        """


class StackVariable(Variable, metaclass=ABCMeta):
    """Function Stack/Local Variable"""

    def __str__(self) -> str:
        return f"stack[0x{self.stack_offset:x}]: {super().__str__()}"

    def __repr__(self) -> str:
        return f"<StackVariable {self} - size={self.size}>"

    @property
    @abstractmethod
    def stack_offset(self) -> int:
        """
        The stack offset if variable is in a stack frame.
        NOTE: We are considered the stack when initially inside the function.
        ie. stack offset of zero would contain the return address followed by
        the arguments if incrementing.
        """
