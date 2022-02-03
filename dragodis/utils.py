"""
Utility functions used throughout the project.
"""


class cached_property(property):
    """
    A cached_property which allows a setter.
    When the given property is set, this will automatically invalidate the cache.
    Good for read many / write rarely type properties in which the property value
    could only change if the setter was called.

    To invalidate the cache outside of setting the property use del.
        e.g. del obj.thing
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "__cached_" + self.fget.__name__

    def __get__(self, instance, type=None):
        """
        First attempts to pull from cached results before calling fget.
        """
        if instance is None:
            return self
        try:
            return instance.__dict__[self.name]
        except KeyError:
            res = instance.__dict__[self.name] = self.fget(instance)
            return res

    def __set__(self, instance, value):
        """
        Sets new value and invalidates cache.
        """
        self.fset(instance, value)
        self.__delete__(instance)

    def __delete__(self, instance):
        """
        Invalidates cache.
        """
        try:
            del instance.__dict__[self.name]
        except KeyError:
            pass
