
class ImmediateValue(object):
    def __init__(self, value):
        self.__value = value

    def __str__(self):
        return str(self.__value)

    def __repr__(self):
        return "ImmediateValue(%s)" % repr(self.__value)

    def __hash__(self):
        return hash(self.__value)

    def __eq__(self, other):
        if isinstance(other, ImmediateValue):
            return self.__value == other.__value
        elif isinstance(other, int):
            return self.__value == other
        raise NotImplementedError

    def __ne__(self, other):
        return not self == other

    @property
    def value(self):
        return self.__value
