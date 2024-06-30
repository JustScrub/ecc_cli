
raise ImportError("Not yet implemented")

from forbiddenfruit import curse
from ecc_imp import ecc
import ecpy, ecpy.curves

counters = {}
orig_ops = [int.__add__, int.__mul__, int.__neg__, pow]

def count_operation(operation):
    counters[operation.__name__] = 0
    def wrapper(*args):
        counters[operation.__name__] += 1
        return operation(*args)
    return wrapper

curse(int, '__add__', count_operation(int.__add__))
curse(int, '__mul__', count_operation(int.__mul__))
curse(int, '__neg__', count_operation(int.__neg__))
curse(int, "ble", lambda a,b: f"{a} {b}")
pow = count_operation(pow)

a = (1890760).__add__(1)
b = 2 * 2
c = 3 - 3
d = 4**4
pow(5, 5)
print((3).ble(4))

print(a,b,c,d)
print(counters)