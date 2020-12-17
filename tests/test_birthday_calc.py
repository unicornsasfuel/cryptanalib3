import ca3

assert(ca3.birthday_calc(2**32,samples=10000) == 0.011574031737030754)
assert(ca3.birthday_calc(2**32,likelihood=.10) == 30083)
