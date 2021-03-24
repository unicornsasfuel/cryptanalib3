import ca3 as ca


g = 5448
h = 6909
Fp = 11251

res = ca.pohlig_hellman(g, h, Fp)
assert(res==511)

g = 23
h = 9689
Fp = 11251

res = ca.pohlig_hellman(g, h, Fp)
assert(res==4261)
