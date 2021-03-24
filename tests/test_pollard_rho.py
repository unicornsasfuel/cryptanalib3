import ca3 as ca


g = 19
h = 24717
Fp = 48611

res = ca.pollard_rho(g, h, Fp)

assert(res == 37869)

