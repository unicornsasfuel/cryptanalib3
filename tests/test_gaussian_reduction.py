import ca3 as ca
from Crypto.Util.number import inverse, long_to_bytes


"""
The NTRU cryptosystem is described in chapter 7 section 7.10 of the book
"An introduction to Mathematical Cryptography" By Hoffstein, Pipher, Silverman
As an example of how gaussian reduction and lattices can be used in cryptanalysis.
This test was based on a challenge that uses it.
"""

def decrypt(q, h, f, g, e):
     a = (f*e) % q
     m = (a*inverse(f, g)) % g
     return m

public_key = (9117355109214948325097971154178357440761841339427842510523046107894649996138217287718042134025044437830492938489674119400594835792056766182530177342378063, 2058857668060064659186287538483265259018281309209866244669032667514977933619087474702103680138302455619603159208903939537753744306287470389569939985838397)
encrypted_flag = 8450027006649008029621056638532817968530522347433675096563701980690935659389095211703915553003263192086586340481588532257232269719422853156125419509692609

q_gen, h_gen = public_key

v1 = (1, h_gen)
v2 = (0, q_gen)

(f1, g1), (f2, g2) = ca.gaussian_lattice_reduction(v1, v2)

msg = decrypt(q_gen, h_gen, f1, g1, encrypted_flag)

if(long_to_bytes(msg) != b'gaussian_lattice_reduction_works'):
    raise Exception('Gaussian Reduction broken!')

