#!/usr/bin/env python

# Copyright 2013 bonsaiviking
# Copyright 2018 Ben Wiederhake
# Implied automatic Github license

import struct

# -------------------
#     SHA1
# -------------------

'''
def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

class SHA1:
    def __init__(self, data=b'', a=0x67452301, b=0xEFCDAB89, c=0x98BADCFE, d=0x10325476, e=0xC3D2E1F0):
        self.h = [a, b, c, d, e]
        self.remainder = data
        self.count = 0

    def _add_chunk(self, chunk):
        self.count += 1
        w = list( struct.unpack(">16I", chunk) + (None,) * (80-16) )
        for i in range(16, 80):
            n = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w[i] = leftrotate(n, 1)
        a,b,c,d,e = self.h
        for i in range(80):
            f = None
            k = None
            if i < 20:
                f = (b & c) ^ (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a,5) + f + e + k + w[i]) % 2**32
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
        self.h[0] = (self.h[0] + a) % 2**32
        self.h[1] = (self.h[1] + b) % 2**32
        self.h[2] = (self.h[2] + c) % 2**32
        self.h[3] = (self.h[3] + d) % 2**32
        self.h[4] = (self.h[4] + e) % 2**32

    def add(self, data, payload_length=0):
        message = self.remainder + data
        r = len(message) + payload_length % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b''
        for chunk in range(0, len(message) + payload_length -r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def hexdigest(self):
        l = len(self.remainder) + 64 * self.count
        self.add( b'\x80' + b'\x00' * ((55 - l) % 64) + struct.pack(">Q", l * 8) )
        h = tuple(x for x in self.h)
        self.__init__()
        return '%08x%08x%08x%08x%08x' % h
'''

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

class SHA1:
    def __init__(self, data=b'', a=0x67452301, b=0xEFCDAB89, c=0x98BADCFE, d=0x10325476, e=0xC3D2E1F0):
        self.h = [a, b, c, d, e]
        self.remainder = data
        self.count = 0

    def _add_chunk(self, chunk):
        self.count += 1
        w = list( struct.unpack(">16I", chunk) + (None,) * (80-16) )
        for i in range(16, 80):
            n = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w[i] = leftrotate(n, 1)
        a,b,c,d,e = self.h
        for i in range(80):
            f = None
            k = None
            if i < 20:
                f = (b & c) ^ (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a,5) + f + e + k + w[i]) % 2**32
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
        self.h[0] = (self.h[0] + a) % 2**32
        self.h[1] = (self.h[1] + b) % 2**32
        self.h[2] = (self.h[2] + c) % 2**32
        self.h[3] = (self.h[3] + d) % 2**32
        self.h[4] = (self.h[4] + e) % 2**32

    def add(self, data):
        
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b''
        for chunk in range(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def finish(self, payload_length=0):
        l = len(self.remainder) + payload_length + 64 * self.count
        self.add( b'\x80' + b'\x00' * ((55 - l) % 64) + struct.pack(">Q", l * 8) )
        h = tuple(x for x in self.h)
        self.__init__()
        return '%08x%08x%08x%08x%08x' % h

def sha1(data):
    return SHA1().add(data).finish()

def extend(data, payload_length, a, b, c, d, e):
    return SHA1(b'', a, b, c, d, e).add(data).finish(payload_length)

# -------------------
#     MD4
# -------------------


def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, data=b'', h=[ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], size=0):
        self.remainder = data
        self.count = size
        self.h = h

    def _add_chunk(self, chunk):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in range(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in range(16):
            i = (16-r)%4
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in range(16):
            i = (16-r)%4
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in range(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def digest(self):
        l = len(self.remainder) + 64 * self.count
        self.add( b'\x80' + b'\x00' * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
        out = struct.pack("<4I", *self.h)
        self.__init__()
        return out

    def hexdigest(self):
        l = len(self.remainder) + 64 * self.count
        self.add( b'\x80' + b'\x00' * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
        out = '%08x%08x%08x%08x' % tuple(self.h)
        self.__init__()
        return out

