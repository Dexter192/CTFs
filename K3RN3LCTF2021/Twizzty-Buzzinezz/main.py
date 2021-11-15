#!/usr/bin/env python3
#
# Polymero
#

# Imports
import os

FLAG = b'flag{...REDACTED...}'
from Cryptodome.Util.number import bytes_to_long, long_to_bytes

class HoneyComb:
    def __init__(self, key):
        self.vals = [i for i in key]

    def turn(self):
        self.vals = [self.vals[-1]] + self.vals[:-1]

    def encrypt(self, msg):
        keystream = []
        while len(keystream) < len(msg):
            keystream += self.vals
            self.turn()
        print(keystream)
        return bytes([msg[i] ^ keystream[i] for i in range(len(msg))]).hex()

    # Knowing that the encrypted string starts with flag{ we can find the first 5 values of the key by finding the corresponding XOR pair such that 63=99^k='f', etc.
    # The full key is [5, 70, 109, 10, 19, 212]
    # The flag is: flag{s1mpl3_X0R_but_w1th_4_tw1zzt}
    def decrypt(self):
        enc = '632a0c6d68a7e5683601394c4be457190f7f7e4ca3343205323e4ca072773c177e6e'
        #key = [255, 127, 224, 83, 49, 220, 220, 255, 127, 224, 83, 49, 49, 220, 255, 127, 224, 83, 83, 49, 220, 255, 127, 224]
        for j in range(212,213):
            key = [5, 70, 109, 10, 19, 0]
            key[-1] = j
            keystream = key
            while len(keystream) < len(enc)//2:
                key = [key[-1]] + key[:-1]
                keystream += key

            dec = ''
            for i in range(0,len(enc),2):
                an_integer = int(enc[i:i+2], 16)
                #hex_value = hex(an_integer)
                dec_val = an_integer ^ keystream[i//2]
                dec += chr(dec_val)
            return dec
hc = HoneyComb(os.urandom(6))

print(hc.vals)
print(hc.encrypt(FLAG))
print(hc.decrypt())


key = [5]