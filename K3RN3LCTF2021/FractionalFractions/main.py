from Cryptodome.Util.number import bytes_to_long, long_to_bytes

#flag = str(bytes_to_long(open('flag.txt','rb').read()))
flag = str(bytes_to_long('flag{f0r_l00ps_g0_brrrrr}'.encode()))
from fractions import Fraction
enc = Fraction(0/1)
for c in flag:
    enc += Fraction(int(c)+1)
    enc = 1/enc
    print(enc)
print()

#enc = Fraction(7817806454609461952471483475242846271662326,63314799458349217804506955537187514185318043)
possible_chars = [0,1,2,3,4,5,6,7,8,9]
byte_flag = ''
while enc > 0:
    enc = 1 / enc
    # Index of the smallest positive value corresponds to the byte at the current position
    enc_list = [enc - Fraction(c+1) for c in possible_chars]
    min_value = min(i for i in enc_list if i >= 0)
    min_index = enc_list.index(min_value)
    byte_flag = str(min_index) + byte_flag
    enc = enc_list[min_index]
    print(enc)
print(long_to_bytes(int(byte_flag)))