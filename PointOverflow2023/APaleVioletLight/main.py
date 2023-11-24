from math import pow

e= 5039

# Prime factors are 5807 x 5861
# https://www.calculatorsoup.com/calculators/math/prime-factors.php
N = 34034827
p = 5807
q = 5861

C = '933969 15848125 24252056 5387227 5511551 10881790 3267174 14500698 28242580 933969 32093017 18035208 2594090 2594090 9122397 21290815 15930721 4502231 5173234 21290815 23241728 2594090 21290815 18035208 10891227 15930721 202434 202434 21290815 5511551 202434 4502231 5173234 25243036'

# Use Euclidean Algorithm to find the private key
# https://www.baeldung.com/cs/prime-numbers-cryptography
# https://math.stackexchange.com/questions/114140/how-to-calclulate-multiplicative-inverse-of-e-mod-phin

# phi_n = 34023160 = (5807-1) x (5861-1)
# e = 5039
# 34023160 = 6751 * 5039 + 4871
# 5039 = 1 * 4871 + 168
# 4871 = 28 * 168 + 167
# 168 = 1 * 167 + 1
# End because 167 % 1 = 0

# Backtrack to write 1 as a linear combination of 34023160 and 5039:
# 1 = 168 - 1 * 167
#   = 168 - 1 * (4871 - 28 * 168)
#   = 168 - 4871 + 28 * 168
#   = 29 * 168 - 4871
#   = 29 * (5039 - 1 * 4871) - 4871
#   = 29 * 5039 - 30 * 4871
#   = 29 * 5039 - 30 * (34023160 - 6751 * 5039)
#   = 29 * 5039 - 30 * 34023160 + 30 * 6751 * 5039
#   = 202559 * 5039 - 30 * 34023160
# Our private key is 202559
# d is -30 but in this case not relevant

priv_key = 202559
test = 'test'
print(test.encode())
init = ''
encoded = ''
decoded = ''
byte_array = []
for b in test.encode():
    init = init + ' ' + str(b)
    enc = (b**e) % N
    encoded = encoded + ' ' + str(enc)
    dec = (enc ** priv_key) % N
    decoded = decoded + ' ' + str(dec)
    byte_array = byte_array + [dec]
print('Initial String: ' + init)
print('Endcoded String: ' + encoded)
print('Decoded String: ' + decoded)
print(bytes(byte_array).decode())
print()

C_array = C.split(' ')
byte_array = []
for c in C_array:
    dec = (int(c) ** priv_key) % N    
    byte_array = byte_array + [dec]
print(bytes(byte_array).decode().replace(' ', '_'))
#poctf{uwsp_533k_4nd_y3_5h411_f1nd}
#print(bytes(test, 'utf-8'))

