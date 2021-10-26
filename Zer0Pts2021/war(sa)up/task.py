from Crypto.Util.number import getStrongPrime, GCD, long_to_bytes
from random import randint
import os

def pad(m: int, n: int):
  # PKCS#1 v1.5 maybe
  ms = m.to_bytes((m.bit_length() + 7) // 8, "big")
  ns = n.to_bytes((n.bit_length() + 7) // 8, "big")
  #assert len(ms) <= len(ns) - 11

  ps = b""
  while len(ps) < len(ns) - len(ms) - 3:
    p = os.urandom(1)
    if p != b"\x00":
      ps += p
  return int.from_bytes(b"\x00\x02" + ps + b"\x00" + ms, "big")

n = 113135121314210337963205879392132245927891839184264376753001919135175107917692925687745642532400388405294058068119159052072165971868084999879938794441059047830758789602416617241611903275905693635535414333219575299357763227902178212895661490423647330568988131820052060534245914478223222846644042189866538583089
e = 1337
#n = 50590938594854950010326878349157
#e = 5
#n = 3337
#e = 79
m = pad(int.from_bytes("Test_Message".encode(), "big"), n)
#m = int.from_bytes(b't', "big")
c1 = pow(m, e, n)

s = 1
while True:
  c_prime = ((s ** e) * c1) % n
  result = long_to_bytes(c_prime)
  if result[0] == 2 and result[1] == 0 and b'\x00' in result[2:]:
    print("s = {}".format(s))
    print("c_prime = {}".format(c_prime))
    print("result = {}".format(result))
    print()
    break
  s = s + 1



while True:
  p = getStrongPrime(512)
  q = getStrongPrime(512)
  n = p * q
  phi = (p-1)*(q-1)
  e = 1337
  if GCD(phi, e) == 1:
    break

n = 113135121314210337963205879392132245927891839184264376753001919135175107917692925687745642532400388405294058068119159052072165971868084999879938794441059047830758789602416617241611903275905693635535414333219575299357763227902178212895661490423647330568988131820052060534245914478223222846644042189866538583089
m = pad(int.from_bytes("Test_Message".encode(), "big"), n)

c1 = pow(m, e, n)
c2 = pow(m // 2, e, n)

print("n =", n)
print("e =", e)
print("c1=", c1)
print("c2=", c2)


