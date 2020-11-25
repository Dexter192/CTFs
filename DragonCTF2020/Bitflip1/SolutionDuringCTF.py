#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime
from bitstring import BitArray
import socket

FLAG = open("flag").read()
FLAG += (16 - (len(FLAG) % 16))*" "

class Decrypt:
  def __init__(self):
    self.alternating = -1
    self.counter = 1
    self.n = 1
    self.seed = 0
    self.iter_inv = 1
    self.iter_inv1 = 1
    self.iter_seed = 1
    self.iter_seed1 = 0

  def get_counter(self):
    self.alternating += 1
    #Return 1 + inv of seed (xor with 1111...)
    if (self.alternating % 2 == 0):
      self.update_seed()
      return self.seed ^ ((1 << self.n+1) - 2)
    #Return seed
    if (self.alternating % 2 == 1):
        return self.seed

  def update_iter(self, curr_iter):
    if (self.alternating % 2 == 0):
      self.iter_inv1 = curr_iter
      return
    if (self.alternating % 2 == 1):
      self.iter_seed = curr_iter
      return

  def update_seed(self):
    if (self.iter_inv1 - self.iter_seed == 1):
      self.seed += 2**self.n
    self.n += 1

class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
    return x & ((1 << num) - 1)


class DiffieHellman:
  def gen_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    while not is_prime(prime):
      iter += 1
      prime = self.rng.getbits(512)
    print("Generated after", iter, "iterations")
    self.iter = iter
    return prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    self.iter = None
    if prime is None:
      prime = self.gen_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x, counter):
  #print("bit-flip str:")
  b = long_to_bytes((1 << 512) - 1)
  #flip_str = base64.b64decode(input().strip())
  print(counter, base64.b64encode(long_to_bytes(counter)))
  flip_str = base64.b64decode(base64.b64encode(long_to_bytes(counter)))
  #flip_str = base64.b64decode(base64.b64encode(long_to_bytes(256)))
  print("bit-flip str: {}".format(flip_str))
  return xor32(flip_str, x)


hostname = 'bitflip1.hackable.software'
port = 1337
init_seed = 323737058686258624099203623673324257396
bob_nr = 1112699670493142467551161853112516433599616213788505762595810516578660318981146291865221796185828576286227780580852448717713071893787085195066740005784076
dec_iv = 'YI0xgAh0eyGoDK6w3vNYyQ=='
enc_flag = '1+Z5oG8lp2V9Krpt4/4SB4oMTT1QLm+rp5zaE3zSk92YFNSM+JBU4YI4ktZzLlYe'
counter = 356827675155618302827545591190212165514
import socket

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    data = s.recv(1024).decode()
    print("Received: {}".format(repr(data)))
    if 'hashcash' in repr(data):
      print('Enter hashcash')
      s.send(input().encode())
      s.send('\n'.encode())

      response = s.recv(4096)
      decrypt = Decrypt()
      while 'bit-flip' in repr(response):
          print(repr(data))
          counter = decrypt.get_counter()
          msg = base64.b64encode(long_to_bytes(counter))
          s.send(msg)
          s.send('\n'.encode())
          response = s.recv(4096)
          print(repr(response))
          iterations = int(repr(response).split(' iterations')[0].split('after ')[1])
          decrypt.update_iter(iterations)
          if (counter >= 2 ** 128):
              init_seed = decrypt.seed
              bob_nr = repr(response).split('number ')[1].split('\\n')[0]
              dec_iv = repr(response).split('\\n')[2]
              enc_flag = repr(response).split('\\n')[3]
              break
    s.shutdown(socket.SHUT_WR)
    print("Closed")
    s.close()
    return counter, init_seed, bob_nr, dec_iv, enc_flag

#counter, init_seed, bob_nr, dec_iv, enc_flag = netcat(hostname, port)

#alice_seed = os.urandom(16)
#alice_seed =  b'\x91\x9biv\x7f\x857?eM\xffn"\x7f\re'
#decrypt = Decrypt()
alice_seed = long_to_bytes(init_seed)

while 1:
  #counter = decrypt.get_counter()
  seed = bit_flip(alice_seed, counter)

  print('Seed: {}'.format(seed))
  alice = DiffieHellman(seed)

  #decrypt.update_iter(alice.iter)

  #bob = DiffieHellman(seed, alice.prime)
  bob = DiffieHellman(os.urandom(16), alice.prime)

  print("bob number", bob.my_number)
  alice.set_other(bob_nr)#bob.my_number)
  bob.set_other(alice.my_number)
  iv = os.urandom(16)
  iv = base64.b64decode(dec_iv)

  print(base64.b64encode(iv).decode())
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  b = bytearray()
  b.extend(map(ord, FLAG))
  #enc_flag = cipher.encrypt(b)
  #print(base64.b64encode(enc_flag).decode())

  cipher1 = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  dec_flag = cipher1.decrypt(base64.b64decode(enc_flag))
  #dec_flag = cipher1.decrypt(enc_flag)
  print(dec_flag)
  print()
  if(counter >= 2**128):
    break

print('Done')
print('Real seed: {}'.format(bytes_to_long(alice_seed)))
print('Decrypted Seed: {}'.format(decrypt.seed))
print('Difference: {}'.format(bytes_to_long(alice_seed)-decrypt.seed))
