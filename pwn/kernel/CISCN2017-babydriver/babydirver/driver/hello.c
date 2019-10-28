/* get size of cred */

#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
//#include<linux/cred.h>
#include<linux/tty.h>
#include<linux/tty_driver.h>

MODULE_LICENSE("DUal BSD/GPL");

//struct cred c1;
struct tty_struct c1;

int hello_init(void){
    int offset;
    printk("hellow boy!\n");
    printk("sizeof tty_struct:%x\n",sizeof(c1));
    printk("tty_struct addr:%p\n",&c1);
    printk("tty_struct.ops addr:%p\n",&(c1.ops));
    printk("tty operations size:0x%x\n",sizeof(struct tty_operations));
    offset =(size_t)&(c1.ops) - (size_t)&c1;
    printk("offset:0x%x\n",offset);
    return 0;
}

int hello_exit(void){
    printk("bye,boy!\n");
    return 0;
}

module_init(hello_init);
module_exit(hello_exit);
