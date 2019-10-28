#include<stdio.h>
#include<stdlib.h>

int main(){
    char *hex="0xffffffffa37cd770";
    size_t i_h=0;
    sscanf(hex,"%llx",&i_h);
    printf("this:%llx\n",i_h);
    return 0;
}
