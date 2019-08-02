#include<stdio.h>


int main(){
    char * str = "3144hellow1234world!";
    char * endstr;
    int ret;
    ret = strtol(str,&endstr,0);
    printf("the number:%d,the end string:%s\n",ret,endstr);

    
}
