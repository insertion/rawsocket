#include<stdio.h>
int main()
{
        printf("[child process] ruid:%d\teuid:%d\n",getuid(),geteuid());
}
