#include<stdio.h>
#include<stdlib.h>
int main()
{
    //If the real user ID is set or the effective user ID is set to a value not equal to the previous real user ID,
    //the saved set-user-ID will be set to the new effective user ID.
        setuid(1001);
        //这个操作可以成功，因为本程序的euid为0
        //setreuid(1001,1001)
        setuid(1002);
        //这个操作不成功，euid已经被改变，只有euid为0的程序可以更改uid为任意值
        //seteuid(0),不可以成功，因为suid也被改变为1001，非特权euid只可以被设置成suid
        system("./printUID");
        //当s位打开后，euid不再继承父进程，而是程序文件的拥有者id

}
