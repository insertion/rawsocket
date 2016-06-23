#include<stdio.h>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#define __FAVOR_BSD
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<arpa/inet.h>

#define BUFFSIZE 1024
// 自定义一个简单以太网结构
typedef struct {
	struct ethhdr *eth;//以太网帧结构
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct tcphdr *tcp;
	struct udphdr *udp;
	char *data;
} Frame;

Frame hdr;// 定义一个头部全局变量	

//打印mac地址
void prinMAC(struct ethhdr *eth){

	printf("\n");
	printf("DST MAC ADDR  %02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	printf("SRC MAC ADDR  %02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	
	// 帧的长度或者包含的协议
	if (ntohs(eth->h_proto)<=1518){
		printf("frame total length: %d\n",ntohs(eth->h_proto));
		printf("including protocol is IP\n");
	
	}else if(ntohs(eth->h_proto)==ETH_P_IP){
		printf("including protocol is IP\n");
	}else if(ntohs(eth->h_proto)==ETH_P_ARP){
		printf("including protocol is ARP\n");
	}else if(ntohs(eth->h_proto)==ETH_P_RARP){
		printf("including protocol is RARP\n");
	}else 
		printf("unknow protocol\n");
	printf("\n");
}

// 打印IP头部信息
void  prinIP(struct iphdr *ip){
	
	struct in_addr saddr,daddr;
	saddr.s_addr=(unsigned long)ip->saddr;//ip源地址
	daddr.s_addr=(unsigned long)ip->daddr;//ip目的地址
	
	printf("SRC IP ADDR : %s\n",inet_ntoa(saddr));
	printf("DST IP ADDR : %s\n",inet_ntoa(daddr));
	
	printf("IP_header_length:  %d\n",ip->ihl<<2 );
	
	printf("IP_total_length:  %d\n",ntohs(ip->tot_len) );
	
	printf("IP_checksum: 0x%04x\n",ntohs(ip->check));
	
	if (ip->protocol==IPPROTO_ICMP){
		printf("including protocol is ICMP\n");
	}else if(ip->protocol==IPPROTO_IP){
		printf("including protocol is IP\n");
	}else if(ip->protocol==IPPROTO_IGMP){
		printf("including protocol is IGMP\n");
	}else if(ip->protocol==IPPROTO_TCP){
		printf("including protocol is TCP\n");
	}else if(ip->protocol==IPPROTO_UDP){
		printf("including protocol is UDP\n");
	}else 
		printf("unknow protocol\n");

	//printf("including protocol:  %d\n",ip->protocol );

	printf("\n");

}

// 处理ip中包含的协议
void deal(char *buff,u_int8_t protocol){

	if (buff == NULL || protocol==0 ){
		printf("deal failed : line 3\n");
		exit(-1);	
	}

	switch(protocol){
		// tcp 协议
		case IPPROTO_TCP:
		{
			printf("Protocol TCP\n");
			hdr.tcp = (struct tcphdr *)(buff + sizeof(struct ethhdr) + sizeof(struct iphdr));
			//tcp的首指针
			printf("SRC PORT : %d\n",ntohs(hdr.tcp->th_sport));
			printf("DST PORT : %d\n",ntohs(hdr.tcp->th_dport));
			
			printf("Sequence_number= %d \t Acknowledgment_number=%d\n",ntohs(hdr.tcp->th_seq), ntohs(hdr.tcp->th_ack));
			printf("tcp header len : %d bytes\n",(hdr.tcp->th_off)<<2);
			printf("flags=%d\n",ntohs(hdr.tcp->th_flags));
			
			if((hdr.tcp->th_flags)&TH_FIN){
				printf("FIN=1\t");
			}
			else 
			  printf("FIN=0\t");
			if((hdr.tcp->th_flags)&TH_SYN){
				printf("SYN=1\t");
			}else  
			 printf("SYN=0\t");
			if((hdr.tcp->th_flags)&TH_ACK){
				printf("ACK=1\n");
			}else   printf("ACK=0\n");
			printf("win=%d\n",ntohs(hdr.tcp->th_win));
			printf("checksum: 0x%02x\n",ntohs(hdr.tcp->th_sum));
				
		};break;
		// udp 协议
		case IPPROTO_UDP:
		{
			printf("Protocol UDP\n");
			hdr.udp = (struct udphdr *)(buff + sizeof(struct ethhdr) + sizeof(struct iphdr));
			printf("SRC PORT : %d\n",ntohs(hdr.udp->uh_sport));
			printf("DST PORT : %d\n",ntohs(hdr.udp->uh_dport));
			
		};break;
		// icmp 协议
		case IPPROTO_ICMP:
		{
			printf("Protocol ICMP\n");
			hdr.icmp = (struct icmphdr *)(buff + sizeof(struct ethhdr )+ sizeof(struct iphdr));
			
			printf("tpye: %d  \t code:%d \t",hdr.icmp->type,hdr.icmp->code);
			
			printf("checksum:0x%02x\n",ntohs(hdr.icmp->checksum));
			
			if(hdr.icmp->type==0 && 0 == hdr.icmp->code){
				
				printf("id: %d \t",ntohs(hdr.icmp->un.echo.id));
				
				printf("sequence: %d\n",ntohs(hdr.icmp->un.echo.sequence));
			}

		};break;
		// ip 协议
		case IPPROTO_IP:
		{
			printf("Protocol IP\n");
		};break;
		// igmp 协议
		case IPPROTO_IGMP:
		{
			printf("Protocol IGMP\n");
		};break;
		// 其他协议
		default:
			printf("Protocol unknown\n");
	}

}


// 对头部进行解析
void handlehd(char *buff,int size){

	if(buff==NULL || size<1){
		printf("handlehd failed! : line 3\n");
		exit(-1);
	}
		
	printf("=======================================\n");
	printf("receive %d bytes \n",size);
	
	// 获得以太网帧头部
	hdr.eth=(struct ethhdr *)buff; // 将buff的地址给eth
	prinMAC(hdr.eth); // 输出mac地址

	// 获得ip头部
	hdr.ip=(struct iphdr *)(buff+sizeof(struct ethhdr));
	prinIP(hdr.ip);// 输出ip头部信息

	// 处理ip包中携带的协议
	deal(buff,hdr.ip->protocol);

	printf("=======================================\n\n");
	




}


// 主函数
int main(){
	
	int sockfd,count; // 套接字描述符
	char buff[BUFFSIZE];// 接收包的大小
	sockfd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)); // 建立原始套接字，可以接收和发送以太网帧
	
	if(sockfd<0){
		printf("socket failed!\n");
		exit(-1);
	}
	printf("create raw_socket success! sockfd=%d\n",sockfd);
	
	count=0;
	// 接收所有的包（ip arp rarp）
	while(1){
		int n;
		// 接收		
		n=recvfrom(sockfd,buff,BUFFSIZE,0,NULL,NULL);
		if(n<0){
			printf("receive failed!\n");
			exit(-1);
		}
		count++;
		printf("\tNumber %d:\n",count);
		
		// 对包的头部进行分析
		handlehd(buff,n);
		



	}
	




}
