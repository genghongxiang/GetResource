#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <WINSOCK2.h>
#include "readConfig.h"
#pragma comment(lib,"WS2_32.LIB")
#define STRSIZE 1024
#define BUFSIZE 10240
#define SessionVideoNum 100
typedef int bpf_int32;
typedef unsigned int bpf_u_int32;
typedef unsigned short  u_short;
typedef unsigned int u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;
//数据帧头
typedef struct FramHeader_t
{ //Pcap捕获的数据帧头
		u_int8 DstMAC[6]; //目的MAC地址
		u_int8 SrcMAC[6]; //源MAC地址
		u_short FrameType;    //帧类型
} FramHeader_t;
typedef struct IPHeader_t
{ //IP数据报头
		u_int8 Ver_HLen;       //版本+报头长度
		u_int8 TOS;            //服务类型
		u_int16 TotalLen;       //总长度
		u_int16 ID; //标识
		u_int16 Flag_Segment;   //标志+片偏移
		u_int8 TTL;            //生存周期
		u_int8 Protocol;       //协议类型
		u_int16 Checksum;       //头部校验和
		u_int32 SrcIP; //源IP地址
		u_int32 DstIP; //目的IP地址
} IPHeader_t;
//TCP数据报头
typedef struct TCPHeader_t
{ //TCP数据报头
		u_int16 SrcPort; //源端口
		u_int16 DstPort; //目的端口
		u_int32 SeqNO; //序号
		u_int32 AckNO; //确认号
		u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)
		u_int8 Flags; //标识TCP不同的控制消息
		u_int16 Window; //窗口大小
		u_int16 Checksum; //校验和
		u_int16 UrgentPointer;  //紧急指针
}TCPHeader_t;
unsigned int sumFlow = 0;
unsigned int sumTime = 0;
struct timeval tvl;
int gGetRequestFlags = 0;
int gStartCalcFlowFlags = 0;
int gResponseOk = 0;
/* prototype of the packet handler */
unsigned int calc = 0;
extern Config g_config;
IpPort *ipPort_tail = NULL;
IpPort *ipPort_head = NULL;

SessionFlow_t SessionFlowArray[SessionVideoNum];
int g_SessionVideoNum = 0;	

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void get_request_info(const struct pcap_pkthdr *header, const u_char *pkt_data);
int match_http(const unsigned char *httpDAta,char *head_str, char *tail_str, char *buf, int total_len);
int get_video(char *uri);
void add_httpRequest(unsigned int sr_cip,unsigned int dst_ip,int src_port,int dst_port,char *buf,const struct pcap_pkthdr *header);
int find_httpRequest(unsigned int sr_cip,unsigned int dst_ip,int src_port,int dst_port,char *url,struct timeval *pStime);
void popElem_from_IpPorts(IpPort *IpPortList);
int get_IpPort_num(IpPort *tmp_IpPort);
int main()
{
	tvl.tv_sec = 0;
	tvl.tv_usec = 0;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* read config  */
	read_config();
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	//printf("Enter the interface number (1-%d):",i);
	//scanf("%d", &inum);
	inum = g_config.netCardNo;
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	FILE *fpSave = fopen("a.pcap", "wb");
	
	u_char  pcap_header[24]={0xD4,0xC3,0xB2,0xA1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0x01,0x00,0x00,0x00};

	fwrite(pcap_header,1,24,fpSave);
	fclose(fpSave);
	FILE *fpa = fopen("a.txt", "w");
	fclose(fpa);
	FILE *fpb = fopen("b.txt", "w");
	fclose(fpb);
	FILE *fpd = fopen("d.txt", "w");
	fclose(fpd);		

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	if(pkt_data[14] != 0x45)
		return;
	
	calc = calc + 1;
	//printf("%s,%.6d len:%d,%d,%c\n", timestr, header->ts.tv_usec, header->len,header->caplen,pkt_data[14]);

		
	FILE *fpSave = fopen("a.pcap", "ab");
	fwrite((u_char*)header,1,16,fpSave);
	fwrite(pkt_data,1,header->len,fpSave);
	fclose(fpSave);
	get_request_info(header,pkt_data);
	
}
void get_request_info(const struct pcap_pkthdr *header, const u_char *pkt_data)
{	
	int ip_len, http_len, ip_proto,inFlowFlag = 0,index = 0;
	int src_port, dst_port, tcp_flags;
	char src_ip[STRSIZE], dst_ip[STRSIZE];
	char  host[STRSIZE], uri[BUFSIZE];
	char  responseCode[20];
	char buf[BUFSIZE];
	memset(responseCode,0,20);
	memset(host, 0, sizeof(host));
	memset(uri, 0, sizeof(uri));
	memset(buf, 0, sizeof(buf));
	IPHeader_t *ip_header;
	TCPHeader_t *tcp_header;
	ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
	
	memcpy(ip_header,pkt_data+sizeof(FramHeader_t),sizeof(IPHeader_t));
	sprintf(src_ip,"%s", inet_ntoa(*((struct in_addr*)&(ip_header->SrcIP))));
	sprintf(dst_ip,"%s", inet_ntoa(*((struct in_addr*)&(ip_header->DstIP))));
	ip_proto = ip_header->Protocol;
	ip_len = ip_header->TotalLen; //IP数据报总长度
	if(ip_proto != 0X06) //判断是否是 TCP 协议
	{
		free(ip_header);
		free(tcp_header);
		return;
	}

	//TCP头 20字节
	memcpy(tcp_header,pkt_data+sizeof(FramHeader_t)+sizeof(IPHeader_t),sizeof(TCPHeader_t));

	src_port = ntohs(tcp_header->SrcPort);
	dst_port = ntohs(tcp_header->DstPort);

	
	tcp_flags = tcp_header->Flags;
	
	if(tcp_flags == 0X18 && dst_port == 80) // (PSH, ACK) 3路握手成功后
	{	
		http_len = ip_len - 40; //http 报文长度
		if(http_len<3)
		{
			free(ip_header);
			free(tcp_header);
			return;			
		}

		const unsigned char *phttp_info = pkt_data + sizeof(FramHeader_t)+sizeof(IPHeader_t)+sizeof(TCPHeader_t);
		if (phttp_info[0] =='G')
		{
			//printf("src=%s,src_port=%d\n", src_ip,src_port);
			//printf("dst=%s,dst_port=%d\n", dst_ip,dst_port);

			match_http(phttp_info,"Host: ", "\r\n", host, http_len); //查找 host 值
			match_http(phttp_info,"GET ", "HTTP", uri, http_len);	//查找 uri 值
			int ret = get_video(uri);
			if (ret == 0)
			{	
				sprintf(buf,"%d,http://%s%s",calc,host,uri);
				popElem_from_IpPorts(ipPort_head);
				add_httpRequest(ip_header->SrcIP,ip_header->DstIP,tcp_header->SrcPort,tcp_header->DstPort,buf,header);
				printf("%s\n",buf);
				FILE * fp;
				fp = fopen("a.txt","a");
				fwrite(buf,1,strlen(buf),fp);
				fwrite("\n",1,strlen("\n"),fp);
				fclose(fp);
				
			}
		}

	}
	
	else if(src_port == 80)
	{
		http_len = ip_len - 40; //http 报文长度
		if(http_len<4)
		{
			free(ip_header);
			free(tcp_header);
			return;			
		}
		char ConType[100];
		char ConLen[20];
		memset(ConType,0,100);
		memset(ConLen,0,20);
		const unsigned char *phttp_info = pkt_data + sizeof(FramHeader_t)+sizeof(IPHeader_t)+sizeof(TCPHeader_t);
		int ret = match_http(phttp_info,"HTTP/", "\r\n", responseCode, http_len);
		int ret2 = match_http(phttp_info,"Content-Type: ", "\r\n", ConType, http_len);
		int ret3 = match_http(phttp_info,"Content-Length: ", "\r\n", ConLen, http_len);
		char *p = NULL;
		char *p2 = NULL;
		p = strstr(responseCode,"200 OK");
		p2 = strstr(responseCode,"206 Partial Content");

		for(index = g_SessionVideoNum-1;index >=0; index--)
		{
			if(SessionFlowArray[index].srcip == ip_header->SrcIP && SessionFlowArray[index].dstip == ip_header->DstIP &&SessionFlowArray[index].srcport == tcp_header->SrcPort && SessionFlowArray[index].dstport == tcp_header->DstPort)
			{		
				int twoPacketTime = (header->ts.tv_sec - SessionFlowArray[index].endtime.tv_sec)*1000000 + header->ts.tv_usec - SessionFlowArray[index].endtime.tv_usec;
				if(twoPacketTime > 1000000)
				{
					char str1[30];
					memset(str1,0,30);
					sprintf(str1,"calc = %d\n",calc);
					FILE * fp;
					fp = fopen("d.txt","a");
					fwrite(str1,1,strlen(str1),fp);					
					fclose(fp);					
					SessionFlowArray[index].endtime.tv_sec = header->ts.tv_sec;
					SessionFlowArray[index].endtime.tv_usec = header->ts.tv_usec;
					break;
				}
				sumTime += twoPacketTime;
				sumFlow += header->caplen;
				
				SessionFlowArray[index].downflow += header->caplen;			
				SessionFlowArray[index].endtime.tv_sec = header->ts.tv_sec;
				SessionFlowArray[index].endtime.tv_usec = header->ts.tv_usec;
				inFlowFlag = 1;
				break;
			}			
		}
		if(inFlowFlag == 1)
		{
			char tmpstr[20];
			memset(tmpstr,0,20);
			sprintf(tmpstr,"%d,%d",sumTime,sumFlow);
			FILE *fpCalc = fopen("calc.txt", "w");
			fwrite(tmpstr,strlen(tmpstr),1,fpCalc);
			fclose(fpCalc);			
		}

		if(p != NULL || p2 != NULL)
		{
			memset(&SessionFlowArray[g_SessionVideoNum],0,sizeof(SessionFlow_t));
			struct timeval tv;
			int flag = find_httpRequest(ip_header->DstIP,ip_header->SrcIP,tcp_header->DstPort,tcp_header->SrcPort,buf,&tv);
			if(flag == 0 && ret2 == 0 && ret3 == 0) 
			{
				char *pConType = NULL;
				char *pConType2 = NULL;
				pConType = strstr(ConType,"text");
				pConType2 = strstr(ConType,"json");
				int len = atoi(ConLen);
				if(p2 != NULL)
				{
					if(pConType != NULL || pConType2 != NULL)
					{
						free(ip_header);
						free(tcp_header);
						return;	
					}					
				}
				else if(p != NULL)
				{
					if(pConType != NULL || pConType2 != NULL || len < 1000000)
					{
						free(ip_header);
						free(tcp_header);
						return;	
					}					
				}
				SessionFlowArray[g_SessionVideoNum].srcip = ip_header->SrcIP;
				SessionFlowArray[g_SessionVideoNum].dstip = ip_header->DstIP;
				SessionFlowArray[g_SessionVideoNum].srcport = tcp_header->SrcPort;
				SessionFlowArray[g_SessionVideoNum].dstport = tcp_header->DstPort;
				SessionFlowArray[g_SessionVideoNum].starttime.tv_sec = tv.tv_sec;
				SessionFlowArray[g_SessionVideoNum].starttime.tv_usec = tv.tv_usec;
				SessionFlowArray[g_SessionVideoNum].endtime.tv_sec = tv.tv_sec;
				SessionFlowArray[g_SessionVideoNum].endtime.tv_usec = tv.tv_usec;
				SessionFlowArray[g_SessionVideoNum].downflow = 0;
				g_SessionVideoNum++;
			
				printf("Content-Length:%d\n",len);
				char str1[30];
				memset(str1,0,30);
				sprintf(str1,"%d,calc = %d\n",len,calc);
				printf("response calc = %d\n",calc);
				FILE * fp;
				fp = fopen("b.txt","a");
				//fwrite(str1,1,strlen(str1),fp);					
				fwrite(buf,1,strlen(buf),fp);
				fwrite("\n",1,strlen("\n"),fp);
				fclose(fp);
			}					
		}

				
	}
	
	free(ip_header);
	free(tcp_header);
	
}

//查找 HTTP 信息
int match_http(const unsigned char *httpDAta,char *head_str, char *tail_str, char *buf, int total_len)
{	
	char *p = NULL;
	p =strstr((const char*)httpDAta,head_str);
	if (p != NULL)
	{
		char *p1 = NULL;
		p1 =strstr(p,tail_str);
		if (p1 != NULL)
			snprintf(buf,int(p1-p-strlen(head_str)),"%s",p+strlen(head_str));
			return 0;
		return -1;
	}
	return -1;
}

int get_video(char *uri)
{
	//char *video_suffix[]={".mp4",".f4v",".flv",".ts",".m2ts",".m3u8",".m4r",".m4v",".wmv",".m2ts",".avi",".rmvb",".rm",".asf",".divx",".mpg",".mpeg",".mpe",".mkv",".vob",".hlv"};
	//int length = sizeof(video_suffix)/sizeof(char*);
	int length = g_config.ext_num;
	int i = 0;
	for(i = 0;i < length;i++)
	{
		char *p = NULL;
		p = strstr(uri,g_config.ext[i]);
		
		if (p != NULL)
		{
			char *pYouku = NULL;
			char *pAqiyi = NULL;
			char *pLetv = NULL;
			pYouku = strstr(uri,"/youku/");  //----------youku video---------
			if(pYouku != NULL)
			{
				uri[p-uri+strlen(g_config.ext[i])] = '\0';
				return 0;
			}
			pAqiyi = strstr(uri,"/videos/v0/"); //------------aqiyi video-------
			if (pAqiyi != NULL)
			{
				char * p2 = NULL;
				p = strstr(uri,"&range=");
				if(p2 != NULL)
				{
					uri[p2-uri] = '\0';					
				}
				return 0;
			}
			pLetv = strstr(uri,"/letv-uts/"); //-------letv video------------
			if (pLetv != NULL)
			{
				char *p2 = NULL;
				char *p3 = NULL;
				p2 = strstr(uri,"&rstart=");
				p3 = strstr(uri,"&rend=");
				if(p2 != NULL && p3 != NULL)
				{
					uri[p2-uri] = '\0';
				}
				return 0;	
			}
			return 0;
		}			
		else
		{
			continue;			
		}

	}
	return -1;
	
}
void add_httpRequest(unsigned int src_ip,unsigned int dst_ip,int src_port,int dst_port,char *buf,const struct pcap_pkthdr *header)
{
	IpPort *tmp_IpPort = (IpPort *)malloc(sizeof(IpPort));
	memset(tmp_IpPort,0,sizeof(IpPort));
	tmp_IpPort->url = (char *)malloc(strlen(buf)+1);
	tmp_IpPort->srcip = src_ip;
	tmp_IpPort->dstip = dst_ip;
	tmp_IpPort->srcport = src_port;
	tmp_IpPort->dstport = dst_port;
	strcpy(tmp_IpPort->url,buf);
	tmp_IpPort->startTim.tv_sec = header->ts.tv_sec;
	tmp_IpPort->startTim.tv_usec = header->ts.tv_usec ;
	//printf("%s\n",tmp_IpPort->url);
	tmp_IpPort->next = NULL;
	if(ipPort_tail == NULL && ipPort_head == NULL)
	{
		ipPort_tail = tmp_IpPort;
		ipPort_head = tmp_IpPort;					
	}
	else
	{
		ipPort_tail->next = tmp_IpPort;
		ipPort_tail = tmp_IpPort;
	}	
	int num = get_IpPort_num(ipPort_head);
	printf("Add one httpquest,the num of IpPort_list is %d\n",num);
}
int find_httpRequest(unsigned int sr_cip,unsigned int dst_ip,int src_port,int dst_port,char *url,struct timeval *pStime)
{
	IpPort *pre_IpPort = ipPort_head;
	IpPort *suf_IpPort = ipPort_head;
	while(suf_IpPort != NULL)
	{
		if(suf_IpPort->srcip == sr_cip && suf_IpPort->dstip == dst_ip && suf_IpPort->srcport == src_port && suf_IpPort->dstport == dst_port)
		{   
			printf(" ----HTTP Response find the HTTP Request----\n");
			strcpy(url,suf_IpPort->url);
			if(ipPort_head == suf_IpPort)
			{
				if(suf_IpPort == ipPort_tail)
				{
					ipPort_head = suf_IpPort->next;
					ipPort_tail = suf_IpPort->next;
				}
				else
				{
					ipPort_head = suf_IpPort->next;	
				}
			}
			else
			{
				if(suf_IpPort == ipPort_tail)
				{
					pre_IpPort->next = suf_IpPort->next;
					ipPort_tail = pre_IpPort;
				}
				else
				{
					pre_IpPort->next = suf_IpPort->next;
				}

			}
			pStime->tv_sec = suf_IpPort->startTim.tv_sec;
			pStime->tv_usec = suf_IpPort->startTim.tv_usec;			
			free(suf_IpPort->url);
			free(suf_IpPort);
			int num = get_IpPort_num(ipPort_head);
			printf("Delete one httpquest,the num of IpPort_list is %d\n",num);
			return 0;
		}
		else
		{
			pre_IpPort = suf_IpPort;
			suf_IpPort = suf_IpPort->next;
		}

	}
	return -1;
	
}
int get_IpPort_num(IpPort *tmp_IpPort)
{
	int i = 0;
	while(tmp_IpPort != NULL)
	{
		i++;
		tmp_IpPort = tmp_IpPort->next;
	}	
	return i;
	
}
void popElem_from_IpPorts(IpPort *IpPortList)
{
	int num = get_IpPort_num(IpPortList);
	if (num > 10)
	{
		printf("IpPortList is too long ,delete first elem!!!!!!");
		IpPort *p = NULL;
		p = ipPort_head;
		ipPort_head = ipPort_head->next;
		free(p->url);
		free(p);
	}	
}