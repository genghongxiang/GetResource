#ifndef __CONFIG_H__
#define __CONFIG_H__
#include <pcap.h>
#define PATH_LEN 1024
#define LIST_MAX 20
#define SYSCONFIG_FILE "send_disturb.xml"
/*
typedef struct config_t{
	int enable;
	int log_level;
	unsigned int map_size;
	int sendcount_first;
	int sendcount_map;
	char root_dir[PATH_LEN];
	int port_num;
	int portList[LIST_MAX];
}Config;
*/
typedef struct config_t{
	char ext[50][10];
	int ext_num;
	int netCardNo;
}Config;
typedef struct ipPort{
	unsigned int srcip;
	unsigned int dstip;
	int srcport;
	int dstport;
	struct timeval startTim;
	char *url;
	struct ipPort *next;
}IpPort;

typedef  struct SessionFlow_t{
	unsigned int srcip;
	unsigned int dstip;
	int srcport;
	int dstport;	
	struct timeval starttime;
	struct timeval endtime;
	int downflow;
}SessionFlow_t;

typedef struct Item_t{
	char type[12];
	char value[28];
	struct Item_t *next;
}Item_t;
typedef struct host_path_t{
	int id;
	int action;
	struct Item_t *pItem_head;
	struct Item_t *pItem_tail;
	struct host_path_t *next;
}Host_Path;
void init_config();
void print_config();
int read_config();
int get_Host_Path_num(Host_Path *Head);

#endif