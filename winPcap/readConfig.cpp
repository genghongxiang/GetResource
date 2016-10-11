#include<iostream>
#include <stdio.h>
//#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "tinyxml.h"
#include "readConfig.h"
using namespace std;
Config g_config;
Host_Path *Host_Path_head = NULL;
Host_Path *Host_Path_tail = NULL;
int get_Host_Path_num(Host_Path *Head);
int read_config()
{
	
	char filename[1024];
	sprintf(filename,"%s","Config.xml");
	printf(filename);
	TiXmlDocument docConfigFile(filename);
	bool bLoadOK = docConfigFile.LoadFile();

	if (false == bLoadOK)
	{
		printf("Error: load xml file %s fail!\n", filename);
		return -1;
	}

	TiXmlHandle docHandle(&docConfigFile);
	TiXmlElement *pItemElement = NULL;	
	int i = 0;
	
	pItemElement = docHandle.FirstChild("Config").FirstChild("Ext").FirstChild("node").Element();
	for (; pItemElement != NULL; pItemElement = pItemElement->NextSiblingElement())
	{
		if (NULL == pItemElement->Attribute("value"))
			continue;
		//printf("%s\n",pItemElement->Attribute("value"));
		sprintf(g_config.ext[i],"%s",pItemElement->Attribute("value"));
		printf("%s\n",g_config.ext[i]);
		g_config.ext_num ++;
		i ++;
	}
	pItemElement = docHandle.FirstChild("Config").FirstChild("NetCardNo").FirstChild("node").Element();
	if(pItemElement != NULL)
	{
		g_config.netCardNo = atoi(pItemElement->Attribute("value"));
	}
	TiXmlElement *root = docConfigFile.RootElement();
	
	TiXmlElement *pRulerElement = root->FirstChildElement("MyRuler")->FirstChildElement("Ruler");
	for (; pRulerElement != NULL ; pRulerElement = pRulerElement->NextSiblingElement())
	{	
		
		int index,action;
		
		pRulerElement->Attribute("id",&index);
		pRulerElement->Attribute("action",&action);
		Host_Path *tmpHost_Path = (Host_Path *)malloc(sizeof(Host_Path));
		tmpHost_Path->id = index;
		tmpHost_Path->action = action;
		tmpHost_Path->pItem_head = NULL;
		tmpHost_Path->pItem_tail = NULL;
		tmpHost_Path->next = NULL;
		pItemElement =pRulerElement ->FirstChildElement("Item");
		
		for(;pItemElement != NULL;pItemElement = pItemElement->NextSiblingElement())
		{
			const char *pType = pItemElement->Attribute("type");
			const char *pValue = pItemElement->Attribute("value");
			Item_t *tmpItem_t = (Item_t *)malloc(sizeof(Item_t));
			memset(tmpItem_t,0,sizeof(Item_t));
			strcpy(tmpItem_t->type,pType);
			strcpy(tmpItem_t->value,pValue);
			tmpItem_t -> next = NULL;
			if(tmpHost_Path->pItem_head == NULL && tmpHost_Path->pItem_tail == NULL)
			{
				tmpHost_Path->pItem_head = tmpItem_t;
				tmpHost_Path->pItem_tail = tmpItem_t;
			}
			else
			{
				tmpHost_Path->pItem_tail ->next = tmpItem_t;
				tmpHost_Path->pItem_tail = tmpItem_t;
			}
			//printf("%s,%s\n",pType,pValue);
		}
		if(Host_Path_head == NULL && Host_Path_tail == NULL)
		{
			Host_Path_head = tmpHost_Path;
			Host_Path_tail = tmpHost_Path;
		}
		else
		{
			Host_Path_tail->next = tmpHost_Path;
			Host_Path_tail = tmpHost_Path;
		}

	}
	get_Host_Path_num(Host_Path_head);
	return 0;
}
int get_Host_Path_num(Host_Path *Head)
{
	int i = 0;
	Host_Path * p = Head;
	while(p != NULL)
	{
		printf("%d,%d\n",p->id,p->action);
		i++;
		Item_t * p2 =  p->pItem_head;
		while(p2 != NULL)
		{
			printf("%s,%s\n",p2->type,p2->value);
			p2 = p2->next;
		}
		p = p->next;
	}	
	return i;
	
}