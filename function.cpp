#include "header.h"
#pragma once
//读取DNS请求中的域名
void GetUrl(char* recvbuf, int recvnum)
{
	char urlname[LENGTH];
	int i = 0, j, k = 0;

	memset(url, 0, LENGTH);
	memcpy(urlname, &(recvbuf[sizeof(DNSHeader)]), recvnum - 16);	//获取请求报文中的域名表示

	int len = strlen(urlname);

	//域名转换
	while (i < len) {
		if (urlname[i] > 0 && urlname[i] <= 63)
			for (j = urlname[i], i++; j > 0; j--, i++, k++)
				url[k] = urlname[i];

		if (urlname[i] != 0) {
			url[k] = '.';
			k++;
		}
	}
	url[k] = '\0';
}

//判断是否在表中找到DNS请求中的域名，找到返回下标
int IsFind(char* url, int num)
{
	int find = NOTFOUND;
	char* domain;

	for (int i = 0; i < num; i++) {
		//strcpy(domain, DNS_table[i].domain);
		domain = DNS_table[i].domain;
		//domain = (char*)DNS_table[i].domain.c_str();
		if (strcmp(domain, url) == 0) {	//找到
			find = i;
			break;
		}
	}
	return find;
}

//将请求ID转换为新的ID并写入ID转换表中
unsigned short RegisterNewID(unsigned short oID, SOCKADDR_IN temp, BOOL ifdone)
{
	srand(time(NULL));
	idTransTable[IDcount].formerID = oID;
	idTransTable[IDcount].client = temp;
	idTransTable[IDcount].DONE = ifdone;
	IDcount++;
	return (unsigned short)(IDcount - 1);	//以表中下标作为新的ID
}
