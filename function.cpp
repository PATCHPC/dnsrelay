#include "header.h"
//函数：获取域名解析表
int GetTable(char *tablePath)
{
	int i=0, j;
	char *pos;
	char *table[AMOUNT];
	FILE *fp;

	//ifstream infile(tablePath, ios::in);	//以读入方式打开文本文件
	if((fp = fopen(tablePath, "rt")) == NULL) {
		printf("Open file error!\n");
		exit(1);
	}

	//每次从文件中读入一行，直至读到文件结束符为止
	while (fgets(table[i], 100 , fp) && i < AMOUNT)
		i++;

	if (i == AMOUNT-1)
		printf("The DNS table memory is full. \n");

	for (j = 0; j < i-1; j++) {
		pos = strchr(table[j] , ' ');
		if (pos-table[j] > strlen(table[j]))
			printf("The record is not in a correct format. \n");
		else {
			strlen(DNS_table[j].IP , table[j] , abs(pos-table[j]));
			strlen(DNS_table[j].domain , pos);
			//DNS_table[j].IP = table[j].substr(0, pos);
			//DNS_table[j].domain = table[j].substr(pos+1);
		}
	}

	fclose(fp);		//关闭文件
	printf("Load records succeed. \n");
	return i-1;			//返回域名解析表中条目个数
}

//读取DNS请求中的域名
void GetUrl(char *recvbuf, int recvnum)
{
	char urlname[LENGTH];
	int i = 0, j, k = 0;

	memset(url, 0, LENGTH);
	memcpy(urlname, &(recvbuf[sizeof(DNSHDR)]), recvnum-16);	//获取请求报文中的域名表示

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
		domain = (char *)DNS_table[i].domain.c_str();
		if (strcmp(domain, url) == 0) {	//找到
			find = i;
			break;
		}
	}
	return find;
}

//将请求ID转换为新的ID并写入ID转换表中
unsigned short RegisterNewID (unsigned short oID, SOCKADDR_IN temp, BOOL ifdone)
{
	srand(time(NULL));
	IDTransTable[IDcount].oldID = oID;
	IDTransTable[IDcount].client = temp;
	IDTransTable[IDcount].done  = ifdone;
	IDcount++;
	return (unsigned short)(IDcount-1);	//以表中下标作为新的ID
}
