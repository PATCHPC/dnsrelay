#pragma once

#include <stdlib.h>

#include <stdio.h>

#include <string.h>

#include <errno.h>

#include <Windows.h>

#include <stdint.h>

#include<time.h>

#pragma warning(disable:4996)

#pragma comment(lib,"wsock32.lib")

//域名解析表最大长度

#define MAX_AMOUNT 1000   //解析表最大容量

#define DEFAULT_DNS_ADDRESS "10.3.9.4" //外部DNS服务器地址

#define DEFAULT_LOCAL_ADDRESS "127.0.0.1" //本地DNS服务器地址

#define DNS_PORT 53 //进行DNS服务的53端口

#define BUF_SIZE 1024   //缓冲区最大容量（字节）

#define LENGTH 100  //域名最大长度

#define NOTFOUND -1  //在解析表中未找到域名



///////////////////结构体的定义////////////////

//DNS报文首部

typedef struct {

	unsigned id : 16;    /* query identification number */

	unsigned rd : 1;     /* recursion desired */

	unsigned tc : 1;     /* truncated message */

	unsigned aa : 1;     /* authoritive answer */

	unsigned opcode : 4; /* purpose of message */

	unsigned qr : 1;     /* response flag */

	unsigned rcode : 4;  /* response code */

	unsigned cd : 1;     /* checking disabled by resolver */

	unsigned ad : 1;     /* authentic data from named */

	unsigned z : 1;      /* unused bits, must be ZERO */

	unsigned ra : 1;     /* recursion available */

	unsigned qdcount : 16;       /* number of question entries */

	unsigned ancount : 16;       /* number of answer entries */

	unsigned nscount : 16;    /* number of authority entries */

	unsigned arcount : 16;     /* number of resource entries */



}DNSHeader;

//DNS域名解析表的结构

typedef struct {

	char* IP;

	char* domain;

}IPTranslate;

typedef struct {

	unsigned short formerID;

	BOOL DONE;     //标记是否完成解析

	SOCKADDR_IN client;   //网络地址

}IDTransform;

/////////常量的定义///////////

IPTranslate DNS_table[MAX_AMOUNT];    //域名-IP解析表

IDTransform idTransTable[MAX_AMOUNT];  //ID转换表

char url[LENGTH];//域名 

int IDcount = 0;    //ID表下标

int debug_level = -1;

/////////////////函数////////////////

//读取DNS请求中的域名,返回域名占用总长度

int GetUrl(char* recvbuf, int recvnum);   

//判断是否在表中找到DNS请求中的域名，找到返回下标

int IsFind(char* url, int num);

//将请求ID转换为新的ID并写入ID转换表中

unsigned short RegisterNewID(unsigned short oID, SOCKADDR_IN temp, BOOL ifdone);

//参数解析

void debuglevelJudge(int argc, char** argv, char* tablePath, char* outerDns);


/////////////////// IO ///////////////////

//函数：读取域名解析表

int ReadTable(char* tablePath);

//读取DNS请求中的域名，返回域名域字节数

int GetUrl(char* recvbuf, int recvnum)

{

	char urlname[LENGTH];

	int i = 0, j, k = 0;

	memset(url, 0, LENGTH);   //以字节为单位拷贝

	memcpy(urlname, &(recvbuf[sizeof(DNSHeader)]), recvnum - 12);	//获取请求报文中的域名表示
	//printf("*********%x************\n", *(unsigned char*)recvbuf);
	//printf("!!!!!!!!!!%x!!!!!!!!!!!\n", *(unsigned char*)urlname);
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
		if (urlname[i] == 0)
		{
			break;
		}
	}

	url[k] = '\0';
	return i + 1;
}

//判断是否在表中找到DNS请求中的域名，找到返回下标

int IsFind(char* url, int num)

{

	int find = NOTFOUND;

	char* domain;

	for (int i = 0; i < num; i++) {


		domain = DNS_table[i].domain;

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
	idTransTable[IDcount].formerID = oID;

	idTransTable[IDcount].client = temp;

	idTransTable[IDcount].DONE = ifdone;

	IDcount++;

	return (unsigned short)(IDcount - 1);	//以表中下标作为新的ID

}

//IO：读取域名解析表并返回域名解析表中的条目个数

int ReadTable(char* tablePath) {

	int i = 0, j;

	char* pos;

	char* table[MAX_AMOUNT];

	FILE* fp;

	if ((fp = fopen(tablePath, "rt")) == NULL) 
	{

		printf("Open file error!\n");

		exit(1);

	}

	//每次从文件中读入一行，直至读到文件结束符为止

	table[i] = (char*)malloc(100 * sizeof(char));

	memset(table[i], 0, 100);

	while (fgets(table[i], 100, fp) && i < MAX_AMOUNT)

	{
		
		i++;

		table[i] = (char*)malloc(100 * sizeof(char));

		memset(table[i], 1, 100);

	}

	if (i == MAX_AMOUNT)

		printf("The DNS table memory is full. \n");

	for (j = 0; j < i - 1; j++) {

		pos = strchr(table[j], ' ');

		if ((unsigned)abs(pos - table[j]) > strlen(table[j]))

			printf("The record is not in a correct format. \n");

		else {

			strncpy(DNS_table[j].IP, table[j], abs(pos - table[j]));

			strcpy(DNS_table[j].domain, pos + 1);

			if (debug_level == 2)
			{
				printf("%d  %s  %s", j + 1, DNS_table[j].IP, DNS_table[j].domain);
			}
			

			DNS_table[j].domain[strlen(DNS_table[j].domain) - 1] = '\0';

		}
		
	}

	fclose(fp);		//关闭文件

	printf("Load records succeed. \n");

	return i - 1;			//返回域名解析表中条目个数

}

void debuglevelJudge(int argc, char** argv, char* tablePath, char* outerDns)
{
	if (argc == 1)   //只有denrelay，全为默认值

	{

		debug_level = 0;

		strcpy(outerDns, DEFAULT_DNS_ADDRESS);

		strcpy(tablePath, "dnsrelay.txt");   //需要加入路径

	}

	else   //有大于1个参数

	{

		if (argv[1][0] == '-')

		{

			if (argv[1][1] == 'd' && argv[1][2] == 'd')  //完整输出

			{

				debug_level = 2;
				strcpy(outerDns, DEFAULT_DNS_ADDRESS);

				strcpy(tablePath, "dnsrelay.txt");

			}

			else

			{

				debug_level = 1;

			}

			if (argc == 2)  //dnsrelay -dd 或 dnsrelay -d

			{

				strcpy(outerDns, DEFAULT_DNS_ADDRESS);

				strcpy(tablePath, "dnsrelay.txt");   //需要加入路径

			}

			else if (argc == 3)

			{

				if (argv[2][0] >= '0' && argv[2][0] <= '9')  //dnsrealy -dd 1.1.1.1 或 dnsrelay -d 1.1.1.1

				{

					strcpy(outerDns, argv[2]);

					strcpy(tablePath, "dnsrelay.txt");

				}

				else if ((argv[2][0] >= 'A' && argv[2][0] <= 'Z') || (argv[2][0] >= 'a' && argv[2][0] <= 'z'))  //dnsrelay -dd c: 或 dnsrelay -d c:

				{

					strcpy(outerDns, DEFAULT_DNS_ADDRESS);

					strcpy(tablePath, argv[2]);  //dnsrelay C:

				}

			}

			else if (argc == 4)

			{

				strcpy(tablePath, argv[3]);

				strcpy(outerDns, argv[2]);

			}

		}

		else if (argv[1][0] >= '0' && argv[1][0] <= '9')

		{

			debug_level = 0;

			strcpy(outerDns, argv[1]);

			if (argc == 3)

			{

				strcpy(tablePath, argv[2]);   //dnsrelay 1.1.1.1 c:

			}

			else

			{

				strcpy(tablePath, "dnsrelay.txt");   //dnsrelay 1.1.1.1 

			}

		}

		else if ((argv[1][0] >= 'A' && argv[1][0] <= 'Z') || (argv[1][0] >= 'a' && argv[1][0] <= 'z'))

		{

			debug_level = 0;

			strcpy(outerDns, DEFAULT_DNS_ADDRESS);

			strcpy(tablePath, argv[1]);  //dnsrelay C:

		}
	}
}

void printtime()
{

	SYSTEMTIME sys;

	GetLocalTime(&sys);

	printf("%4d/%02d/%02d %02d:%02d:%02d ", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);

}

//输出完整信息

void standard_print(char* buf, int length)

{

	unsigned char tage;

	int num;

	unsigned short* p ;

	unsigned char* p1 = (unsigned char*)buf;  //8位

	for (int i = 0; i < length; i++)

	{

		tage = (unsigned char)buf[i];

		printf("%02x ", tage);

	}
	printf("\n");

	printf("      ");

	printf("ID %02x", *p1);

	p1++;

	printf("%02x, ", *p1);

	p1++;

	printf("QR %x, ", ((*p1) & (0x80)) >> 7);

	printf("OPCODE %x, ", ((*p1) & (0x78)) >> 3);

	printf("AA %x, ", ((*p1) & (0x04)) >> 2);

	printf("TC %x, ", ((*p1) & (0x02)) >> 1);

	printf("RD %x, ", (*p1) & (0x01));

	p1++;

	printf("RA %x, ", ((*p1) & (0x80)) >> 7);

	printf("Z %x, ", ((*p1) & (0x70)) >> 4);

	printf("RCODE %x\n", (*p1) & (0x0F));

	p1++;

	printf("      ");

	p = (unsigned short*)p1;

	printf("QDCOUNT %d, ",ntohs(*p));

	p++;

	printf("ANCOUNT %d, ", ntohs(*p));

	p++;

	printf("NSCOUNT %d, ", ntohs(*p));

	p++;

	printf("ARCOUNT %d, ", ntohs(*p));

	printf("\n");


}


int main(int argc, char** argv) {

	//定义常量

	WSADATA wsaData;

	SOCKET  socketServer, socketLocal;				//本地DNS和外部DNS两个套接字（不同主机应用层进程之间通信）

	SOCKADDR_IN serverName, clientName, localName;	//本地DNS、外部DNS和请求端三个网络套接字地址（地址族、端口号、IP）

	char sendbuf[BUF_SIZE];

	char recvbuf[BUF_SIZE];

	char tablePath[100];

	char outerDns[16];

	int iLen_cli, iSend, iRecv;

	int num;   //dnsrelay.txt长度

	int i;

	int count = 0;  //序号

	//分析指令
	debuglevelJudge(argc, argv,tablePath, outerDns);
	

	//初始化ID转换表

	for (i = 0; i < MAX_AMOUNT; i++)

	{

		idTransTable[i].formerID = 0;

		idTransTable[i].DONE = FALSE;

		memset(&(idTransTable[i].client), 0, sizeof(SOCKADDR_IN));

	}
	//初始化IP、域名对应表
	for (i = 0; i < MAX_AMOUNT; i++)

	{

		DNS_table[i].IP = (char*)malloc(30 * sizeof(char));

		memset(DNS_table[i].IP, 0, 30);

		DNS_table[i].domain = (char*)malloc(30 * sizeof(char));

		memset(DNS_table[i].domain, 0, 30);

	}


	WSAStartup(MAKEWORD(2, 2), &wsaData);           //启动套接字
	//创建本地DNS和外部DNS套接字
	socketServer = socket(AF_INET, SOCK_DGRAM, 0);  //创建外部套接字

	socketLocal = socket(AF_INET, SOCK_DGRAM, 0);   //创建本地套接字

	//////////////////////////////////////////////////////////////////////


	//初始化本地DNS和外部DNS两个套接字

	localName.sin_family = AF_INET;   //IPv4

	localName.sin_port = htons(DNS_PORT);

	localName.sin_addr.s_addr = inet_addr(DEFAULT_LOCAL_ADDRESS); //set to local address

	serverName.sin_family = AF_INET;

	serverName.sin_port = htons(DNS_PORT);

	serverName.sin_addr.s_addr = inet_addr(outerDns);  //set to out address

	/////////////////////////////////////////////////////////////////////
	/*
	int reuse = 1;
	setsockopt(socketLocal, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));*/

	if (bind(socketLocal, (SOCKADDR*)&localName, sizeof(localName))) 
	{  //绑定本地地址和套接口

		printf("Binding Port 53 failed.\n");

		exit(1);

	}

	else
	{

		printf("Binding Port 53 succeed.\n");

	}

	num = ReadTable(tablePath);  //the number of the table


	//本地DNS中继服务器的具体操作

	while (1) 
	{

		int iLen_cli = sizeof(clientName);

		memset(recvbuf, 0, BUF_SIZE);

		//接受DNS请求
		//recvfrom成功则返回实际接收到的字符数，失败返回-1，错误原因会存于errno 中
		//clientname的结构
		//struct sockaddr_in {
		//	short   sin_family;
		//	u_short sin_port;
		//	struct  in_addr sin_addr;
		//	char    sin_zero[8];
		//};
		iRecv = recvfrom(socketLocal, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);   //（本地套接字，buf，buflen，flag，from指针，*fromlen）

		memset(&iSend, 0, sizeof(int));

		if (iRecv == SOCKET_ERROR) {

		    printf("Recvfrom Failed:%d\n", WSAGetLastError());

			continue;

		}

		else if (iRecv == 0) {//对方关闭连接

			break;

		}

		else {
			//iRecv为读入的字节数
			int ulen;
			unsigned short* pout;
			unsigned char* ptemp;
			ulen = GetUrl(recvbuf, iRecv);				//获取域名，返回名字域长度
			ptemp = (unsigned char*)recvbuf;           //定位QTYPE首地址
			ptemp += 12;
			ptemp += ulen;
			pout = (unsigned short*)ptemp;            //输出QTYPE和QCLASS
			int find = IsFind(url, num);		//在域名解析表中查找

			//输出
			if (debug_level == 1)
			{
				printf("%d:  ", count);
				printtime();
				printf("Client: %s ", inet_ntoa(clientName.sin_addr));
				printf(" %s\n", url);
			}
			if (debug_level == 2)
			{
                printf("RECV from %s : %d (%dBytes)  ", inet_ntoa(clientName.sin_addr), iSend, iSend / 8);
                standard_print(recvbuf, iRecv);
				printf("%d:  ", count);
				printtime();
				printf("    Client: %s ", inet_ntoa(clientName.sin_addr));
				printf("    %s,", url);
				printf("    TYPE %d,", ntohs(*pout));
				pout++;
				printf("    CLASS %d\n", ntohs(*pout));
			}
			count++;
		
			//在域名解析表中没有找到

			if (find == NOTFOUND) 
			{

				unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));   //两字节ID

				memcpy(pID, recvbuf, sizeof(unsigned short));    //报文最前面就是ID

				unsigned short nID = htons(RegisterNewID(ntohs(*pID), clientName, FALSE));    //机器数变成网络数

				memcpy(recvbuf, &nID, sizeof(unsigned short));    //ID转换


				//把recvbuf转发至指定的外部DNS服务器

				iSend = sendto(socketServer, recvbuf, iRecv, 0, (SOCKADDR*)&serverName, sizeof(serverName));    //（服务器套接字，buf，buflen，flag，to指针，tolen）
				if (iSend == SOCKET_ERROR) 
				{

					printf("sendto Failed:%d\n", WSAGetLastError());

					continue;
				}

				else if (iSend == 0)
				{

					break;

				}

				else
				{
					if (debug_level == 2)
					{
						printf("Send to %s : %d (%dBytes)  [ID %04x -> %04x]\n", inet_ntoa(serverName.sin_addr), iSend, iSend / 8, *pID, ntohs(nID));
					}
				}

				free(pID);	//释放动态分配的内存

				//接收来自外部DNS服务器的响应报文

				iRecv = recvfrom(socketServer, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);

				//ID转换

				pID = (unsigned short*)malloc(sizeof(unsigned short));

				memcpy(pID, recvbuf, sizeof(unsigned short));

				int m = ntohs(*pID);     //新ID是转换表中的下标，通过下标找到记录

				unsigned short oID = htons(idTransTable[m].formerID);  //oldID是一个网络数

				memcpy(recvbuf, &oID, sizeof(unsigned short));   //把oldID放回报头传回客户端

				idTransTable[m].DONE = TRUE;

				if (debug_level == 2)
				{
					printf("RECV from %s : %d (%dBytes)  ", inet_ntoa(clientName.sin_addr), iSend, iSend / 8);
					standard_print(recvbuf, iRecv);
				}

				//从ID转换表中获取发出DNS请求者的信息

				clientName = idTransTable[m].client;

				//把recvbuf转发至请求者处

				iSend = sendto(socketLocal, recvbuf, iRecv, 0, (SOCKADDR*)&clientName, sizeof(clientName));

				if (iSend == SOCKET_ERROR)
				{

					printf("send to Failed:%d \n", WSAGetLastError());

					return 1;
				}

				else if (iSend == 0)
				{
					return -1;
				}

				else
				{
					if (debug_level == 2)
					{
						printf("Send to %s : %d (%dBytes)  [ID %04x -> %04x]\n", inet_ntoa(clientName.sin_addr), iSend, iSend / 8, ntohs(*pID), oID);
					}
				}

				free(pID);	//释放动态分配的内存
			}



			//在域名解析表中找到

			else {

				//获取请求报文的ID

				unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));

				memcpy(pID, recvbuf, sizeof(unsigned short));

				//转换ID

				unsigned short nID = RegisterNewID(ntohs(*pID), clientName, FALSE);


				//构造响应报文返回

				memcpy(sendbuf, recvbuf, iRecv);						//拷贝请求报文

				unsigned short a = htons(0x8180);   //QR=1，RD=1，RA=1

				memcpy(&sendbuf[2], &a, sizeof(unsigned short));		//修改标志域

				//修改回答数域

				if (strcmp(DNS_table[find].IP, "0.0.0.0") == 0)
				{
					a = htons(0x0000);	//屏蔽功能：回答数为0
					printf("已拦截屏蔽网站！  ");
				}

				else
					a = htons(0x0001);	//服务器功能回答数为1

				memcpy(&sendbuf[6], &a, sizeof(unsigned short));  //修改ANCOUNT

				int curLen = 0;

				//构造DNS响应部分

				char answer[16];   //16字节应答
				//DNS协议消息压缩技术，使用偏移指针代替重复的字符串。该指针用两个8bit表示
				//最开始的两个bit必须都为1后面的14bit表示字符串在整个DNS消息包中的偏移量。
				//其中第一个出现的域名偏移量固定为12字节（00001100），加上最开始的两个1，那二进制就是
				unsigned short Name = htons(0xc00c);    //1100 0000 0000 1100

				memcpy(answer, &Name, sizeof(unsigned short));

				curLen += sizeof(unsigned short);



				//类型A
				unsigned short TypeA = htons(0x0001);

				memcpy(answer + curLen, &TypeA, sizeof(unsigned short));

				curLen += sizeof(unsigned short);


				//类型in1
				unsigned short ClassA = htons(0x0001);

				memcpy(answer + curLen, &ClassA, sizeof(unsigned short));

				curLen += sizeof(unsigned short);



				unsigned long timeLive = htonl(0x7b);     

				memcpy(answer + curLen, &timeLive, sizeof(unsigned long));

				curLen += sizeof(unsigned long);



				unsigned short IPLen = htons(0x0004);    //长度：4字节

				memcpy(answer + curLen, &IPLen, sizeof(unsigned short));

				curLen += sizeof(unsigned short);


				//解析出的IP
				unsigned long IP = (unsigned long)inet_addr(DNS_table[find].IP);

				memcpy(answer + curLen, &IP, sizeof(unsigned long));

				curLen += sizeof(unsigned long);

				curLen += iRecv;



				//请求报文和响应部分共同组成DNS响应报文存入sendbuf

				memcpy(sendbuf + iRecv, answer, curLen);



				//发送DNS响应报文

				iSend = sendto(socketLocal, sendbuf, curLen, 0, (SOCKADDR*)&clientName, sizeof(clientName));

				if (iSend == SOCKET_ERROR) {

					printf("send to Failed:%s \n", WSAGetLastError());

					//cout << "sendto Failed: " << WSAGetLastError() << endl;

					continue;

				}

				else if (iSend == 0)

					break;
				else
				{
					if (debug_level == 2)
					{
						printf("Send to %s : %d (%dBytes)  [ID %04x -> %04x]\n", inet_ntoa(serverName.sin_addr), iSend, iSend / 8, *pID, nID);
					}
				}


				free(pID);		//释放动态分配的内存

			}

		}



	}
	closesocket(socketServer);	//关闭套接字
	closesocket(socketLocal);
	WSACleanup();				//释放ws2_32.dll动态链接库初始化时分配的资源

}
