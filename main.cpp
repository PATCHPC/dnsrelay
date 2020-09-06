#pragma once

#include <stdlib.h>

#include <stdio.h>

#include <string.h>

#include <errno.h>

#include <Windows.h>

//#include <WinSock2.h>

//#include <tm32f10x.h>

#include <stdint.h>

#include<time.h>
#include<iostream>

//#include<sys/time.h>
#include<stdint.h>

using namespace std;


#pragma warning(disable:4996)

//using namespace std;

#pragma comment(lib,"wsock32.lib")

//域名解析表最大长度

#define MAX_AMOUNT 500

#define DEFAULT_DNS_ADDRESS "10.3.9.4" //外部DNS服务器地址

#define DEFAULT_LOCAL_ADDRESS "127.0.0.1" //本地DNS服务器地址

#define DNS_PORT 53 //进行DNS服务的53端口

#define BUF_SIZE 1024

#define LENGTH 100

#define NOTFOUND -1

#define AMOUNT 600

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

	BOOL DONE;

	SOCKADDR_IN client;

}IDTransform;

//常量的定义

//为防止重复定义加了extern

IPTranslate DNS_table[MAX_AMOUNT];

IDTransform idTransTable[MAX_AMOUNT];

char url[LENGTH];//域名 （为啥要放全局啊俺也不懂

SYSTEMTIME sys;

int Day, Hour, Minute, Second, Milliseconds;

int IDcount = 0;

/////////////////算法（？）函数////////////////

//读取DNS请求中的域名

void GetUrl(char* recvbuf, int recvnum);

//判断是否在表中找到DNS请求中的域名，找到返回下标

int IsFind(char* url, int num);

//将请求ID转换为新的ID并写入ID转换表中

unsigned short RegisterNewID(unsigned short oID, SOCKADDR_IN temp, BOOL ifdone);

/////////////////// IO ///////////////////

//函数：读取域名解析表

int ReadTable(char* tablePath);

//IO：打印时间、新id、功能、域名、IP

void DisplayInfo(unsigned short newID, int find);


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

	url[k] = '\n';

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

//IO：读取域名解析表并返回域名解析表中的条目个数

int ReadTable(char* tablePath) {

	int i = 0, j;

	char* pos;

	char* table[AMOUNT];

	FILE* fp;

	//ifstream infile(tablePath, ios::in);	//以读入方式打开文本文件

	if ((fp = fopen(tablePath, "rt")) == NULL) {

		printf("Open file error!\n");

		exit(1);

	}

	//每次从文件中读入一行，直至读到文件结束符为止

	table[i] = (char*)malloc(100 * sizeof(char));

	memset(table[i], 0, 100);

	while (fgets(table[i], 100, fp) && i < AMOUNT)

	{

		i++;

		table[i] = (char*)malloc(100 * sizeof(char));

		memset(table[i], 1, 100);

	}

	if (i == AMOUNT)

		printf("The DNS table memory is full. \n");

	for (j = 0; j < i - 1; j++) {

		pos = strchr(table[j], ' ');

		if ((unsigned)abs(pos - table[j]) > strlen(table[j]))

			printf("The record is not in a correct format. \n");

		else {

			//DNS_table[j] = (IPTranslate*)malloc(sizeof(IPTranslate));

			strncpy(DNS_table[j].IP, table[j], abs(pos - table[j]));

			strcpy(DNS_table[j].domain, pos + 1);

			//DNS_table[j].IP = table[j].substr(0, pos);

			//DNS_table[j].domain = table[j].substr(pos+1);

		}

	}

	fclose(fp);		//关闭文件

	printf("Load records succeed. \n");

	return i - 1;			//返回域名解析表中条目个数

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


	for (int i = 0; i < length; i++)

	{

		tage = (unsigned char)buf[i];

		printf("%02x ", tage);

	}
	printf("\n");
	for (int i = 0; i < length; i++)

	{

		tage = (unsigned char)buf[i];
		if (i == 0)
		{
			printf("ID %02x", tage);
		}
		if (i == 1)
			printf("%02x, ", tage);
		if (i == 2)
		{
			printf("QR %x, ", tage >> 7);
			printf("OPCODE %x, ", (tage << 1) >> 4);
			printf("AA %x, ", (tage << 5) >> 7);
			printf("TC %x, ", (tage << 6) >> 7);
			printf("RD %x, ", (tage << 7) >> 7);
		}
		if (i == 3)
		{
			printf("RA %x, ", tage >> 7);
			printf("Z %x, ", (tage << 1) >> 5);
			printf("RCODE %x\n", (tage << 4) >> 4);
		}
		if (i == 4)
		{
			num = (int)tage;
		}
		if (i == 5)
		{
			printf("QDCOUNT %d ,", num * 128 + (int)tage);
		}

		if (i == 6)
		{
			num = (int)tage;
		}
		if (i == 7)
		{
			printf("ANCOUNT %d ,", num * 128 + (int)tage);
		}
		if (i == 8)
		{
			num = (int)tage;
		}
		if (i == 9)
		{
			printf("NSCOUNT %d ,", num * 128 + (int)tage);
		}
		if (i == 10)
		{
			num = (int)tage;
		}
		if (i == 11)
		{
			printf("ARCOUNT %d ", num * 128 + (int)tage);
		}
	}
	printf("\n");

}

int main(int argc, char** argv) {
	   
	//定义常量

	WSADATA wsaData;

	SOCKET  socketServer, socketLocal;				//本地DNS和外部DNS两个套接字

	SOCKADDR_IN serverName, clientName, localName;	//本地DNS、外部DNS和请求端三个网络套接字地址

	char sendbuf[BUF_SIZE];

	char recvbuf[BUF_SIZE];

	char tablePath[100];

	char outerDns[16];

	int iLen_cli, iSend, iRecv;

	int num;

	int i, debug_level = -1;

	int count = 0;

	//分析指令

	//（删）这一块和参考的地方有所区别。[已删]

	GetLocalTime(&sys);

	Day = sys.wDay;

	Hour = sys.wHour;

	Minute = sys.wMinute;

	Second = sys.wSecond;

	Milliseconds = sys.wMilliseconds;

	if (argc == 1)   //只有denrelay，全为默认值

	{

		debug_level = 0;

		strcpy(outerDns, DEFAULT_DNS_ADDRESS);

		strcpy(tablePath, "E:\\adns\\dnsrelay.txt");   //需要加入路径

	}

	else   //有大于1个参数

	{

		if (argv[1][0] == '-')

		{

			if (argv[1][1] == 'd' && argv[1][2] == 'd')  //完整输出

			{

				debug_level = 2;

			}

			else

			{

				debug_level = 1;

			}

			if (argc == 2)  //dnsrelay -dd 或 dnsrelay -d

			{

				strcpy(outerDns, DEFAULT_DNS_ADDRESS);

				strcpy(tablePath, "E:\\adns\\dnsrelay.txt");   //需要加入路径

			}

			else if (argc == 3)

			{

				if (argv[2][0] >= '0' && argv[2][0] <= '9')  //dnsrealy -dd 1.1.1.1 或 dnsrelay -d 1.1.1.1

				{

					strcpy(outerDns, argv[2]);

					strcpy(tablePath, "E:\\adns\\dnsrelay.txt");

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

				strcpy(tablePath, "E:\\adns\\dnsrelay.txt");   //dnsrelay 1.1.1.1 

			}

		}

		else if ((argv[1][0] >= 'A' && argv[1][0] <= 'Z') || (argv[1][0] >= 'a' && argv[1][0] <= 'z'))

		{

			debug_level = 0;

			strcpy(outerDns, DEFAULT_DNS_ADDRESS);

			strcpy(tablePath, argv[1]);  //dnsrelay C:

		}



	}

	//inicialize the ID table

	for (i = 0; i < AMOUNT; i++)

	{

		idTransTable[i].formerID = 0;

		idTransTable[i].DONE = FALSE;

		memset(&(idTransTable[i].client), 0, sizeof(SOCKADDR_IN));

	}

	for (i = 0; i < AMOUNT; i++)

	{

		DNS_table[i].IP = (char*)malloc(30 * sizeof(char));

		memset(DNS_table[i].IP, 0, 30);

		DNS_table[i].domain = (char*)malloc(30 * sizeof(char));

		memset(DNS_table[i].domain, 0, 30);

	}


	WSAStartup(MAKEWORD(2, 2), &wsaData);           //initialize the WinSock service
	//创建本地DNS和外部DNS套接字
	socketServer = socket(AF_INET, SOCK_DGRAM, 0);  //create extern socket

	socketLocal = socket(AF_INET, SOCK_DGRAM, 0);   //create local socket

	//////////////////////////////////////////////////////////////////////
	/*
	int non_block = 1;
	ioctlsocket(socketServer, FIONBIO, (u_long FAR*) & non_block);
	ioctlsocket(socketLocal, FIONBIO, (u_long FAR*) & non_block);*/
	//socketServer = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP);
	//socketLocal = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMP);

	//设置本地DNS和外部DNS两个套接字
	//inicialize the socket

	localName.sin_family = AF_INET;

	localName.sin_port = htons(DNS_PORT);

	localName.sin_addr.s_addr = inet_addr(DEFAULT_LOCAL_ADDRESS); //set to local address
	
	serverName.sin_family = AF_INET;

	serverName.sin_port = htons(DNS_PORT);

	serverName.sin_addr.s_addr = inet_addr(outerDns);  //set to out address

	/////////////////////////////////////////////////////////////////////
	/*
	int reuse = 1;
	setsockopt(socketLocal, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));*/

	if (bind(socketLocal, (SOCKADDR*)&localName, sizeof(localName))) {

		printf("Binding Port 53 failed.\n");

		exit(1);

	}

	else

		printf("Binding Port 53 succeed.\n");


	num = ReadTable(tablePath);  //the number of the table


	//本地DNS中继服务器的具体操作

	while (1) {

		iLen_cli = sizeof(clientName);

		memset(recvbuf, 0, BUF_SIZE);
			   
		//接受DNS请求

		iRecv = recvfrom(socketLocal, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);
		
		memset(&iSend, 0, sizeof(int));

		if (iRecv == SOCKET_ERROR) {
			//	cout << WSAGetLastError();
	//			printf("Recvfrom Failed:%s\n", WSAGetLastError());

			continue;

		}

		else if (iRecv == 0) {//连接已经中止

			break;

		}

		else {
			//iRecv为读入的字节数
			GetUrl(recvbuf, iRecv);				//获取域名

			int find = IsFind(url, num);		//在域名解析表中查找


			if (debug_level == 1)
			{
				printf("%d:  ", count);
				printtime();
				printf("Client: %s ", inet_ntoa(clientName.sin_addr));
				printf(" %s\n", url);
			}
			if (debug_level == 2)
			{
				printf("%d:  ", count);
				printtime();
				printf("RECV from %s : %d (%dBytes)  ", inet_ntoa(clientName.sin_addr), iSend, iSend / 8);
				standard_print(recvbuf, iRecv);
			}
			count++;
			//			printf("%s", url);

						//cout << url << endl;



			//在域名解析表中没有找到

			if (find == NOTFOUND) {

				//ID转换

				unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));

				memcpy(pID, recvbuf, sizeof(unsigned short));

				unsigned short nID = htons(RegisterNewID(ntohs(*pID), clientName, FALSE));

				memcpy(recvbuf, &nID, sizeof(unsigned short));
				//打印 时间 客户端IP 域名 


				//把recvbuf转发至指定的外部DNS服务器

				iSend = sendto(socketServer, recvbuf, iRecv, 0, (SOCKADDR*)&serverName, sizeof(serverName));
				//WSAGetLastError();
				if (iSend == SOCKET_ERROR) {
					//		printf("!!!\n");
					//		printf("sendto Failed:%s\n", WSAGetLastError());

					cout << "sendto Failed: " << WSAGetLastError() << endl;

					continue;

				}

				else if (iSend == 0)

					break;

				else
				{
					if (debug_level == 2)
					{
						printf("Send to %s : %d (%dBytes)  [ID %u -> %u]\n", inet_ntoa(serverName.sin_addr), iSend, iSend / 8, *pID, nID);
					}
				}

				free(pID);	//释放动态分配的内存

				//接收来自外部DNS服务器的响应报文

				iRecv = recvfrom(socketServer, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);

				//ID转换

				pID = (unsigned short*)malloc(sizeof(unsigned short));

				memcpy(pID, recvbuf, sizeof(unsigned short));

				int m = ntohs(*pID);

				unsigned short oID = htons(idTransTable[m].formerID);

				memcpy(recvbuf, &oID, sizeof(unsigned short));

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

				if (iSend == SOCKET_ERROR) {

					//		printf("send to Failed:%s \n", WSAGetLastError());

					cout << "sendto Failed: " << WSAGetLastError() << endl;
					//cout << WSAGetLastError() 

					continue;

				}

				else if (iSend == 0)

					break;

				else
				{
					if (debug_level == 2)
					{
						printf("Send to %s : %d (%dBytes)  [ID %u -> %u]\n", inet_ntoa(serverName.sin_addr), iSend, iSend / 8, *pID, nID);
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

				//打印 时间 newID 功能 域名 IP

		//		DisplayInfo(nID, find);



				//构造响应报文返回

				memcpy(sendbuf, recvbuf, iRecv);						//拷贝请求报文

				unsigned short a = htons(0x8180);

				memcpy(&sendbuf[2], &a, sizeof(unsigned short));		//修改标志域



				//修改回答数域



				if (strcmp(DNS_table[find].IP, "0.0.0.0") == 0)

					a = htons(0x0000);	//屏蔽功能：回答数为0

				else

					a = htons(0x0001);	//服务器功能：回答数为1

				memcpy(&sendbuf[6], &a, sizeof(unsigned short));

				int curLen = 0;



				//构造DNS响应部分

				char answer[16];

				unsigned short Name = htons(0xc00c);

				memcpy(answer, &Name, sizeof(unsigned short));

				curLen += sizeof(unsigned short);



				unsigned short TypeA = htons(0x0001);

				memcpy(answer + curLen, &TypeA, sizeof(unsigned short));

				curLen += sizeof(unsigned short);



				unsigned short ClassA = htons(0x0001);

				memcpy(answer + curLen, &ClassA, sizeof(unsigned short));

				curLen += sizeof(unsigned short);



				unsigned long timeLive = htonl(0x7b);

				memcpy(answer + curLen, &timeLive, sizeof(unsigned long));

				curLen += sizeof(unsigned long);



				unsigned short IPLen = htons(0x0004);

				memcpy(answer + curLen, &IPLen, sizeof(unsigned short));

				curLen += sizeof(unsigned short);



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
						printf("Send to %s : %d (%dBytes)  [ID %u -> %u]\n", inet_ntoa(serverName.sin_addr), iSend, iSend / 8, *pID, nID);
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

