#include "header.h"

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
	int i, debug_level;
	//分析指令
	//（删）这一块和参考的地方有所区别。[已删]
	WSAStartup(MAKEWORD(2, 2), &wsaData);           //initialize the WinSock service
	socketServer = socket(AF_INET, SOCK_DGRAM, 0);  //create extern socket
	socketLocal = socket(AF_INET, SOCK_DGRAM, 0);   //create local socket

	//keep time
	GetLocalTime(&sys);
	Day = sys.wDay;
	Hour = sys.wHour;
	Minute = sys.wMinute;
	Second = sys.wSecond;
	Milliseconds = sys.wMilliseconds;

	//inicialize the socket
	localName.sin_family = AF_INET;
	localName.sin_port = htons(DNS_PORT);
	localName.sin_addr.s_addr = inet_addr(DEFAULT_LOCAL_ADDRESS); //set to local address

	serverName.sin_family = AF_INET;
	serverName.sin_port = htons(DNS_PORT);
	serverName.sin_addr.s_addr = inet_addr(outerDns);  //set to out address

	//inicialize the ID table
	for (i = 0; i < AMOUNT; i++)
	{
		idTransTable[i].formerID = 0;
		idTransTable[i].DONE = FALSE;
		memset(&(idTransTable[i].client), 0, sizeof(SOCKADDR_IN));
	}

	//process parameter
	for (i = 1; i < argc; ++i)
	{
		if (argv[i][0] == '-')
		{
			if (argv[i][1] == 'd' && argv[i][2] == 'd')
			{
				debug_level = 2;
				strcpy(outerDns, argv[2]);
				strcpy(tablePath, "...dnsrelay.txt");     //需要加入路径
			}
			else
			{
				debug_level = 1;
				strcpy(outerDns, argv[2]);
				strcpy(tablePath, argv[3]);
			}
		}
		else
		{
			debug_level = 0;
			strcpy(outerDns, DEFAULT_DNS_ADDRESS);
			strcpy(tablePath, "....dnsrelay.txt");   //需要加入路径
		}
	}
	num = ReadTable(tablePath);  //the number of the table

	if (bind(socketLocal, (SOCKADDR*)&localName, sizeof(localName))) {
		printf("Binding Port 53 failed.\n");
		exit(1);
	}
	else
		printf("Binding Port 53 succeed.\n");


	//本地DNS中继服务器的具体操作
	while (1) {
		iLen_cli = sizeof(clientName);
		memset(recvbuf, 0, BUF_SIZE);

		//接受DNS请求
		iRecv = recvfrom(socketLocal, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&clientName, &iLen_cli);

		if (iRecv == SOCKET_ERROR) {
			printf("Recvfrom Failed:%s\n", WSAGetLastError());
			continue;
		}
		else if (iRecv == 0) {
			break;
		}
		else {
			GetUrl(recvbuf, iRecv);				//获取域名
			int find = IsFind(url, num);		//在域名解析表中查找

			printf("%s", url);
			//cout << url << endl;

			//在域名解析表中没有找到
			if (find == NOTFOUND) {
				//ID转换
				unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
				memcpy(pID, recvbuf, sizeof(unsigned short));
				unsigned short nID = htons(RegisterNewID(ntohs(*pID), clientName, FALSE));
				memcpy(recvbuf, &nID, sizeof(unsigned short));

				//打印 时间 newID 功能 域名 IP
				DisplayInfo(ntohs(nID), find);

				//把recvbuf转发至指定的外部DNS服务器
				iSend = sendto(socketServer, recvbuf, iRecv, 0, (SOCKADDR*)&serverName, sizeof(serverName));
				if (iSend == SOCKET_ERROR) {
					printf("sendto Failed:s%\n", WSAGetLastError());
					//cout << "sendto Failed: " << WSAGetLastError() << endl;
					continue;
				}
				else if (iSend == 0)
					break;

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

				//从ID转换表中获取发出DNS请求者的信息
				clientName = idTransTable[m].client;

				//把recvbuf转发至请求者处
				iSend = sendto(socketLocal, recvbuf, iRecv, 0, (SOCKADDR*)&clientName, sizeof(clientName));
				if (iSend == SOCKET_ERROR) {
					printf("send to Failed:s%\n", WSAGetLastError());
					//cout << "sendto Failed: " << WSAGetLastError() << endl;
					continue;
				}
				else if (iSend == 0)
					break;

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
				DisplayInfo(nID, find);

				//构造响应报文返回
				memcpy(sendbuf, recvbuf, iRecv);						//拷贝请求报文
				unsigned short a = htons(0x8180);
				memcpy(&sendbuf[2], &a, sizeof(unsigned short));		//修改标志域

				//修改回答数域

				if (strcmp(dnsTable[find].IP, "0.0.0.0") == 0)
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

				unsigned long IP = (unsigned long)inet_addr(dnsTable[find].IP);
				memcpy(answer + curLen, &IP, sizeof(unsigned long));
				curLen += sizeof(unsigned long);
				curLen += iRecv;

				//请求报文和响应部分共同组成DNS响应报文存入sendbuf
				memcpy(sendbuf + iRecv, answer, curLen);

				//发送DNS响应报文
				iSend = sendto(socketLocal, sendbuf, curLen, 0, (SOCKADDR*)&clientName, sizeof(clientName));
				if (iSend == SOCKET_ERROR) {
					printf("send to Failed:s%\n", WSAGetLastError());
					//cout << "sendto Failed: " << WSAGetLastError() << endl;
					continue;
				}
				else if (iSend == 0)
					break;

				free(pID);		//释放动态分配的内存
			}
		}

	}
