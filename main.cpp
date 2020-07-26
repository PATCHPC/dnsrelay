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

	//分析指令
	//（删）这一块和参考的地方有所区别。
	if (argc == 1) {
		strcpy(outerDns, DEFAULT_DNS_ADDRESS);
		strcpy(tablePath, "");
	}
	else if (argc == 2) {
		strcpy(outerDns, argv[1]);
		strcpy(tablePath, "C:\\Windows\\System32\\dnsrelay.txt");
	}
	else if (argc == 3) {
		strcpy(outerDns, argv[1]);
		strcpy(tablePath, argv[2]);
	}
}
