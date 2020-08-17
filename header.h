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

#pragma warning(disable:4996)


//using namespace std;
#pragma comment(lib,"wsock32.lib")


//域名解析表最大长度
#define MAX_AMOUNT 500
#define DEFAULT_DNS_ADDRESS "192.168.146.2" //外部DNS服务器地址
#define DEFAULT_LOCAL_ADDRESS "127.0.0.1" //本地DNS服务器地址
#define DNS_PORT 53 //进行DNS服务的53端口
#define BUF_SIZE 512
#define LENGTH 65
#define NOTFOUND -1
#define AMOUNT 1


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
extern IPTranslate DNS_table[MAX_AMOUNT];
extern IDTransform idTransTable[MAX_AMOUNT];
extern char url[LENGTH];//域名 （为啥要放全局啊俺也不懂

SYSTEMTIME sys;
extern int Day, Hour, Minute, Second, Milliseconds;

extern int IDcount = 0;
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
