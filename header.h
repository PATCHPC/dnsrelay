#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

using namespace std;
#pragma comment(lib,"wsock32.lib")





typedef struct {
	char* IP;
	char* domain;
}IPTranslate;

typedef struct {
	unsigned short formerID;
	bool DONE;
}IPTransform;


//读取DNS请求中的域名


//判断是否在表中找到DNS请求中的域名，找到返回下标


//将请求ID转换为新的ID并写入ID转换表中


//函数：读取域名解析表
int ReadTable(char* tablePath);


//IO：打印时间、新id、功能、域名、IP
void DisplayInfo(unsigned short newID, int find);
