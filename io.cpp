#include "header.h"

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
	while (fgets(table[i], 100, fp) && i < AMOUNT)
		i++;

	if (i == AMOUNT - 1)
		printf("The DNS table memory is full. \n");

	for (j = 0; j < i - 1; j++) {
		pos = strchr(table[j], ' ');
		if ( (unsigned)abs(pos - table[j]) > strlen(table[j]))
			printf("The record is not in a correct format. \n");
		else {
			strncpy(DNS_table[j].IP, table[j], abs(pos - table[j]));
			strcpy(DNS_table[j].domain, pos);
			//DNS_table[j].IP = table[j].substr(0, pos);
			//DNS_table[j].domain = table[j].substr(pos+1);
		}
	}

	fclose(fp);		//关闭文件
	printf("Load records succeed. \n");

	return i - 1;			//返回域名解析表中条目个数
}



//IO：打印时间、新id、功能、域名、IP
void DisplayInfo(unsigned short newID, int find) {
	//print time
	GetLocalTime(&sys);
	if (sys.wMilliseconds >= Milliseconds)
	{
		printf("%7d", (((sys.wDay - Day) * 24 + sys.wHour - Hour) * 60 + sys.wMinute - Minute) * 60 + sys.wSecond - Second);
		printf(".%03d", sys.wMilliseconds - Milliseconds);
	}
	else
	{
		printf("%7d", (((sys.wDay - Day) * 24 + sys.wHour - Hour) * 60 + sys.wMinute - Minute) * 60 + sys.wSecond - Second - 1);
		printf(".%03d", 1000 + sys.wMilliseconds - Milliseconds);
	}
	printf("    ");

	//print new ID
	printf("%-4u", newID);
	printf("    ");

	//if dns not found
	if (find == NOTFOUND)
	{
		printf("    中继");
		printf("    ");
		//print url
		printf("%-20s", url);
		printf("    ");
		//print IP
		printf("                     \n");

	}
	//ip found
	else
	{
		if (DNS_table[find].IP == "0.0.0.0")
		{
			printf("    屏蔽");
			printf("    ");

			printf("*%-19s", url);
			printf("    ");

			printf("                     \n");
		}
		else
		{
			printf("   服务器");
			printf("    ");

			printf("*%-19s", url);
			printf("    ");

			printf("%-20s\n", DNS_table[find].IP);
		}
	}
}


//输出完整信息？
void standard_print(char* buf, int length)
{
	unsigned char tage;
	printf("receive len=%d: ", length);
	for (int i = 0; i < length; i++)
	{
		tage = (unsigned char)buf[i];
		printf("%02x ", tage);
	}
	printf("\n");
}
