#include "header.h"

//IO：读取域名解析表并返回域名解析表中的条目个数
int ReadTable(char* tablePath) {
	int i=0, j, pos=0;
	string table[AMOUNT];

	ifstream infile(tablePath, ios::in);	//以读入方式打开文本文件

	if(! infile) {
		cerr << "Open" << tablePath << "error!" <<endl;
		exit(1);
	}

	//每次从文件中读入一行，直至读到文件结束符为止
	while (getline(infile, table[i]) && i < AMOUNT)
		i++;

	if (i == AMOUNT-1)
		cout << "The DNS table memory is full. " << endl;

	for (j = 0; j < i-1; j++) {
		pos = table[j].find(' ');
		if (pos > table[j].size())
			cout << "The record is not in a correct format. " << endl;
		else {
			dnsTable[j].IP = table[j].substr(0, pos);
			dnsTable[j].domain = table[j].substr(pos+1);
		}
	}

	infile.close();		//关闭文件
	cout << "Load records succeed. " << endl;

	return i-1;			//返回域名解析表中条目个数
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
		if (dnsTable[find].IP == "0.0.0.0")
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

			printf("%-20s\n", dnsTable[find].IP);
		}
	}
}


//输出完整信息？
void standard_print(char* buf, int length)
{
	unsigned char tage;
	printf("receive len=%d: ", length);
	for (int i = 0;i < length;i++)
	{
		tage = (unsigned char)buf[i];
		printf("%02x ", tage);
	}
	printf("\n");
}