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
			DNS_table[j].IP = table[j].substr(0, pos);
			DNS_table[j].domain = table[j].substr(pos+1);
		}
	}

	infile.close();		//关闭文件
	cout << "Load records succeed. " << endl;

	return i-1;			//返回域名解析表中条目个数
}



//IO：打印时间、新id、功能、域名、IP
void DisplayInfo(unsigned short newID, int find) {

}
