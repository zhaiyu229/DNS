#pragma once
#pragma comment(lib,"ws2_32.lib")//����ws2_32��
#define _WINSOCK_DEPRECATED_NO_WARNINGS//����WinsocketһЩAPI����
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)//���� Winsocket 10054����

#include <WinSock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <mutex>
#include <ctime>
#include "Message.h"
using std::mutex;
using std::fstream;
using std::thread;


enum cmdLevel{
	ZEROTH, 
	FIRST,
	SECOND 
};//���еȼ� [��|-d|-dd]

struct Parameter {
	cmdLevel level = ZEROTH;//Ĭ��0�����
	std::string dnsIp = "10.3.9.5";//Ĭ��DNSΪ10.3.9.5
	std::string localFile = "dnsrelay.txt";//Ĭ�ϱ����ļ�Ϊ dnsrelay.txt
};//���в���

struct HostInfo {
	std::string ip;//32λip��ַ
	std::string domainName;//����
};//����txt��Ϣ

struct Request {
	bool isHandling = true;//�Ƿ����ڱ�����
	unsigned short newID;//�·����ID
	char query[512];//��������
	int dataLength;
	sockaddr_in clientAddress;//�ͻ�����Ϣ
};

extern std::vector<Request> requestVector;//����ͻ��˷���������
extern std::vector<HostInfo> hostInfoVector;//���汾��txt��Ϣ
extern Parameter parameter;//�����в���
extern mutex reqMutex;//����requestVec��
extern mutex outPutMutex;//�����Ϣ��

void startWSA();//����WSA����
sockaddr_in createSockaddr(int af,int port,std::string ip);//�����������
void bindSocket(SOCKET& soc,sockaddr_in& address);//���׽���
Parameter getParameter(int argc,char* argv[]);//��ȡ���в���
void getHostInfo(std::string fileName);//��ȡ���ض��ձ�
void addReqToVector(Request& request);//���ͻ���������뵽����������
void getReqFromVector(Request& request,bool& isGain);//�����������л�ȡ����
void handleRequest(SOCKET listenSocket,std::vector<HostInfo> hostInfo);//��������
void upperHandle(Request& request,SOCKET listenSocket,SOCKET upperSocket);//�����ϲ㴦��
void hostHandle(Request& request, std::string ip, SOCKET listenSocket);//���ش���
std::string nameFormat(std::string domainName);//3www5baidu3com0 -> www.baidu.com
void outPut(bool isSend,bool isMyAnswer,sockaddr_in clientRequest,char* sendBuffer);//�����Ϣ
struct tm getNowTime();//��ȡ��ǰʱ��


