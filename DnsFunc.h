#pragma once
#pragma comment(lib,"ws2_32.lib")//链接ws2_32库
#define _WINSOCK_DEPRECATED_NO_WARNINGS//忽略Winsocket一些API警告
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)//处理 Winsocket 10054错误

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
};//运行等级 [无|-d|-dd]

struct Parameter {
	cmdLevel level = ZEROTH;//默认0级输出
	std::string dnsIp = "10.3.9.5";//默认DNS为10.3.9.5
	std::string localFile = "dnsrelay.txt";//默认本地文件为 dnsrelay.txt
};//运行参数

struct HostInfo {
	std::string ip;//32位ip地址
	std::string domainName;//域名
};//本地txt信息

struct Request {
	bool isHandling = true;//是否正在被处理
	unsigned short newID;//新分配的ID
	char query[512];//缓存问题
	int dataLength;
	sockaddr_in clientAddress;//客户端信息
};

extern std::vector<Request> requestVector;//缓存客户端发来的请求
extern std::vector<HostInfo> hostInfoVector;//缓存本地txt信息
extern Parameter parameter;//命令行参数
extern mutex reqMutex;//访问requestVec锁
extern mutex outPutMutex;//输出信息锁

void startWSA();//启动WSA环境
sockaddr_in createSockaddr(int af,int port,std::string ip);//创建网络对象
void bindSocket(SOCKET& soc,sockaddr_in& address);//绑定套接字
Parameter getParameter(int argc,char* argv[]);//获取运行参数
void getHostInfo(std::string fileName);//读取本地对照表
void addReqToVector(Request& request);//将客户端请求加入到请求序列中
void getReqFromVector(Request& request,bool& isGain);//从请求序列中获取请求
void handleRequest(SOCKET listenSocket,std::vector<HostInfo> hostInfo);//处理请求
void upperHandle(Request& request,SOCKET listenSocket,SOCKET upperSocket);//交付上层处理
void hostHandle(Request& request, std::string ip, SOCKET listenSocket);//本地处理
std::string nameFormat(std::string domainName);//3www5baidu3com0 -> www.baidu.com
void outPut(bool isSend,bool isMyAnswer,sockaddr_in clientRequest,char* sendBuffer);//输出信息
struct tm getNowTime();//获取当前时间


