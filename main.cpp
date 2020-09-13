#include <iostream>
#include <thread>
#include "DnsFunc.h"

const int THREADNUM = 30;//线程数
const unsigned short MAXID = 0xffff;
int main(int argc,char* argv[])
{
	parameter = getParameter(argc, argv);//获取运行参数
	getHostInfo(parameter.localFile);//获取本地信息
	if (parameter.level != ZEROTH) {
		printf("Designed by Liuxiangyu & ZhaiYu & WangSiFan\n");
		printf("Successfully read of %d local messages\n",hostInfoVector.size());
		printf("The IP of uppperDNS is [%s]\n", parameter.dnsIp.c_str());
	}
	startWSA();//启动WSA环境
	SOCKET listenSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//ipv4 报文 UDP

	/*************解决10054问题*********************/
	BOOL bNewBehavior = FALSE;
	DWORD dwBytesReturned = 0;
	WSAIoctl(listenSocket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof bNewBehavior, NULL, 0, &dwBytesReturned, NULL, NULL);
	/*************解决10054问题*********************/


	sockaddr_in myAddress = createSockaddr(AF_INET, 53, "0.0.0.0");//创建网络对象
	bindSocket(listenSocket, myAddress);//绑定端口
//-----------------------------------初始化完成------------------------------------------------------------------
//-----------------------------------初始化完成------------------------------------------------------------------
	//创建线程,实现并发处理设为THREADNUM个
	thread handleThread[THREADNUM];
	for (int i = 0; i < THREADNUM; i++) {
		handleThread[i] = thread(handleRequest, listenSocket,hostInfoVector);//1025~65534
	}

	unsigned short id = 0;
	sockaddr_in clientAddress;//客户端信息(ip 端口)
	int addrLength = sizeof(sockaddr_in);//长度
	unsigned short newID = 0;
	while (true) {
		char requestBuffer[512];//接收请求缓冲区
		int recvLength = recvfrom(listenSocket, requestBuffer, 512, 0, (sockaddr*)&clientAddress, &addrLength);
		
		if (recvLength == SOCKET_ERROR) {
			if (parameter.level == SECOND) {
				printf("Receive CLIENT failed,the error code is %d\n", WSAGetLastError());
			}
			continue;
		}
		else {
			Request temp;
			temp.isHandling = false;
			temp.newID = (id++) % MAXID;
			temp.clientAddress = clientAddress;
			temp.dataLength = recvLength;
			memcpy(temp.query, requestBuffer, recvLength);
			addReqToVector(temp);
			if (parameter.level != ZEROTH) {
				outPut(false, false, clientAddress, requestBuffer);
			}
		}
	}
	for (int i = 0; i < THREADNUM; i++) {
		if (handleThread[i].joinable()) {
			handleThread[i].join();
		}
	}
}