#include "DnsFunc.h"
mutex reqMutex;//请求序列锁
mutex outPutMutex;//输出锁
std::vector<HostInfo> hostInfoVector = {};//本地信息表
std::vector<Request> requestVector = {};//请求vector表
Parameter parameter;//命令行参数

void startWSA()
{
	WORD version = MAKEWORD(2, 2);
	WSADATA data;
	WSAStartup(version, &data);//启动wsc2环境
}

sockaddr_in createSockaddr(int af, int port, std::string ip)
{
	sockaddr_in address = {};
	address.sin_family = af;//ipv4
	address.sin_port = htons(port);//端口
	address.sin_addr.S_un.S_addr = inet_addr(ip.c_str());//将点分制转换为网络字节序列
	return address;
}

void bindSocket(SOCKET& soc, sockaddr_in& address)//绑定地址端口
{
	if (bind(soc, (const sockaddr*)&address, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		printf("BIND failed,the error code is %d\n", WSAGetLastError());
		exit(0);
	}
}

Parameter getParameter(int argc, char* argv[])//获取运行参数
{
	Parameter parameter;
	for (int i = 1; i < argc; i++) {
		std::string s = argv[i];
		if (s == "-d")
			parameter.level = FIRST;
		else if (s == "-dd")
			parameter.level = SECOND;
		else if (s.find(".txt") != s.npos)
			parameter.localFile = s;
		else
			parameter.dnsIp = s;
	}
	return parameter;
}

void getHostInfo(std::string fileName)//读取本地对照表
{
	fstream hostFile;
	hostFile.open(fileName.c_str(), std::ios::in);//只读方式打开文件
	if (hostFile.is_open() == false) {		//打开文件失败
		printf("文件读取失败\n");
		exit(0);
	}
	else {
		std::string tempIp;
		std::string tempDominName;
		HostInfo tempHostInfo;
		while (hostFile >> tempIp) {//读取ip
			hostFile >> tempDominName;//读取域名
			tempHostInfo.ip = tempIp;
			tempHostInfo.domainName = tempDominName;
			hostInfoVector.push_back(tempHostInfo);//加入本地缓存
		}
	}
	hostFile.close();
}

void addReqToVector(Request& request)
{
	reqMutex.lock();//锁住requestVec;
	int i = 0;
	for (i = 0; i < requestVector.size(); i++) {
		if (requestVector[i].isHandling == true) {	//已经处理完 可以覆盖
			requestVector[i] = request;
			break;
		}
	}
	if (i == requestVector.size()) {		//requestVec已经满，需要push_back
		requestVector.push_back(request);
	}
	reqMutex.unlock();//解锁
}

void getReqFromVector(Request& request, bool& isGain)
{
	reqMutex.lock();
	for (int i = 0; i < requestVector.size(); i++) {
		if (requestVector[i].isHandling == false) {//没有在处理中
			requestVector[i].isHandling = true;//在处理中
			request = requestVector[i];
			isGain = true;//得到请求
			break;
		}
	}
	reqMutex.unlock();
}

std::string nameFormat(std::string domainName)
{
	std::string normalDomainName;
	int i = 0;
	while (i < domainName.size()) {
		int size = domainName.at(i);
		for (int j = i + 1; j <= i + size; j++) {
			normalDomainName.push_back(domainName.at(j));
		}
		i = i + size + 1;
		if (i < domainName.size()) {
			normalDomainName.push_back('.');
		}
	}
	return normalDomainName;
}

void handleRequest(SOCKET listenSocket, std::vector<HostInfo> hostInfo)
{
	SOCKET upperSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//创建socket,和上层DNS通讯
	/*******************************解决10054问题**********************************/
	BOOL bNewBehavior = FALSE;
	DWORD dwBytesReturned = 0;
	WSAIoctl(upperSocket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof bNewBehavior, NULL, 0, &dwBytesReturned, NULL, NULL);
	/*******************************解决10054问题**********************************/

	DWORD timeOut = 4000;//4000ms的超时时间
	if (setsockopt(upperSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeOut, sizeof(timeOut)) == -1) {
		printf("socket设定超时时间失败\n");
		exit(0);
	}
	/*
	struct timeval timeout;
	timeout.tv_sec = 5000;
	timeout.tv_usec = 0;//超时时间设为5000ms
	if (setsockopt(upperSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == -1) {
		printf("socket设定超时时间失败\n");
		exit(0);
	}
		https://docs.microsoft.com/zh-cn/windows/desktop/api/winsock/nf-winsock-setsockopt [微软官方文档]
		↓
		Value		Type	Description
		SO_RCVTIMEO	DWORD	Sets the timeout, in milliseconds, for blocking receive calls.
		SO_RCVTIMEO	DWORD	设置阻塞接收的超时(以毫秒为单位)
		
		所以说 timeout中的tv_seconds(单位s)会被转换为[毫秒]
		当设置timeout.tv_sec = 1000时,实际设置超时时间为1000ms = 1s,并不是1000s
	*/
	while (true) {
		Request request;
		bool isGain = false;
		while (isGain == false) {
			Sleep(5);//资源释放 防止cpu过载
			getReqFromVector(request, isGain);
		}
		DnsHeader* head = (DnsHeader*)request.query;
		if (ntohs(head->QDCOUNT) > 1) {	//问题数目大于1个,交给上层处理
			upperHandle(request, listenSocket, upperSocket);
		}
		else {	//问题数目等于1个
			std::string domainName = request.query + sizeof(DnsHeader);//获取域名
			std::string normalDomainName = nameFormat(domainName);//3www5baidu3com0 --> www.baidu.com
			DnsQuestion* question = (DnsQuestion*)(request.query + sizeof(DnsHeader) + domainName.size()+1);
			if (ntohs(question->QTYPE) == 1 && ntohs(question->QCLASS) == 1) {	//IPv4 Internet查询 则现在本地搜索
				int index = 0;
				for (index = 0; index < hostInfo.size(); index++) {
					if (hostInfo[index].domainName == normalDomainName) {
						break;
					}
				}
				if (index == hostInfo.size()) {	//本地未搜索到
					upperHandle(request, listenSocket, upperSocket);//交给上层处理
				}
				else {	//本地搜索到
					hostHandle(request, hostInfo[index].ip, listenSocket);
				}
			}
			else {	//其他类型查询
				upperHandle(request, listenSocket, upperSocket);//交给上层处理
			}			
		}
	}
}
void hostHandle(Request& request, std::string ip,SOCKET listenSocket)
{
	int sendLength = request.dataLength;
	DnsHeader* head = (DnsHeader*)request.query;
	if (ip == "0.0.0.0") {	//非法域名
		head->QOATR = 0x81;
		head->RZR = 0x83;
	}
	else {	//正常域名
		head->QOATR = 0x81;
		head->RZR = 0x80;
		head->ANCOUNT = htons(1);//答案数为1
		
		char* position = request.query + request.dataLength;//指向数据末尾

		unsigned short pointer = 0x0cc0;//“指针”
		memcpy(position, &pointer, sizeof(unsigned short));//填入“指针”
		position = position + sizeof(unsigned short);//指向数据末尾
		
		DnsQuestion question;
		question.QCLASS = htons(1);
		question.QTYPE = htons(1);
		memcpy(position, &question, sizeof(DnsQuestion));
		position = position + sizeof(DnsQuestion);//指向数据末尾

		DnsRecource resource;
		resource.ttl = htonl(86400);//1天的秒数
		resource.dataLength = htons(4);//答案为4字节ip地址 所以此处为4
		memcpy(position, &resource, sizeof(DnsRecource));
		position = position + sizeof(DnsRecource);//指向数据末尾

		unsigned long ipNet = inet_addr(ip.c_str());//IP地址
		memcpy(position, &ipNet, sizeof(unsigned long));

		sendLength = sendLength + sizeof(unsigned short) + sizeof(DnsQuestion) + sizeof(DnsRecource) + sizeof(unsigned long);
	}
	sendto(listenSocket, request.query, sendLength, 0, (const sockaddr*)&request.clientAddress, sizeof(sockaddr_in));//发送给客户

	if (parameter.level == SECOND) {
		Sleep(5);
		outPut(true, true, request.clientAddress, request.query);//输出信息
	}
}


void upperHandle(Request& request, SOCKET listenSocket, SOCKET upperSocket)
{
	char recvBuffer[512];//接收上层应答
	int length = sizeof(sockaddr_in);
	sockaddr_in upperDnsAddr = createSockaddr(AF_INET, 53, parameter.dnsIp.c_str());//上层地址
	unsigned short oldID = *((unsigned short*)(request.query));//记录旧id
	memcpy(request.query, &request.newID, sizeof(unsigned short));//换为新的id
	sendto(upperSocket, request.query, request.dataLength, 0, (const sockaddr*)&upperDnsAddr, sizeof(sockaddr_in));//发送给上层
	int recvLength = recvfrom(upperSocket, recvBuffer, 512, 0, (sockaddr*)&upperDnsAddr, &length);//接收上层的应答
	if (recvLength == SOCKET_ERROR) {	//接收上层应答超时或者出现错误
		int error = WSAGetLastError();
		if (error == 10060) {
			printf("sorry,the Answer packet from upperDNS timeOut\n");
			return;
		}
	}
	else {
		unsigned short* id = (unsigned short*)recvBuffer;//判断ID是否相等
		if (*id == request.newID) {
			*id = oldID;//再换为旧ID
			sendto(listenSocket, recvBuffer, recvLength, 0, (const sockaddr*)&request.clientAddress, sizeof(sockaddr_in));
			if (parameter.level == SECOND) {
				Sleep(5);
				outPut(true, false, request.clientAddress, recvBuffer);//输出信息
			}
		}
	}
}

struct tm getNowTime()
{
	struct tm t;
	time_t now = time(NULL);
	localtime_s(&t, &now);
	return t;
}

void outPut(bool isSend, bool isMyAnswer,sockaddr_in clientAddress,char* buffer)
{
	outPutMutex.lock();//输出锁住,否则多个线程输出会乱序
	if (isSend == false) {
		struct tm time = getNowTime();//获取当前时间
		DnsHeader* head = (DnsHeader*)buffer;
		std::string ip =  inet_ntoa(clientAddress.sin_addr);//获取客户端地址
		std::string domainName = buffer + sizeof(DnsHeader);//只获取第一个域名
		domainName = nameFormat(domainName);
		printf("----------------------------------------------------------------------\n");
		printf("QUERY packet\n");
		printf("Time:[%d/%d/%d %d:%d:%d]\n", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday
			, time.tm_hour, time.tm_min, time.tm_sec);
		printf("Receive from CLIENT,IP:[%s]\n", ip.c_str());
		printf("ID:[%hu]\n", ntohs(head->ID));
		printf("QDCOUNT:[%hu]\n", ntohs(head->QDCOUNT));
		printf("DomainName:[%s]\n", domainName.c_str());
		printf("----------------------------------------------------------------------\n");
	}
	else {
		struct tm time = getNowTime();
		DnsHeader* tempHead = (DnsHeader*)buffer;
		unsigned char QR = (tempHead->QOATR & 0x80) >> 7;
		unsigned char OPCODE = (tempHead->QOATR & 0x78) >> 3;
		unsigned char AA = (tempHead->QOATR & 0x04) >> 2;
		unsigned char TC = (tempHead->QOATR & 0x02) >> 1;
		unsigned char RD = (tempHead->QOATR & 0x01);
		unsigned char RA = (tempHead->RZR & 0x80) >> 7;
		unsigned char ZERO = (tempHead->RZR & 0x70) >> 4;
		unsigned char RCODE = (tempHead->RZR & 0x0F);
	
		std::string ip = inet_ntoa(clientAddress.sin_addr);
		std::string domainName = (buffer + sizeof(DnsHeader));
		std::string normalDomainName = nameFormat(domainName);//转换域名
		
		printf("ANSWER packet\n");
		printf("Time   :[%d/%d/%d %d:%d:%02d]\n", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday
			, time.tm_hour, time.tm_min, time.tm_sec);
		if (isMyAnswer == true) {
			printf("The packet is MY ANSWER,send to client[%s]\n", ip.c_str());
		}
		else {
			printf("Receive from UPPERDNS,send to client[%s]\n", ip.c_str());
		}
		printf("ID     :[%hu]\n", ntohs(tempHead->ID));
		printf("Flags  :[QR:%d|OPCODE:%d|AA:%d|TC:%d|RD:%d|RA:%d|ZERO:%d|RCODE:%d]\n", QR, OPCODE, AA, TC, RD, RA, ZERO, RCODE);
		printf("Number :[QDCOUNT:%hu|ANCOUNT:%hu|NSCOUNT:%hu|ARCOUNT:%hu]\n"
			,ntohs(tempHead->QDCOUNT), ntohs(tempHead->ANCOUNT), ntohs(tempHead->NSCOUNT), ntohs(tempHead->ARCOUNT));
		printf("Query  :DomainName:[%s]\n", normalDomainName.c_str());

		DnsQuestion* tempQuestion = (DnsQuestion*)(buffer + sizeof(DnsHeader) + domainName.size() + 1);
		printf("        [TYPE:%hu|CLASS:%hu]\n", ntohs(tempQuestion->QTYPE), ntohs(tempQuestion->QCLASS));

		if (ntohs(tempQuestion->QTYPE) == 1 && ntohs(tempQuestion->QCLASS) == 1 && ntohs(tempHead->QDCOUNT) == 1) {
			char* temp = buffer + sizeof(DnsHeader) + domainName.size() + 1 + sizeof(DnsQuestion);//此时temp指向答案的起始位置
			for (int i = 0; i < ntohs(tempHead->ANCOUNT); i++) { //对答案解析
				unsigned char* pointer = (unsigned char*)temp;
				int count = 0;//记录非指针记录个数
				while ((pointer[count] >> 6) != 0x03 && pointer[count]!= '\0') {
					count++;
				}
				if (pointer[count] != '\0') {
					temp = temp + 2 + count;
				}
				else {
					temp = temp + count;
				}
				tempQuestion = (DnsQuestion*)temp;
				printf("Answer%d:[TYPE:%hu|CLASS:%hu]\n", i, ntohs(tempQuestion->QTYPE), ntohs(tempQuestion->QCLASS));
				
				temp = temp + sizeof(DnsQuestion);
				DnsRecource* tempResource = (DnsRecource*)temp;
				printf("	[ttl:%d|dataLength:%hu]\n", ntohl(tempResource->ttl), ntohs(tempResource->dataLength));
				temp = temp + sizeof(DnsRecource);
				
				if (ntohs(tempQuestion->QTYPE) != 1 || ntohs(tempQuestion->QCLASS) != 1 || ntohs(tempResource->dataLength)!=4) {
					printf("Answer%d is not IPV4 or Internet\n",i);
					
				}
				else {
					unsigned long* ip = (unsigned long*)temp;
					struct sockaddr_in ipAdress ;
					ipAdress.sin_addr.S_un.S_addr = *ip;
					std::string IpPoint =  inet_ntoa(ipAdress.sin_addr);
					printf("*****IP:[%s]\n", IpPoint.c_str());
				}
				temp = temp + ntohs(tempResource->dataLength);
			}
		}
		printf("----------------------------------------------------------------------\n");
	}
	outPutMutex.unlock();//解锁
}



