#include "DnsFunc.h"
mutex reqMutex;//����������
mutex outPutMutex;//�����
std::vector<HostInfo> hostInfoVector = {};//������Ϣ��
std::vector<Request> requestVector = {};//����vector��
Parameter parameter;//�����в���

void startWSA()
{
	WORD version = MAKEWORD(2, 2);
	WSADATA data;
	WSAStartup(version, &data);//����wsc2����
}

sockaddr_in createSockaddr(int af, int port, std::string ip)
{
	sockaddr_in address = {};
	address.sin_family = af;//ipv4
	address.sin_port = htons(port);//�˿�
	address.sin_addr.S_un.S_addr = inet_addr(ip.c_str());//�������ת��Ϊ�����ֽ�����
	return address;
}

void bindSocket(SOCKET& soc, sockaddr_in& address)//�󶨵�ַ�˿�
{
	if (bind(soc, (const sockaddr*)&address, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		printf("BIND failed,the error code is %d\n", WSAGetLastError());
		exit(0);
	}
}

Parameter getParameter(int argc, char* argv[])//��ȡ���в���
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

void getHostInfo(std::string fileName)//��ȡ���ض��ձ�
{
	fstream hostFile;
	hostFile.open(fileName.c_str(), std::ios::in);//ֻ����ʽ���ļ�
	if (hostFile.is_open() == false) {		//���ļ�ʧ��
		printf("�ļ���ȡʧ��\n");
		exit(0);
	}
	else {
		std::string tempIp;
		std::string tempDominName;
		HostInfo tempHostInfo;
		while (hostFile >> tempIp) {//��ȡip
			hostFile >> tempDominName;//��ȡ����
			tempHostInfo.ip = tempIp;
			tempHostInfo.domainName = tempDominName;
			hostInfoVector.push_back(tempHostInfo);//���뱾�ػ���
		}
	}
	hostFile.close();
}

void addReqToVector(Request& request)
{
	reqMutex.lock();//��סrequestVec;
	int i = 0;
	for (i = 0; i < requestVector.size(); i++) {
		if (requestVector[i].isHandling == true) {	//�Ѿ������� ���Ը���
			requestVector[i] = request;
			break;
		}
	}
	if (i == requestVector.size()) {		//requestVec�Ѿ�������Ҫpush_back
		requestVector.push_back(request);
	}
	reqMutex.unlock();//����
}

void getReqFromVector(Request& request, bool& isGain)
{
	reqMutex.lock();
	for (int i = 0; i < requestVector.size(); i++) {
		if (requestVector[i].isHandling == false) {//û���ڴ�����
			requestVector[i].isHandling = true;//�ڴ�����
			request = requestVector[i];
			isGain = true;//�õ�����
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
	SOCKET upperSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//����socket,���ϲ�DNSͨѶ
	/*******************************���10054����**********************************/
	BOOL bNewBehavior = FALSE;
	DWORD dwBytesReturned = 0;
	WSAIoctl(upperSocket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof bNewBehavior, NULL, 0, &dwBytesReturned, NULL, NULL);
	/*******************************���10054����**********************************/

	DWORD timeOut = 4000;//4000ms�ĳ�ʱʱ��
	if (setsockopt(upperSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeOut, sizeof(timeOut)) == -1) {
		printf("socket�趨��ʱʱ��ʧ��\n");
		exit(0);
	}
	/*
	struct timeval timeout;
	timeout.tv_sec = 5000;
	timeout.tv_usec = 0;//��ʱʱ����Ϊ5000ms
	if (setsockopt(upperSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == -1) {
		printf("socket�趨��ʱʱ��ʧ��\n");
		exit(0);
	}
		https://docs.microsoft.com/zh-cn/windows/desktop/api/winsock/nf-winsock-setsockopt [΢��ٷ��ĵ�]
		��
		Value		Type	Description
		SO_RCVTIMEO	DWORD	Sets the timeout, in milliseconds, for blocking receive calls.
		SO_RCVTIMEO	DWORD	�����������յĳ�ʱ(�Ժ���Ϊ��λ)
		
		����˵ timeout�е�tv_seconds(��λs)�ᱻת��Ϊ[����]
		������timeout.tv_sec = 1000ʱ,ʵ�����ó�ʱʱ��Ϊ1000ms = 1s,������1000s
	*/
	while (true) {
		Request request;
		bool isGain = false;
		while (isGain == false) {
			Sleep(5);//��Դ�ͷ� ��ֹcpu����
			getReqFromVector(request, isGain);
		}
		DnsHeader* head = (DnsHeader*)request.query;
		if (ntohs(head->QDCOUNT) > 1) {	//������Ŀ����1��,�����ϲ㴦��
			upperHandle(request, listenSocket, upperSocket);
		}
		else {	//������Ŀ����1��
			std::string domainName = request.query + sizeof(DnsHeader);//��ȡ����
			std::string normalDomainName = nameFormat(domainName);//3www5baidu3com0 --> www.baidu.com
			DnsQuestion* question = (DnsQuestion*)(request.query + sizeof(DnsHeader) + domainName.size()+1);
			if (ntohs(question->QTYPE) == 1 && ntohs(question->QCLASS) == 1) {	//IPv4 Internet��ѯ �����ڱ�������
				int index = 0;
				for (index = 0; index < hostInfo.size(); index++) {
					if (hostInfo[index].domainName == normalDomainName) {
						break;
					}
				}
				if (index == hostInfo.size()) {	//����δ������
					upperHandle(request, listenSocket, upperSocket);//�����ϲ㴦��
				}
				else {	//����������
					hostHandle(request, hostInfo[index].ip, listenSocket);
				}
			}
			else {	//�������Ͳ�ѯ
				upperHandle(request, listenSocket, upperSocket);//�����ϲ㴦��
			}			
		}
	}
}
void hostHandle(Request& request, std::string ip,SOCKET listenSocket)
{
	int sendLength = request.dataLength;
	DnsHeader* head = (DnsHeader*)request.query;
	if (ip == "0.0.0.0") {	//�Ƿ�����
		head->QOATR = 0x81;
		head->RZR = 0x83;
	}
	else {	//��������
		head->QOATR = 0x81;
		head->RZR = 0x80;
		head->ANCOUNT = htons(1);//����Ϊ1
		
		char* position = request.query + request.dataLength;//ָ������ĩβ

		unsigned short pointer = 0x0cc0;//��ָ�롱
		memcpy(position, &pointer, sizeof(unsigned short));//���롰ָ�롱
		position = position + sizeof(unsigned short);//ָ������ĩβ
		
		DnsQuestion question;
		question.QCLASS = htons(1);
		question.QTYPE = htons(1);
		memcpy(position, &question, sizeof(DnsQuestion));
		position = position + sizeof(DnsQuestion);//ָ������ĩβ

		DnsRecource resource;
		resource.ttl = htonl(86400);//1�������
		resource.dataLength = htons(4);//��Ϊ4�ֽ�ip��ַ ���Դ˴�Ϊ4
		memcpy(position, &resource, sizeof(DnsRecource));
		position = position + sizeof(DnsRecource);//ָ������ĩβ

		unsigned long ipNet = inet_addr(ip.c_str());//IP��ַ
		memcpy(position, &ipNet, sizeof(unsigned long));

		sendLength = sendLength + sizeof(unsigned short) + sizeof(DnsQuestion) + sizeof(DnsRecource) + sizeof(unsigned long);
	}
	sendto(listenSocket, request.query, sendLength, 0, (const sockaddr*)&request.clientAddress, sizeof(sockaddr_in));//���͸��ͻ�

	if (parameter.level == SECOND) {
		Sleep(5);
		outPut(true, true, request.clientAddress, request.query);//�����Ϣ
	}
}


void upperHandle(Request& request, SOCKET listenSocket, SOCKET upperSocket)
{
	char recvBuffer[512];//�����ϲ�Ӧ��
	int length = sizeof(sockaddr_in);
	sockaddr_in upperDnsAddr = createSockaddr(AF_INET, 53, parameter.dnsIp.c_str());//�ϲ��ַ
	unsigned short oldID = *((unsigned short*)(request.query));//��¼��id
	memcpy(request.query, &request.newID, sizeof(unsigned short));//��Ϊ�µ�id
	sendto(upperSocket, request.query, request.dataLength, 0, (const sockaddr*)&upperDnsAddr, sizeof(sockaddr_in));//���͸��ϲ�
	int recvLength = recvfrom(upperSocket, recvBuffer, 512, 0, (sockaddr*)&upperDnsAddr, &length);//�����ϲ��Ӧ��
	if (recvLength == SOCKET_ERROR) {	//�����ϲ�Ӧ��ʱ���߳��ִ���
		int error = WSAGetLastError();
		if (error == 10060) {
			printf("sorry,the Answer packet from upperDNS timeOut\n");
			return;
		}
	}
	else {
		unsigned short* id = (unsigned short*)recvBuffer;//�ж�ID�Ƿ����
		if (*id == request.newID) {
			*id = oldID;//�ٻ�Ϊ��ID
			sendto(listenSocket, recvBuffer, recvLength, 0, (const sockaddr*)&request.clientAddress, sizeof(sockaddr_in));
			if (parameter.level == SECOND) {
				Sleep(5);
				outPut(true, false, request.clientAddress, recvBuffer);//�����Ϣ
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
	outPutMutex.lock();//�����ס,�������߳����������
	if (isSend == false) {
		struct tm time = getNowTime();//��ȡ��ǰʱ��
		DnsHeader* head = (DnsHeader*)buffer;
		std::string ip =  inet_ntoa(clientAddress.sin_addr);//��ȡ�ͻ��˵�ַ
		std::string domainName = buffer + sizeof(DnsHeader);//ֻ��ȡ��һ������
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
		std::string normalDomainName = nameFormat(domainName);//ת������
		
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
			char* temp = buffer + sizeof(DnsHeader) + domainName.size() + 1 + sizeof(DnsQuestion);//��ʱtempָ��𰸵���ʼλ��
			for (int i = 0; i < ntohs(tempHead->ANCOUNT); i++) { //�Դ𰸽���
				unsigned char* pointer = (unsigned char*)temp;
				int count = 0;//��¼��ָ���¼����
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
	outPutMutex.unlock();//����
}



