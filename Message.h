#pragma once

struct DnsHeader {
	unsigned short ID;//16位标识符
	unsigned char  QOATR;//QR-1位 OPCODE-4位 AA-1位 TC-1位 RD-1位
/*
	QR 1位 0表示查询报 1表示响应报                        
	OPCODE 4位 0表示标准查询 1表示反向查询 2表示服务器状态	
	AA 1位 1表示权威回答 0表示非权威回答					
	TC 1位 1表示报文长度大于512字节,截断					
	RD 1位 1表示期望递归,0表示期望迭代						
*/
	unsigned char RZR;//RA-1位 Z-3位 RCODE-4位
/*
	RA 1位 1表示服务器支持递归查询,0表示不支持	
	Z 3位 必须为0,保留字段
	RCODE 4位 0表示无差错,3表示名字差错,2表示服务器错误	
*/
	unsigned short QDCOUNT;//16位整数 问题数目
	unsigned short ANCOUNT;//16位整数 答案资源数目
	unsigned short NSCOUNT;//16位整数 授权资源数目
	unsigned short ARCOUNT;//16位整数 附加资源数目
};

//问题部分
//因查询名的长度未知,所以暂且不写入结构体
struct DnsQuestion {
	unsigned short QTYPE;//查询类型 1->ip地址
	unsigned short QCLASS;//查询类 1->互联网地址
};

#pragma pack (1)
struct DnsRecource {
	int ttl;//生存时间
	unsigned short dataLength;
};
#pragma pack()