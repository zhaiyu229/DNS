#pragma once

struct DnsHeader {
	unsigned short ID;//16λ��ʶ��
	unsigned char  QOATR;//QR-1λ OPCODE-4λ AA-1λ TC-1λ RD-1λ
/*
	QR 1λ 0��ʾ��ѯ�� 1��ʾ��Ӧ��                        
	OPCODE 4λ 0��ʾ��׼��ѯ 1��ʾ�����ѯ 2��ʾ������״̬	
	AA 1λ 1��ʾȨ���ش� 0��ʾ��Ȩ���ش�					
	TC 1λ 1��ʾ���ĳ��ȴ���512�ֽ�,�ض�					
	RD 1λ 1��ʾ�����ݹ�,0��ʾ��������						
*/
	unsigned char RZR;//RA-1λ Z-3λ RCODE-4λ
/*
	RA 1λ 1��ʾ������֧�ֵݹ��ѯ,0��ʾ��֧��	
	Z 3λ ����Ϊ0,�����ֶ�
	RCODE 4λ 0��ʾ�޲��,3��ʾ���ֲ��,2��ʾ����������	
*/
	unsigned short QDCOUNT;//16λ���� ������Ŀ
	unsigned short ANCOUNT;//16λ���� ����Դ��Ŀ
	unsigned short NSCOUNT;//16λ���� ��Ȩ��Դ��Ŀ
	unsigned short ARCOUNT;//16λ���� ������Դ��Ŀ
};

//���ⲿ��
//���ѯ���ĳ���δ֪,�������Ҳ�д��ṹ��
struct DnsQuestion {
	unsigned short QTYPE;//��ѯ���� 1->ip��ַ
	unsigned short QCLASS;//��ѯ�� 1->��������ַ
};

#pragma pack (1)
struct DnsRecource {
	int ttl;//����ʱ��
	unsigned short dataLength;
};
#pragma pack()