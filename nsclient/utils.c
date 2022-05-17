#include "utils.h"


#define MAX_DOMAIN_LEN 63
#define MIN_DOMAIN_LEN 3 
#define OFFSET_READER_MASK 49152 //49152 = 11000000 00000000
#define DOMAIN_NAME_SIZE 256
#define READER_MIN 192


// conventions are taken from : https://registry.gov.in/domiannamingcon.php
bool IsValidDomain(char* domainName) {
	int i, len = strlen(domainName);
	char c;

	// assert domain address length => 3 and <=63
	if ((len < MIN_DOMAIN_LEN) || (len > MAX_DOMAIN_LEN)) {
		printf("ERROR: `%s`: Domain name length must be [3,63] \n", domainName);
		return false;
	}
	// hyphens cannot appear at both third and fourth positions
	if ((domainName[2] == '-') && (domainName[3] == '-')) {
		printf("ERROR: `%s`: Hyphens cannot appear at both third and fourth positions of domain name \n", domainName);
		return false;
	}

	for (i = 0; i < len; i++) {
		c = domainName[i];
		if (c == ' ') {
			printf("ERROR: `%s`: Domain name can't have spaces \n", domainName);
			return false;
		}
		if (((i == 0) || (i == (len - 1))) && (c == '-')) {
			printf("ERROR: `%s`: Domain name can't start or end with hyphens \n", domainName);
			return false;
		}
		// Valid characters: '.', '-', 0-9, a-z
		if ((c != '.') && (c != '-') && !isdigit(c) && !isalpha(c)) {
			printf("ERROR: `%c`: invalid char in domain name \n", c);
			return false;
		}

	}
	return true;
}

SOCKET InitSocket() {
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		perror("ERROR in socket init");
		exit(-1);
	}
	return s;
}

void SetDnsHeader(DNS_HEADER* dns_hdr) {
	dns_hdr->id = (unsigned short)htons(GetCurrentProcessId());
	dns_hdr->qr = 0; //This is a query
	dns_hdr->opcode = 0; //This is a standard query
	dns_hdr->aa = 0; //Not Authoritative
	dns_hdr->tc = 0; //This message is not truncated
	dns_hdr->rd = 1; //Recursion Desired
	dns_hdr->ra = 0; //Recursion not available
	dns_hdr->z = 0;
	dns_hdr->ad = 0;
	dns_hdr->cd = 0;
	dns_hdr->rcode = 0;
	dns_hdr->qd_count = htons(1); //we have only 1 question
	dns_hdr->an_count = 0;
	dns_hdr->auth_count = 0;
	dns_hdr->add_rec_count = 0;
}

//this will convert www.google.com to 3www6google3com - valid DNS format for query
void ConvertDomainToDnsFormat(unsigned char* domainName, unsigned char* ques_name) {
    int lock=0;
	strcat((char*)domainName,".");

	for(int i=0 ; i<(int)strlen((char*)domainName) ; i++)
	{
		if(domainName[i]=='.')
		{
			*ques_name++=i-lock;
			for(;lock<i;lock++)
			{
				*ques_name++= domainName[lock];
			}
			lock++; 
		}
	}
	*ques_name++='\0';
}

void SetQuestionInfo(QUESTION* ques, char* buf, char *name ) {
	ques = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1)];// fill it
	ques->q_type = htons(1);// ipv4 address
	ques->q_class = htons(1);//its internet
}

unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned int p = 0, jumped = 0, offset;
	int i, j;

	*count = 1;
	unsigned char* domainName = (unsigned char*)malloc(DOMAIN_NAME_SIZE);

	domainName[0] = '\0';

	//read the names in 3www6google3com format
	while (*reader != 0)
	{
		if (*reader >= READER_MIN)
		{
			offset = (*reader) * DOMAIN_NAME_SIZE + *(reader + 1) - OFFSET_READER_MASK;
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			domainName[p++] = *reader;
		}

		reader = reader + 1;

		if (jumped == 0) *count = *count + 1; //if we havent jumped to another location then we can count up
	}

	domainName[p] = '\0'; //string complete
	if (jumped == 1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for (i = 0; i < (int)strlen((const char*)domainName); i++)
	{
		p = domainName[i];
		for (j = 0; j < (int)p; j++)
		{
			domainName[i] = domainName[i + 1];
			i = i + 1;
		}
		domainName[i] = '.';
	}

	domainName[i - 1] = '\0'; //remove the last dot

	return domainName;
}

void ParseDnsReply(char* buf, char* domainName, char* ques_name) {
	char* reader;
	int halt = 0;
	RES_RECORD reply;
	SOCKADDR_IN sockaddr;

	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)ques_name) + 1) + sizeof(struct QUESTION)];
	reply.name = ReadName(reader, buf, &halt);
	reader = reader + halt;
	reply.resource = (struct R_DATA*)(reader);
	reader = reader + sizeof(struct R_DATA);
	domainName[strlen(domainName) - 1] = '\0';
	if (ntohs(reply.resource->type) == 1) {
		// Has IPv4 Address
		reply.rdata = (unsigned char*)malloc(ntohs(reply.resource->data_len));
		for (int j = 0; j < ntohs(reply.resource->data_len); j++) {
			reply.rdata[j] = reader[j];
		}
		reply.rdata[ntohs(reply.resource->data_len)] = '\0';
		reader = reader + ntohs(reply.resource->data_len);
		long* p = (long*)reply.rdata;
		sockaddr.sin_addr.s_addr = (*p);
		printf("%s\n", inet_ntoa(sockaddr.sin_addr));
	}
	else {
		reply.rdata = ReadName(reader, buf, &halt);
		reader = reader + halt;
		perror("ERROR: NONEXISTENT");
	}
}

void dnsQuery(unsigned char* domainName, char* ip_input) {
	SOCKET sock;
	SOCKADDR_IN dest;
	DNS_HEADER* dns_hdr = NULL;
	QUESTION* ques = NULL;
	unsigned char buf[65536], * ques_name;
	int temp;

	sock = InitSocket();

	// Configure the sockaddress structure with information of DNS server
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(ip_input);

	dns_hdr = (struct DNS_HEADER*)&buf;
	SetDnsHeader(dns_hdr);

	ques_name = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];
	ConvertDomainToDnsFormat(domainName, ques_name);
	//SetQuestionInfo(ques, buf, ques_name);
	ques = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)ques_name) + 1)];// fill it
	ques->q_type = htons(1);// ipv4 address
	ques->q_class = htons(1);//its internet

	temp = sizeof(dest);
	if (sendto(sock, (char*)buf, sizeof(struct DNS_HEADER) + (strlen((const char*)ques_name) + 1) + sizeof(struct QUESTION), 0, (struct sockaddr*)&dest, temp) == SOCKET_ERROR)
	{
		perror("ERROR in sending dns query");
	}

	if (recvfrom(sock, (char*)buf, 65536, 0, (struct sockaddr*)&dest, &temp) == SOCKET_ERROR) {
		perror("ERROR in receving dns answer");
	}
	ParseDnsReply(buf, domainName, ques_name);
	dns_hdr = (struct DNS_HEADER*)buf;

	return;
}