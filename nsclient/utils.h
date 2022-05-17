#include "conio.h"
#include "stdio.h"
#include "windows.h"
#include "stdbool.h"
#include <ctype.h>
#include <stdbool.h>

//Constants from assignment
#define A_HOST_ADDRESS 1    

// DNS header structure
typedef struct DNS_HEADER {
    unsigned short id;
    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;
    unsigned char rcode : 4;
    unsigned char cd : 1;       // checking disabled
    unsigned char ad : 1;       // authenticated data
    unsigned char z : 1;
    unsigned char ra : 1;

    unsigned short qd_count;    // count of entries in question section
    unsigned short an_count;    // count of RRs in answer section  
    unsigned short auth_count;    // count of name server RRs in autority record section 
    unsigned short add_rec_count;    // count of RRs in additional recors section

} DNS_HEADER;


typedef struct QUESTION {
    unsigned short q_type;
    unsigned short q_class;
} QUESTION;

// Not sure what is this pragna notation 
#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
typedef struct R_DATA;

// Pointers to resource record contents
typedef struct RES_RECORD {
    unsigned char* name;
    struct R_DATA* resource;
    unsigned char* rdata;
} RES_RECORD;

void dnsQuery(unsigned char* domainName, char* ip_input);
bool IsValidDomain(char* domainName);