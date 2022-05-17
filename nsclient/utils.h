
//Constants from assignment
#define A_HOST_ADDRESS 1    
#define NS_AUTHO_NAME 2     // authoritative name server 
#define TXT 16              // text strings
#define AXFR 252            // request transfer entire zone 

// leftovers from online code 
#define T_CNAME 5 /* canonical name */
#define T_SOA 6   /* start of authority zone */
#define T_PTR 12  /* domain name pointer */
#define T_MX 15   /* mail routing information */

// utils functions declarations




// DNS header structure
typedef struct DNS_HEADER {
    unsigned short id;
    unsigned char qr : 1;
    unsigned char opcode : 4;
    unsigned char aa : 1;
    unsigned char tc : 1;
    unsigned char rd : 1;
    unsigned char ra : 1;
    unsigned char z : 1;
    unsigned char rcode : 4;

    unsigned short qd_count;    // count of entries in question section
    unsigned short an_count;    // count of RRs in answer section  
    unsigned short ns_count;    // count of name server RRs in autority record section 
    unsigned short ar_count;    // count of RRs in additional recors section


    //leftovers 
    unsigned char cd : 1;       // checking disabled
    unsigned char ad : 1;       // authenticated data


} DNS_HEADER;


typedef struct QUESTION {
    unsigned short q_name;
    unsigned short q_type;
    unsigned short q_class;
} QUESTION;

// Not sure what is this pragna notation 
#pragma pack(push, 1)
struct R_DATA {
    unsigned long name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned long data;
};
#pragma pack(pop)
typedef struct R_DATA;

// Pointers to resource record contents
typedef struct RES_RECORD {
    unsigned char* name;
    struct R_DATA* resource;
    unsigned char* rdata;
} RES_RECORD;
