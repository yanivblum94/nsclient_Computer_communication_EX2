#include "conio.h"
#include "stdio.h"
#include "windows.h"
#include <stdbool.h>

#define MAX_LEN_DOMAIN_NAME 2000//can be configured easily
#define FAIL_CODE 1
#define SUCCESS_CODE 0

int GetDomainFromUser(char* input) {
    printf("Enter domain name\n");
    if (scanf("%s", input) == SUCCESS_CODE) {
        printf("ERROR: Getting input from user failed\n");
        return FAIL_CODE;
    }
    return SUCCESS_CODE;
}

int main(int argc, char* argv[]) {
    char* ip_input = argv[1];
    char domainName[MAX_LEN_DOMAIN_NAME];
    bool is_valid_domain;
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("ERROR: Failed in Winsock init. Error code: (%d)\n", WSAGetLastError());
        return FAIL_CODE;
    }

    while (true) {
        GetDomainFromUser(domainName);
        if (strcmp(domainName, "quit") == SUCCESS_CODE) { break; }
        if (!IsValidDomain(domainName)) {
            printf("ERROR: BAD NAME\n");
            continue;
        }
        dnsQuery(domainName, ip_input);
    }
    return SUCCESS_CODE;
}