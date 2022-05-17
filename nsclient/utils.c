#include "utils.h"
#include "stdbool.h"
#include <ctype.h>

#define max_name_len 63
#define min_name_len 3 

// conventions are taken from : https://registry.gov.in/domiannamingcon.php
bool IsValidDomain(char* domainName) {
    int i, len = strlen(domainName);
    char c;

    // assert domain address length => 3 and <=63
    if ((len < min_name_len) && (len > max_name_len)) {
        printf("ERROR: `%s`: Domain name length must be [2,63] \n", domainName);
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
        if ( ((i == 0) || (i == (len - 1) )) && (c == '-')){
            printf("ERROR: `%s`: Domain name can't start or end with hyphens \n", domainName);
            return false;
        }
        // Valid characters: '.', '-', 0-9, a-z
        if ((c != '.') && (c != '-') &&  !isdigit(c) && !isalpha(c) ) {
            printf("ERROR: `%c`: invalid char in domain name \n", c);
            return false;
        }

    }
    return true;
}

