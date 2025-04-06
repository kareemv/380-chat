#include "dh.h"
#include "keys.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Initialize DH parameters
    init("params");

    // Create long term keys for server and client
    dhKey serverKey, clientKey;
    initKey(&serverKey);
    initKey(&clientKey);

    // Generate servers long term key
    dhGenk(&serverKey);

    // Write server keys to files 
    char* serverKeyFileName = "server_long_term_key";
    writeDH(serverKeyFileName, &serverKey);
    printf("Server long-term DH key saved to %s\n", serverKeyFileName);

    // Generate clients long term key
    dhGenk(&clientKey);

    // Write client keys to files 
    char* clientKeyFileName = "client_long_term_key";
    writeDH(clientKeyFileName, &clientKey);
    printf("Client long-term DH key saved to %s\n", clientKeyFileName);

    shredKey(&serverKey); 
    shredKey(&clientKey); 
    return 0;
}