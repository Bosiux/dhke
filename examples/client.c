#include "../include/dhke.h"
#include "../protocol/protocol.h"
#include <stdio.h>
#include <string.h>      // For strlen(), strcmp()
#include <unistd.h>      // For close()
#include <arpa/inet.h>   // For sockaddr_in

#define MAX_MSG_LEN 1024  



int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Errore: Numero di argomenti invalido\n");
        return 1;
    }

    char *server_ip = argv[1];
    int sockfd;
    DHKE_Context ctx;

    protocol_init_connection(&sockfd, ROLE_CLIENT, server_ip);
    dhke_init(&ctx, NULL, NULL);
    dhke_generate_key_pair(&ctx);

    if (protocol_perform_dhke(sockfd, &ctx)) {
        fprintf(stderr, "Handshake fallito\n");
        return 1;
    }

    char msg[MAX_MSG_LEN];

    while (1) {
        printf("Inserisci messaggio (invio per uscire): ");
        if (!fgets(msg, sizeof(msg), stdin)) {
            break; 
        }

        msg[strcspn(msg, "\n")] = '\0';

        if (strlen(msg) == 0) {
            break; 
        }

        uint8_t ciphertext[strlen(msg) + 1];

        protocol_send_secure(sockfd, &ctx, (uint8_t*)msg, strlen(msg) + 1, ciphertext);

        printf("- Messaggio cifrato: ");
        for (size_t i = 0; i < strlen(msg) + 1; i++) {
            printf("%02X ", ciphertext[i]);
        }
        printf("\n");
    }

    close(sockfd);
    return 0;
}