#include "../include/dhke.h"
#include "../protocol/protocol.h"
#include <stdio.h>
#include <string.h>      // For strlen(), strcmp()
#include <unistd.h>      // For close()
#include <arpa/inet.h>   // For sockaddr_in

int main(int argc, char *argv[]) {
    
    int sockfd, new_sock;
    DHKE_Context ctx;
    struct sockaddr_in serv_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    protocol_init_connection(&sockfd, ROLE_SERVER, NULL);
    dhke_init(&ctx, NULL, NULL);

    printf("In attesa di connessioni...\n");

    while (1) {
        new_sock = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len);
        if (new_sock < 0) {
            perror("accept");
            continue;
        }

        printf("Client connesso.\n");

        dhke_generate_key_pair(&ctx);
        if (protocol_perform_dhke(new_sock, &ctx)) {
            fprintf(stderr, "Handshake fallito\n");
            close(new_sock);
            continue;
        }

        while (1) {
            uint8_t buffer[PROTOCOL_BUFFER_SIZE];
            int len = protocol_receive_secure(new_sock, &ctx, buffer, PROTOCOL_BUFFER_SIZE);

            if (len <= 0) {
                printf("Client disconnesso o errore.\n");
                break;
            }

            printf("[%d byte]: %.*s\n", len, len, buffer);
        }

        close(new_sock);
        printf("In attesa di nuove connessioni...\n");
    }

    close(sockfd);
    return 0;
}