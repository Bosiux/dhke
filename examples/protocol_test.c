#include "../include/dhke.h"
#include "../protocol/protocol.h"
#include <stdio.h>
#include <string.h>      // For strlen(), strcmp()
#include <unistd.h>      // For close()
#include <arpa/inet.h>   // For sockaddr_in



void run_server() {
    int sockfd, new_sock;
    DHKE_Context ctx;
    struct sockaddr_in serv_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    protocol_init_connection(&sockfd, ROLE_SERVER, NULL);
    dhke_init(&ctx, NULL, NULL);

    printf("Server waiting for connections...\n");

    while (1) {
        new_sock = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len);
        if (new_sock < 0) {
            perror("accept");
            continue;
        }

        printf("Client connected.\n");

        dhke_generate_key_pair(&ctx);
        if (protocol_perform_dhke(new_sock, &ctx)) {
            fprintf(stderr, "DHKE failed\n");
            close(new_sock);
            continue;
        }

        while (1) {
            uint8_t buffer[PROTOCOL_BUFFER_SIZE];
            int len = protocol_receive_secure(new_sock, &ctx, buffer, PROTOCOL_BUFFER_SIZE);

            if (len <= 0) {
                printf("Client disconnected or error occurred.\n");
                break;
            }

            printf("Received (%d bytes): %.*s\n", len, len, buffer);
        }

        close(new_sock);
        printf("Waiting for next connection...\n");
    }

    close(sockfd);
}


#define MAX_MSG_LEN 1024  

void run_client(const char *server_ip) {
    int sockfd;
    DHKE_Context ctx;

    protocol_init_connection(&sockfd, ROLE_CLIENT, server_ip);
    dhke_init(&ctx, NULL, NULL);
    dhke_generate_key_pair(&ctx);

    if (protocol_perform_dhke(sockfd, &ctx)) {
        fprintf(stderr, "DHKE failed\n");
        return;
    }

    char msg[MAX_MSG_LEN];

    while (1) {
        printf("Enter message (empty to quit): ");
        if (!fgets(msg, sizeof(msg), stdin)) {
            break; 
        }

        msg[strcspn(msg, "\n")] = '\0';

        if (strlen(msg) == 0) {
            break; 
        }

        protocol_send_secure(sockfd, &ctx, (uint8_t*)msg, strlen(msg) + 1);
    }

    close(sockfd);
}


int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--server") == 0) {
        run_server();
    } else if (argc > 2 && strcmp(argv[1], "--client") == 0) {
        run_client(argv[2]);
    } else {
        printf("Usage:\n  %s --server\n  %s --client <ip>\n", argv[0], argv[0]);
    }
    return 0;
}
