#ifndef DHKE_PROTOCOL_H
#define DHKE_PROTOCOL_H

#include "../include/dhke.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PROTOCOL_PORT 8080
#define PROTOCOL_BUFFER_SIZE 4096

typedef enum {
    ROLE_CLIENT,
    ROLE_SERVER
} ProtocolRole;

// Core protocol functions
int protocol_init_connection(int *sockfd, ProtocolRole role, const char *address);
int protocol_perform_dhke(int sockfd, DHKE_Context *ctx);

// Secure message I/O
int protocol_send_secure(int sockfd, DHKE_Context *ctx, const uint8_t *msg, size_t len);
int protocol_receive_secure(int sockfd, DHKE_Context *ctx, uint8_t *buffer, size_t max_len);

// Network helpers
int protocol_send(int sockfd, const void *data, size_t len);
int protocol_recv(int sockfd, void *buffer, size_t max_len);

#endif
