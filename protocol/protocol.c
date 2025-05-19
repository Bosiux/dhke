/**
 * @file protocol.c
 * @brief Implementation of a secure communication protocol using Diffie-Hellman Key Exchange (DHKE).
 *
 * This file provides functions for sending and receiving data securely over a network
 * using Diffie-Hellman Key Exchange (DHKE) for shared secret generation and encryption.
 * It includes functions for initializing connections, performing DHKE, and securely
 * transmitting and receiving encrypted messages.
 */

#include "protocol.h"
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

/**
 * @brief Sends data over a socket.
 *
 * @param sockfd The socket file descriptor.
 * @param data Pointer to the data to be sent.
 * @param len Length of the data to be sent.
 * @return Number of bytes sent on success, -1 on failure.
 */
int protocol_send(int sockfd, const void *data, size_t len);

/**
 * @brief Receives data from a socket.
 *
 * @param sockfd The socket file descriptor.
 * @param buffer Pointer to the buffer where received data will be stored.
 * @param max_len Maximum length of data to be received.
 * @return Number of bytes received on success, -1 on failure.
 */
int protocol_recv(int sockfd, void *buffer, size_t max_len);

/**
 * @brief Initializes a connection for the protocol.
 *
 * @param sockfd Pointer to the socket file descriptor to be initialized.
 * @param role The role of the connection (server or client).
 * @param address The address to connect to (used only for client role).
 * @return 0 on success, -1 on failure.
 */
int protocol_init_connection(int *sockfd, ProtocolRole role, const char *address);

/**
 * @brief Performs the Diffie-Hellman Key Exchange (DHKE) protocol.
 *
 * @param sockfd The socket file descriptor.
 * @param ctx Pointer to the DHKE context containing keys and shared secret.
 * @return 0 on success, -1 on failure.
 */
int protocol_perform_dhke(int sockfd, DHKE_Context *ctx);

/**
 * @brief Sends a securely encrypted message over a socket.
 *
 * @param sockfd The socket file descriptor.
 * @param ctx Pointer to the DHKE context containing encryption keys.
 * @param msg Pointer to the plaintext message to be sent.
 * @param len Length of the plaintext message.
 * @return 0 on success, -1 on failure.
 */
int protocol_send_secure(int sockfd, DHKE_Context *ctx, const uint8_t *msg, size_t len);

/**
 * @brief Receives and decrypts a securely encrypted message from a socket.
 *
 * @param sockfd The socket file descriptor.
 * @param ctx Pointer to the DHKE context containing decryption keys.
 * @param buffer Pointer to the buffer where the decrypted message will be stored.
 * @param max_len Maximum length of the buffer.
 * @return Length of the decrypted message on success, -1 on failure.
 */
int protocol_receive_secure(int sockfd, DHKE_Context *ctx, uint8_t *buffer, size_t max_len);


int protocol_send(int sockfd, const void *data, size_t len) {
    ssize_t sent = send(sockfd, data, len, 0);
    if (sent < 0) {
        perror("Send failed");
        return -1;
    }
    return (int)sent;
}

int protocol_recv(int sockfd, void *buffer, size_t max_len) {
    ssize_t received = recv(sockfd, buffer, max_len, 0);
    if (received < 0) {
        perror("Receive failed");
        return -1;
    }
    return (int)received;
}

int protocol_init_connection(int *sockfd, ProtocolRole role, const char *address) {
    struct sockaddr_in serv_addr;
    
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PROTOCOL_PORT);

    if (role == ROLE_SERVER) {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(*sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Bind failed");
            return -1;
        }
        if (listen(*sockfd, 1) < 0) {
            perror("Listen failed");
            return -1;
        }
    } else {
        if (inet_pton(AF_INET, address, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address");
            return -1;
        }
        if (connect(*sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Connection failed");
            return -1;
        }
    }
    return 0;
}

int protocol_perform_dhke(int sockfd, DHKE_Context *ctx) {
    uint8_t peer_pubkey[DHKE_KEY_SIZE];
    
    if (protocol_send(sockfd, ctx->public_key, DHKE_KEY_SIZE) != DHKE_KEY_SIZE) {
        fprintf(stderr, "Failed to send public key\n");
        return -1;
    }
    
    if (protocol_recv(sockfd, peer_pubkey, DHKE_KEY_SIZE) != DHKE_KEY_SIZE) {
        fprintf(stderr, "Failed to receive peer public key\n");
        return -1;
    }

    dhke_compute_shared_secret(ctx, peer_pubkey);

    uint8_t local_hmac[DHKE_HMAC_SIZE], remote_hmac[DHKE_HMAC_SIZE];
    
    dhke_generate_hmac(ctx, peer_pubkey, DHKE_KEY_SIZE, local_hmac);
    
    if (protocol_send(sockfd, local_hmac, DHKE_HMAC_SIZE) != DHKE_HMAC_SIZE ||
        protocol_recv(sockfd, remote_hmac, DHKE_HMAC_SIZE) != DHKE_HMAC_SIZE) {
        fprintf(stderr, "HMAC exchange failed\n");
        return -1;
    }

    if (!dhke_verify_hmac(ctx, ctx->public_key, DHKE_KEY_SIZE, remote_hmac)) {
        fprintf(stderr, "HMAC verification failed\n");
        return -1;
    }

    return 0;
}

int protocol_send_secure(int sockfd, DHKE_Context *ctx, const uint8_t *msg, size_t len) {
    uint8_t nonce[DHKE_NONCE_SIZE];
    uint8_t tag[16];
    uint8_t ciphertext[len];
    
    dhke_encrypt(ctx, msg, len, ciphertext, nonce, tag);
    
    printf("Encrypted ciphertext (%zu bytes): ", len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    if (protocol_send(sockfd, nonce, DHKE_NONCE_SIZE) != DHKE_NONCE_SIZE) {
        fprintf(stderr, "Failed to send nonce\n");
        return -1;
    }

    if (protocol_send(sockfd, tag, 16) != 16) {
        fprintf(stderr, "Failed to send tag\n");
        return -1;
    }

    if (protocol_send(sockfd, ciphertext, len) != len) {
        fprintf(stderr, "Failed to send ciphertext\n");
        return -1;
    }
    
    return 0;
}

int protocol_receive_secure(int sockfd, DHKE_Context *ctx, uint8_t *buffer, size_t max_len) {
    uint8_t nonce[DHKE_NONCE_SIZE];
    uint8_t tag[16];
    
    if (protocol_recv(sockfd, nonce, DHKE_NONCE_SIZE) != DHKE_NONCE_SIZE) {
        fprintf(stderr, "Failed to receive nonce\n");
        return -1;
    }

    if (protocol_recv(sockfd, tag, 16) != 16) {
        fprintf(stderr, "Failed to receive tag\n");
        return -1;
    }

    int cipher_len = protocol_recv(sockfd, buffer, max_len);
    if (cipher_len <= 0) {
        fprintf(stderr, "Failed to receive ciphertext\n");
        return -1;
    }

    if (!dhke_decrypt(ctx, buffer, cipher_len, buffer, nonce, tag)) {
        fprintf(stderr, "Decryption failed\n");
        return -1;
    }
    
    return cipher_len;
}
