/**
 * @file dhke.h
 * @brief Header file for Diffie-Hellman Key Exchange (DHKE) implementation with HMAC and encryption support.
 *
 * This library provides an implementation of the Diffie-Hellman Key Exchange (DHKE) protocol,
 * including support for key generation, shared secret computation, HMAC generation and verification,
 * and authenticated encryption and decryption using GCM mode.
 */

#ifndef DHKE_H
#define DHKE_H

#include <stdint.h>
#include <stddef.h>
/**
 * @def DHKE_KEY_SIZE
 * @brief Size of the key in bytes (2048-bit or 256 bytes).
 */
#define DHKE_KEY_SIZE 256 

/**
 * @def DHKE_HMAC_SIZE
 * @brief Size of the HMAC output in bytes (SHA-384 HMAC).
 */
#define DHKE_HMAC_SIZE 48  

/**
 * @def DHKE_NONCE_SIZE
 * @brief Size of the GCM nonce in bytes.
 */
#define DHKE_NONCE_SIZE 12

/**
 * @struct DHKE_Context
 * @brief Structure to hold the context for the DHKE protocol.
 *
 * This structure contains all the necessary parameters and keys for performing
 * the Diffie-Hellman Key Exchange, HMAC operations, and encryption/decryption.
 *
 * @var DHKE_Context::prime
 * Prime number used in the Diffie-Hellman key exchange.
 * @var DHKE_Context::generator
 * Generator value used in the Diffie-Hellman key exchange.
 * @var DHKE_Context::private_key
 * Private key generated for the local party.
 * @var DHKE_Context::public_key
 * Public key derived from the private key.
 * @var DHKE_Context::shared_secret
 * Shared secret computed using the peer's public key.
 * @var DHKE_Context::session_key
 * Session key derived from the shared secret.
 * @var DHKE_Context::hmac_key
 * Key used for HMAC generation and verification.
 */
typedef struct {
    uint8_t prime[DHKE_KEY_SIZE];
    uint8_t generator[DHKE_KEY_SIZE];
    uint8_t private_key[DHKE_KEY_SIZE];
    uint8_t public_key[DHKE_KEY_SIZE];
    uint8_t shared_secret[DHKE_KEY_SIZE];
    uint8_t session_key[DHKE_KEY_SIZE];
    uint8_t hmac_key[DHKE_KEY_SIZE];
} DHKE_Context;

/**
 * @brief Initializes the DHKE context with the given prime and generator values.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 * @param prime Pointer to the prime number.
 * @param generator Pointer to the generator value.
 */
void dhke_init(DHKE_Context *ctx, const uint8_t *prime, const uint8_t *generator);

/**
 * @brief Generates a key pair (private and public keys) for the local party.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 */
void dhke_generate_key_pair(DHKE_Context *ctx);

/**
 * @brief Computes the shared secret using the peer's public key.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 * @param peer_public_key Pointer to the peer's public key.
 */
void dhke_compute_shared_secret(DHKE_Context *ctx, const uint8_t *peer_public_key);

/**
 * @brief Generates an HMAC for the given data using the session key.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 * @param data Pointer to the input data.
 * @param len Length of the input data.
 * @param out Pointer to the output buffer for the HMAC.
 */
void dhke_generate_hmac(DHKE_Context *ctx, const uint8_t *data, size_t len, uint8_t *out);

/**
 * @brief Verifies the HMAC for the given data.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 * @param data Pointer to the input data.
 * @param len Length of the input data.
 * @param hmac Pointer to the HMAC to verify.
 * @return 1 if the HMAC is valid, 0 otherwise.
 */
int dhke_verify_hmac(DHKE_Context *ctx, const uint8_t *data, size_t len, const uint8_t *hmac);

/**
 * @brief Encrypts the given plaintext using the session key and GCM mode.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 * @param plaintext Pointer to the plaintext data.
 * @param len Length of the plaintext data.
 * @param ciphertext Pointer to the output buffer for the ciphertext.
 * @param nonce Pointer to the output buffer for the nonce.
 * @param tag Pointer to the output buffer for the authentication tag.
 */
void dhke_encrypt(DHKE_Context *ctx, const uint8_t *plaintext, size_t len,
                  uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag);

/**
 * @brief Decrypts the given ciphertext using the session key and GCM mode.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 * @param ciphertext Pointer to the ciphertext data.
 * @param len Length of the ciphertext data.
 * @param plaintext Pointer to the output buffer for the plaintext.
 * @param nonce Pointer to the nonce used during encryption.
 * @param tag Pointer to the authentication tag used during encryption.
 * @return 1 if decryption is successful and the tag is valid, 0 otherwise.
 */
int dhke_decrypt(DHKE_Context *ctx, const uint8_t *ciphertext, size_t len,
                 uint8_t *plaintext, const uint8_t *nonce, const uint8_t *tag);

/**
 * @brief Cleans up the DHKE context by securely erasing sensitive data.
 *
 * @param ctx Pointer to the DHKE_Context structure.
 */
void dhke_cleanup(DHKE_Context *ctx);

#endif

