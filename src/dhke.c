/**
 * @file dhke.c
 * @brief Implementation of Diffie-Hellman Key Exchange (DHKE) with additional cryptographic utilities.
 *
 * This file provides functions for initializing the DHKE context, generating key pairs,
 * computing shared secrets, and performing encryption, decryption, and HMAC operations.
 * It also includes cleanup routines to securely erase sensitive data.
 */

#include "dhke_internal.h"
#include <string.h>

/**
 * @brief Initializes the DHKE context with the given prime and generator values.
 *
 * @param ctx Pointer to the DHKE_Context structure to initialize.
 * @param prime Pointer to the prime value (optional, uses RFC prime if NULL).
 * @param generator Pointer to the generator value (optional, defaults to 2 if NULL).
 */
void dhke_init(DHKE_Context *ctx, const uint8_t *prime, const uint8_t *generator);

/**
 * @brief Generates a key pair (private and public keys) for the DHKE context.
 *
 * @param ctx Pointer to the initialized DHKE_Context structure.
 */
void dhke_generate_key_pair(DHKE_Context *ctx);

/**
 * @brief Computes the shared secret using the peer's public key.
 *
 * @param ctx Pointer to the initialized DHKE_Context structure.
 * @param peer_key Pointer to the peer's public key.
 */
void dhke_compute_shared_secret(DHKE_Context *ctx, const uint8_t *peer_key);

/**
 * @brief Generates an HMAC for the given data using the session's HMAC key.
 *
 * @param ctx Pointer to the initialized DHKE_Context structure.
 * @param data Pointer to the input data.
 * @param len Length of the input data.
 * @param out Pointer to the output buffer for the generated HMAC.
 */
void dhke_generate_hmac(DHKE_Context *ctx, const uint8_t *data, size_t len, uint8_t *out);

/**
 * @brief Verifies the HMAC for the given data.
 *
 * @param ctx Pointer to the initialized DHKE_Context structure.
 * @param data Pointer to the input data.
 * @param len Length of the input data.
 * @param hmac Pointer to the HMAC to verify.
 * @return 1 if the HMAC is valid, 0 otherwise.
 */
int dhke_verify_hmac(DHKE_Context *ctx, const uint8_t *data, size_t len, const uint8_t *hmac);

/**
 * @brief Encrypts plaintext using AES-GCM with the session key.
 *
 * @param ctx Pointer to the initialized DHKE_Context structure.
 * @param plaintext Pointer to the plaintext data.
 * @param len Length of the plaintext data.
 * @param ciphertext Pointer to the output buffer for the ciphertext.
 * @param nonce Pointer to the output buffer for the generated nonce.
 * @param tag Pointer to the output buffer for the authentication tag.
 */
void dhke_encrypt(DHKE_Context *ctx, const uint8_t *plaintext, size_t len,
                  uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag);

/**
 * @brief Decrypts ciphertext using AES-GCM with the session key.
 *
 * @param ctx Pointer to the initialized DHKE_Context structure.
 * @param ciphertext Pointer to the ciphertext data.
 * @param len Length of the ciphertext data.
 * @param plaintext Pointer to the output buffer for the decrypted plaintext.
 * @param nonce Pointer to the nonce used during encryption.
 * @param tag Pointer to the authentication tag used during encryption.
 * @return 1 if decryption and authentication are successful, 0 otherwise.
 */
int dhke_decrypt(DHKE_Context *ctx, const uint8_t *ciphertext, size_t len,
                 uint8_t *plaintext, const uint8_t *nonce, const uint8_t *tag);

/**
 * @brief Cleans up the DHKE context by securely erasing sensitive data.
 *
 * @param ctx Pointer to the DHKE_Context structure to clean up.
 */
void dhke_cleanup(DHKE_Context *ctx);


void dhke_init(DHKE_Context *ctx, const uint8_t *prime, const uint8_t *generator) {
    memset(ctx, 0, sizeof(DHKE_Context));
    if (prime) memcpy(ctx->prime, prime, DHKE_KEY_SIZE);
    else dhke_load_rfc_prime(ctx->prime);

    if (generator) memcpy(ctx->generator, generator, DHKE_KEY_SIZE);
    else memset(ctx->generator + DHKE_KEY_SIZE - 1, 2, 1);
}

void dhke_generate_key_pair(DHKE_Context *ctx) {
    dhke_generate_random(ctx->private_key, DHKE_KEY_SIZE);
    dhke_mod_exp(ctx->generator, ctx->private_key, ctx->prime, ctx->public_key);
}

void dhke_compute_shared_secret(DHKE_Context *ctx, const uint8_t *peer_key) {
    dhke_validate_key(peer_key, ctx->prime);
    dhke_mod_exp(peer_key, ctx->private_key, ctx->prime, ctx->shared_secret);
    dhke_derive_keys(ctx->shared_secret, ctx->session_key, ctx->hmac_key);
}

void dhke_generate_hmac(DHKE_Context *ctx, const uint8_t *data, size_t len, uint8_t *out) {
    dhke_hmac_sha384(ctx->hmac_key, DHKE_KEY_SIZE, data, len, out);
}

int dhke_verify_hmac(DHKE_Context *ctx, const uint8_t *data, size_t len, const uint8_t *hmac) {
    uint8_t expected[DHKE_HMAC_SIZE];
    dhke_generate_hmac(ctx, data, len, expected);
    return CRYPTO_memcmp(expected, hmac, DHKE_HMAC_SIZE) == 0;
}

void dhke_encrypt(DHKE_Context *ctx, const uint8_t *plaintext, size_t len,
                  uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag) {
    dhke_encrypt_aes_gcm(ctx->session_key, plaintext, len, ciphertext, nonce, tag);
}

int dhke_decrypt(DHKE_Context *ctx, const uint8_t *ciphertext, size_t len,
                 uint8_t *plaintext, const uint8_t *nonce, const uint8_t *tag) {
    return dhke_decrypt_aes_gcm(ctx->session_key, ciphertext, len, plaintext, nonce, tag);
}

void dhke_cleanup(DHKE_Context *ctx) {
    OPENSSL_cleanse(ctx->private_key, DHKE_KEY_SIZE);
    OPENSSL_cleanse(ctx->shared_secret, DHKE_KEY_SIZE);
    OPENSSL_cleanse(ctx->session_key, DHKE_KEY_SIZE);
    OPENSSL_cleanse(ctx->hmac_key, DHKE_KEY_SIZE);
}

