/**
 * @file dhke_internal.h
 * @brief Internal API for Diffie-Hellman Key Exchange (DHKE) operations.
 *
 * This header file provides internal functions for implementing the Diffie-Hellman
 * Key Exchange protocol and related cryptographic operations. It is intended to be
 * used as part of a library for secure key exchange and encryption.
 *
 * The functions in this file include:
 * - Loading predefined RFC 3526 primes for DHKE.
 * - Generating random values for cryptographic purposes.
 * - Performing modular exponentiation for DHKE computations.
 * - Validating keys against a given prime.
 * - Deriving cryptographic keys from shared secrets.
 * - Computing HMAC using SHA-384.
 * - Encrypting and decrypting data using AES-GCM.
 *
 * Note: This header is for internal use only and should not be exposed as part of
 * the public API. It relies on OpenSSL for cryptographic operations.
 *
 * Dependencies:
 * - OpenSSL libraries: BIGNUM (BN), RAND, EVP, KDF, HMAC, and CRYPTO.
 * - Standard C libraries: string.h, stdlib.h, stdio.h.
 */
#ifndef DHKE_INTERNAL_H
#define DHKE_INTERNAL_H

#include "../include/dhke.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


void dhke_load_rfc_prime(uint8_t *prime_out); // Load RFC 3526 prime

void dhke_generate_random(uint8_t *buf, size_t len);

void dhke_mod_exp(const uint8_t *base, const uint8_t *exp, const uint8_t *mod, uint8_t *out);

void dhke_validate_key(const uint8_t *key, const uint8_t *prime);

void dhke_derive_keys(const uint8_t *shared_secret, uint8_t *key1, uint8_t *key2);

void dhke_hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out);

void dhke_encrypt_aes_gcm(const uint8_t *key, const uint8_t *plaintext, size_t len,
                          uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag);

int dhke_decrypt_aes_gcm(const uint8_t *key, const uint8_t *ciphertext, size_t len,
                         uint8_t *plaintext, const uint8_t *nonce, const uint8_t *tag);


#endif

