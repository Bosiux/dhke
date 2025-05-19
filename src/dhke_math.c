/**
 * @file dhke_math.c
 * @brief Implementation of Diffie-Hellman Key Exchange (DHKE) mathematical operations.
 *
 * This file contains functions for modular exponentiation and key validation
 * used in the Diffie-Hellman Key Exchange protocol.
 */

#include "dhke_internal.h"

/**
 * @brief Performs modular exponentiation.
 *
 * Computes the result of (base^exp) % mod and stores it in the output buffer.
 *
 * @param base Pointer to the base value in binary format.
 * @param exp Pointer to the exponent value in binary format.
 * @param mod Pointer to the modulus value in binary format.
 * @param out Pointer to the output buffer where the result will be stored.
 *
 * @note The size of the input and output buffers is assumed to be DHKE_KEY_SIZE.
 *       This function uses OpenSSL's BIGNUM library for big integer arithmetic.
 */
void dhke_mod_exp(const uint8_t *base, const uint8_t *exp, const uint8_t *mod, uint8_t *out);

/**
 * @brief Validates a Diffie-Hellman public key.
 *
 * Ensures that the given public key is within the valid range (1 < key < prime - 1)
 * and belongs to the correct subgroup of the prime modulus.
 *
 * @param key Pointer to the public key in binary format.
 * @param prime Pointer to the prime modulus in binary format.
 *
 * @note If the key is invalid, this function will print an error message to stderr
 *       and terminate the program using `abort()`.
 *       This function uses OpenSSL's BIGNUM library for big integer arithmetic.
 */
void dhke_validate_key(const uint8_t *key, const uint8_t *prime);

void dhke_mod_exp(const uint8_t *base, const uint8_t *exp, const uint8_t *mod, uint8_t *out) {
    BIGNUM *b = BN_bin2bn(base, DHKE_KEY_SIZE, NULL);
    BIGNUM *e = BN_bin2bn(exp, DHKE_KEY_SIZE, NULL);
    BIGNUM *m = BN_bin2bn(mod, DHKE_KEY_SIZE, NULL);
    BIGNUM *res = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(res, b, e, m, ctx);
    BN_bn2binpad(res, out, DHKE_KEY_SIZE);

    BN_free(b); BN_free(e); BN_free(m); BN_free(res); BN_CTX_free(ctx);
}

void dhke_validate_key(const uint8_t *key, const uint8_t *prime) {
    BIGNUM *k = BN_bin2bn(key, DHKE_KEY_SIZE, NULL);
    BIGNUM *p = BN_bin2bn(prime, DHKE_KEY_SIZE, NULL);
    BIGNUM *one = BN_new(); BN_one(one);
    BIGNUM *pm1 = BN_dup(p); BN_sub_word(pm1, 1);

    if (BN_cmp(k, one) <= 0 || BN_cmp(k, pm1) >= 0) {
        fprintf(stderr, "Invalid DH public key\n");
        abort();
    }

    BIGNUM *q = BN_dup(pm1); BN_div_word(q, 2);
    BIGNUM *check = BN_new(); BN_mod_exp(check, k, q, p, BN_CTX_new());

    if (!BN_is_one(check)) {
        fprintf(stderr, "Invalid subgroup\n");
        abort();
    }

    BN_free(k); BN_free(p); BN_free(one); BN_free(pm1); BN_free(q); BN_free(check);
}

