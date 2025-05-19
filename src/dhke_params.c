/**
 * @file dhke_params.c
 * @brief Implementation of Diffie-Hellman Key Exchange (DHKE) parameter loading.
 *
 * This file contains the implementation for loading predefined Diffie-Hellman
 * parameters, specifically the RFC 7919 FFDHE2048 prime, into a binary buffer.
 */

#include "dhke_internal.h"

/**
 * @brief Loads the RFC 7919 FFDHE2048 prime into a binary buffer.
 *
 * This function converts the predefined hexadecimal representation of the
 * RFC 7919 FFDHE2048 prime into a binary format and stores it in the provided
 * output buffer. The prime is represented as a constant string in hexadecimal
 * format and is converted using OpenSSL's BIGNUM utilities.
 *
 * @param[out] prime_out A pointer to a buffer where the binary representation
 *                       of the prime will be stored. The buffer must have
 *                       sufficient space to hold DHKE_KEY_SIZE bytes.
 *
 * @note The function uses OpenSSL's BIGNUM library for hexadecimal-to-binary
 *       conversion and ensures the output buffer is zero-padded to the
 *       required size.
 *
 * @warning The caller must ensure that the `prime_out` buffer is allocated
 *          with at least DHKE_KEY_SIZE bytes before calling this function.
 */

static const char *RFC_FFDHE_2048 =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

void dhke_load_rfc_prime(uint8_t *prime_out) {
    BIGNUM *p = NULL;
    BN_hex2bn(&p, RFC_FFDHE_2048);
    memset(prime_out, 0, DHKE_KEY_SIZE);
    BN_bn2binpad(p, prime_out, DHKE_KEY_SIZE);
    BN_free(p);
}

