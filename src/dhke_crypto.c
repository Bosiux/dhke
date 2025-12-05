/**
 * @file dhke_crypto.c
 * @brief Implementation of cryptographic functions for Diffie-Hellman Key Exchange (DHKE).
 */

#include "dhke_internal.h"

/**
 * @brief Generates a random sequence of bytes.
 * 
 * @param buf Pointer to the buffer where the random bytes will be stored.
 * @param len Length of the random byte sequence to generate.
 */
void dhke_generate_random(uint8_t *buf, size_t len);

/**
 * @brief Derives session and HMAC keys using HKDF (HMAC-based Key Derivation Function).
 * 
 * @param secret Pointer to the shared secret used as the input key material.
 * @param session_key Pointer to the buffer where the derived session key will be stored.
 * @param hmac_key Pointer to the buffer where the derived HMAC key will be stored.
 */
void dhke_derive_keys(const uint8_t *secret, uint8_t *session_key, uint8_t *hmac_key);

/**
 * @brief Computes an HMAC using SHA-384.
 * 
 * @param key Pointer to the key used for HMAC computation.
 * @param key_len Length of the key.
 * @param data Pointer to the input data to be authenticated.
 * @param len Length of the input data.
 * @param out Pointer to the buffer where the HMAC output will be stored.
 */
void dhke_hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out);

/**
 * @brief Encrypts plaintext using AES-256-GCM.
 * 
 * @param key Pointer to the encryption key.
 * @param plaintext Pointer to the plaintext data to be encrypted.
 * @param len Length of the plaintext data.
 * @param ciphertext Pointer to the buffer where the encrypted data will be stored.
 * @param nonce Pointer to the buffer where the generated nonce will be stored.
 * @param tag Pointer to the buffer where the authentication tag will be stored.
 */
void dhke_encrypt_aes_gcm(const uint8_t *key, const uint8_t *plaintext, size_t len, uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag);

/**
 * @brief Decrypts ciphertext using AES-256-GCM.
 * 
 * @param key Pointer to the decryption key.
 * @param ciphertext Pointer to the encrypted data to be decrypted.
 * @param len Length of the ciphertext data.
 * @param plaintext Pointer to the buffer where the decrypted data will be stored.
 * @param nonce Pointer to the nonce used during encryption.
 * @param tag Pointer to the authentication tag used during encryption.
 * @return int Returns 1 if decryption is successful and authentication is valid, otherwise 0.
 */
int dhke_decrypt_aes_gcm(const uint8_t *key, const uint8_t *ciphertext, size_t len, uint8_t *plaintext, const uint8_t *nonce, const uint8_t *tag);


void dhke_generate_random(uint8_t *buf, size_t len)
{
    if (!RAND_bytes(buf, len)) {
        fprintf(stderr, "Random generation failed\n");
        abort();
    }
}

void dhke_derive_keys(const uint8_t *secret, uint8_t *session_key, uint8_t *hmac_key)
{
    uint8_t out[DHKE_KEY_SIZE * 2];
    size_t out_len = sizeof(out);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) {
        fprintf(stderr, "HKDF context creation failed\n");
        abort();
    }
    
    // Ordine corretto delle chiamate
    if (!EVP_PKEY_derive_init(kctx)) {
        fprintf(stderr, "HKDF derive init failed\n");
        EVP_PKEY_CTX_free(kctx);
        abort();
    }
    
    if (!EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha384())) {
        fprintf(stderr, "HKDF set MD failed\n");
        EVP_PKEY_CTX_free(kctx);
        abort();
    }
    
    // Imposta la chiave PRIMA del salt e info
    if (!EVP_PKEY_CTX_set1_hkdf_key(kctx, secret, DHKE_KEY_SIZE)) {
        fprintf(stderr, "HKDF set key failed\n");
        EVP_PKEY_CTX_free(kctx);
        abort();
    }
    
    // Salt opzionale
    uint8_t empty_salt[1] = {0};
    if (!EVP_PKEY_CTX_set1_hkdf_salt(kctx, empty_salt, 0)) {
        fprintf(stderr, "HKDF set salt failed\n");
        EVP_PKEY_CTX_free(kctx);
        abort();
    }
    
    if (!EVP_PKEY_CTX_add1_hkdf_info(kctx, (const uint8_t *)"AUTH_ENCRYPT_KEYS", 16)) {
        fprintf(stderr, "HKDF add info failed\n");
        EVP_PKEY_CTX_free(kctx);
        abort();
    }
    
    // HKDF-Expand per derivazioni estese
    size_t session_key_len = DHKE_KEY_SIZE;
    size_t hmac_key_len = DHKE_KEY_SIZE;
    
    // Deriva session_key
    EVP_PKEY_CTX *kctx1 = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx1 || !EVP_PKEY_derive_init(kctx1) ||
        !EVP_PKEY_CTX_set_hkdf_md(kctx1, EVP_sha384()) ||
        !EVP_PKEY_CTX_set1_hkdf_key(kctx1, secret, DHKE_KEY_SIZE) ||
        !EVP_PKEY_CTX_set1_hkdf_salt(kctx1, empty_salt, 0) ||
        !EVP_PKEY_CTX_add1_hkdf_info(kctx1, (const uint8_t *)"SESSION_KEY", 11) ||
        !EVP_PKEY_derive(kctx1, session_key, &session_key_len)) {
        fprintf(stderr, "HKDF derive session key failed\n");
        EVP_PKEY_CTX_free(kctx1);
        abort();
    }
    EVP_PKEY_CTX_free(kctx1);
    
    // Deriva hmac_key
    EVP_PKEY_CTX *kctx2 = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx2 || !EVP_PKEY_derive_init(kctx2) ||
        !EVP_PKEY_CTX_set_hkdf_md(kctx2, EVP_sha384()) ||
        !EVP_PKEY_CTX_set1_hkdf_key(kctx2, secret, DHKE_KEY_SIZE) ||
        !EVP_PKEY_CTX_set1_hkdf_salt(kctx2, empty_salt, 0) ||
        !EVP_PKEY_CTX_add1_hkdf_info(kctx2, (const uint8_t *)"HMAC_KEY", 8) ||
        !EVP_PKEY_derive(kctx2, hmac_key, &hmac_key_len)) {
        fprintf(stderr, "HKDF derive HMAC key failed\n");
        EVP_PKEY_CTX_free(kctx2);
        abort();
    }
    EVP_PKEY_CTX_free(kctx2);
}


void dhke_hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t *out)
{
    unsigned int out_len;
    HMAC(EVP_sha384(), key, key_len, data, len, out, &out_len);
}

void dhke_encrypt_aes_gcm(const uint8_t *key, const uint8_t *plaintext, size_t len, uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag)
{
    dhke_generate_random(nonce, DHKE_NONCE_SIZE);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
}

int dhke_decrypt_aes_gcm(const uint8_t *key, const uint8_t *ciphertext, size_t len, uint8_t *plaintext, const uint8_t *nonce, const uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    return ret == 1;
}

