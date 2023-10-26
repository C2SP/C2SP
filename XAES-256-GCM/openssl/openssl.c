#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

int derive_key(unsigned char out[32], const unsigned char key[32],
               const unsigned char nonce[24]) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[9], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "AES256", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "CMAC", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "COUNTER", 0);
    int use_l = 0;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, &use_l);
    int r = 16;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, &r);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, 32);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "X", 1);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)nonce, 12);
    *p = OSSL_PARAM_construct_end();

    int res = EVP_KDF_derive(kctx, out, 32, params);
    EVP_KDF_CTX_free(kctx);
    return res == 1;
}

int seal_aes_256_gcm(const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char key[32], const unsigned char nonce[12],
                     unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
    if (res != 1) goto err;

    int tag_len = EVP_CIPHER_CTX_tag_length(ctx);
    *ciphertext = OPENSSL_malloc(plaintext_len + tag_len);
    if (!*ciphertext) goto err;

    int ciphertext_len;
    res = EVP_EncryptUpdate(ctx, *ciphertext, &ciphertext_len, plaintext, plaintext_len);
    if (res != 1) goto err;

    int final_len;
    res = EVP_EncryptFinal_ex(ctx, *ciphertext + ciphertext_len, &final_len);
    if (res != 1 || final_len != 0) goto err;

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, *ciphertext + ciphertext_len);
    if (res != 1) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + tag_len;

err:
    EVP_CIPHER_CTX_free(ctx);
    if (*ciphertext) OPENSSL_free(*ciphertext);
    *ciphertext = NULL;
    return -1;
}

int open_aes_256_gcm(const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char key[32], const unsigned char nonce[12],
                     unsigned char **plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int res = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
    if (res != 1) goto err;

    int tag_len = EVP_CIPHER_CTX_tag_length(ctx);
    *plaintext = OPENSSL_malloc(ciphertext_len - tag_len);
    if (!*plaintext) goto err;

    int plaintext_len;
    res = EVP_DecryptUpdate(ctx, *plaintext, &plaintext_len, ciphertext,
                            ciphertext_len - tag_len);
    if (res != 1) goto err;

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len,
                              (void *)(ciphertext + ciphertext_len - tag_len));
    if (res != 1) goto err;

    int final_len;
    res = EVP_DecryptFinal_ex(ctx, *plaintext + plaintext_len, &final_len);
    if (res != 1 || final_len != 0) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;

err:
    EVP_CIPHER_CTX_free(ctx);
    if (*plaintext) OPENSSL_free(*plaintext);
    *plaintext = NULL;
    return -1;
}

int seal_xaes_256_gcm(const unsigned char *plaintext, size_t plaintext_len,
                      const unsigned char key[32], const unsigned char nonce[24],
                      unsigned char **ciphertext) {
    unsigned char derived_key[32];
    if (!derive_key(derived_key, key, nonce)) return 0;
    return seal_aes_256_gcm(plaintext, plaintext_len, derived_key, nonce + 12, ciphertext);
}

int open_xaes_256_gcm(const unsigned char *ciphertext, size_t ciphertext_len,
                      const unsigned char key[32], const unsigned char nonce[24],
                      unsigned char **plaintext) {
    unsigned char derived_key[32];
    if (!derive_key(derived_key, key, nonce)) return 0;
    return open_aes_256_gcm(ciphertext, ciphertext_len, derived_key, nonce + 12, plaintext);
}

int main() {
    const unsigned char key[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    const unsigned char nonce[24] = {
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};

    const unsigned char *plaintext = (const unsigned char *)"Hello, XAES-256-GCM!";
    size_t plaintext_len = strlen((const char *)plaintext);

    unsigned char *ciphertext;
    int ciphertext_len = seal_xaes_256_gcm(plaintext, plaintext_len, key, nonce, &ciphertext);
    if (ciphertext_len < 0) return 1;

    for (size_t i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    unsigned char *decrypted;
    int decrypted_len = open_xaes_256_gcm(ciphertext, ciphertext_len, key, nonce, &decrypted);
    if (decrypted_len < 0) return 1;

    printf("%.*s\n", decrypted_len, decrypted);

    OPENSSL_free(ciphertext);
    OPENSSL_free(decrypted);
    return 0;
}
