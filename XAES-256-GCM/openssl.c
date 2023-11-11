int derive_key(unsigned char out[32], const unsigned char key[32], const unsigned char nonce[24]) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[9], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "AES256", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "CMAC", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "COUNTER", 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, 16);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "X", strlen("X"));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, nonce[:12], 12);
    *p = OSSL_PARAM_construct_end();

    int res = EVP_KDF_derive(kctx, out, sizeof(out), params);
    
    EVP_KDF_CTX_free(kctx);
    return res;
}
