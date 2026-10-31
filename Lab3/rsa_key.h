#ifndef RSA_KEY_H
#define RSA_KEY_H

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

[[noreturn]] static inline void die_rsa(const char* what) {
    std::fprintf(stderr, "FAILED: %s\n", what);
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

#define OK1_KEY(call)    do { if ((call) != 1) die_rsa(#call); } while (0)
#define OKPOS_KEY(call)  do { if ((call) <= 0) die_rsa(#call); } while (0)
#define NOTNULL_KEY(ptr) do { if ((ptr) == nullptr) die_rsa(#ptr " is NULL"); } while (0)

static inline void print_hex(const char* label, const unsigned char* p, size_t n, size_t maxShown = 24) {
    std::printf("  %-16s", label);
    for (size_t i = 0; i < n && i < maxShown; ++i) std::printf("%02x", p[i]);
    if (n > maxShown) std::printf("... (%lu bytes)", static_cast<unsigned long>(n));
    std::printf("\n");
}

static inline void print_bn_bits(const char* label, const BIGNUM* x) {
    char* s = BN_bn2hex(x);
    NOTNULL_KEY(s);
    std::printf("  %-16s%d bits, 0x%.24s...\n", label, BN_num_bits(x), s);
    OPENSSL_free(s);
}

static inline void print_bn_dec(const char* label, const BIGNUM* x) {
    char* s = BN_bn2dec(x);
    NOTNULL_KEY(s);
    std::printf("  %-16s%s\n", label, s);
    OPENSSL_free(s);
}

// Generate RSA key pair using modern OpenSSL 3 EVP API
static inline EVP_PKEY* generate_rsa_key(int bits = 3072) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    NOTNULL_KEY(kctx);
    OKPOS_KEY(EVP_PKEY_keygen_init(kctx));
    OKPOS_KEY(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits));
    EVP_PKEY* key = nullptr;
    OKPOS_KEY(EVP_PKEY_generate(kctx, &key));
    EVP_PKEY_CTX_free(kctx);
    return key;
}

// Check if an EVP_PKEY contains private key parameters
static inline bool is_private_key(EVP_PKEY* pkey) {
    if (!pkey) return false;
    BIGNUM* d = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) == 1) {
        BN_clear_free(d);
        return true;
    }
    return false;
}

// Export key files: PEM (PKCS#8 & SPKI) and DER (PKCS#8 & SPKI)
static inline void export_key_files(EVP_PKEY* key,
                                   const char* privPem = "private.pem",
                                   const char* pubPem  = "public.pem",
                                   const char* privDer = "private.der",
                                   const char* pubDer  = "public.der") {
    if (is_private_key(key)) {
        BIO* b = BIO_new_file(privPem, "wb"); NOTNULL_KEY(b);
        OK1_KEY(PEM_write_bio_PrivateKey(b, key, nullptr, nullptr, 0, nullptr, nullptr));
        BIO_free(b);

        b = BIO_new_file(privDer, "wb"); NOTNULL_KEY(b);
        OK1_KEY(i2d_PKCS8PrivateKey_bio(b, key, nullptr, nullptr, 0, nullptr, nullptr));
        BIO_free(b);
    }
    BIO* b = BIO_new_file(pubPem, "wb"); NOTNULL_KEY(b);
    OK1_KEY(PEM_write_bio_PUBKEY(b, key));
    BIO_free(b);

    b = BIO_new_file(pubDer, "wb"); NOTNULL_KEY(b);
    OK1_KEY(i2d_PUBKEY_bio(b, key));
    BIO_free(b);
    std::printf("  Exported key files successfully (%s, %s)\n", pubPem, pubDer);
}

// Load key from file with format support (PEM/DER)
static inline EVP_PKEY* load_key_from_file(const char* path, bool isPrivate, bool isPem) {
    BIO* b = BIO_new_file(path, "rb");
    NOTNULL_KEY(b);
    EVP_PKEY* k = nullptr;
    if (isPrivate) {
        k = isPem ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr)
                  : d2i_PrivateKey_bio(b, nullptr);
    } else {
        k = isPem ? PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr)
                  : d2i_PUBKEY_bio(b, nullptr);
    }
    BIO_free(b);
    NOTNULL_KEY(k);
    return k;
}

// Auto detect and load key from file (PEM or DER, private or public)
static inline EVP_PKEY* load_key_auto(const char* path) {
    BIO* b = BIO_new_file(path, "rb");
    if (!b) return nullptr;

    EVP_PKEY* k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
    if (!k) {
        (void)BIO_reset(b); ERR_clear_error();
        k = PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr);
    }
    if (!k) {
        (void)BIO_reset(b); ERR_clear_error();
        k = d2i_PrivateKey_bio(b, nullptr);
    }
    if (!k) {
        (void)BIO_reset(b); ERR_clear_error();
        k = d2i_PUBKEY_bio(b, nullptr);
    }
    BIO_free(b);
    if (!k) ERR_clear_error();
    return k;
}

// Compute Key ID (SHA-256 over SubjectPublicKeyInfo DER bytes)
static inline Bytes compute_key_id(EVP_PKEY* key) {
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0) die_rsa("i2d_PUBKEY failed");
    Bytes id(32);
    unsigned int outLen = 0;
    OK1_KEY(EVP_Digest(der, static_cast<size_t>(len), id.data(), &outLen, EVP_sha256(), nullptr));
    OPENSSL_free(der);
    return id;
}

// Extract BIGNUM parameter from EVP_PKEY
static inline BIGNUM* get_bn_param(EVP_PKEY* key, const char* name) {
    BIGNUM* x = nullptr;
    OK1_KEY(EVP_PKEY_get_bn_param(key, name, &x));
    return x;
}

// Show key information (n, e, d, p, q, dP, dQ, qInv)
static inline void print_key_info(EVP_PKEY* key) {
    if (!key) {
        std::printf("  No key loaded!\n");
        return;
    }
    std::printf("\n--- Key Information (RSA %d-bit, %s) ---\n",
                EVP_PKEY_get_bits(key), is_private_key(key) ? "private" : "public");
    BIGNUM* n = get_bn_param(key, OSSL_PKEY_PARAM_RSA_N);
    BIGNUM* e = get_bn_param(key, OSSL_PKEY_PARAM_RSA_E);
    print_bn_bits("n", n);
    print_bn_dec("e", e);
    BN_free(n); BN_free(e);

    if (is_private_key(key)) {
        BIGNUM *d = nullptr, *p = nullptr, *q = nullptr, *dP = nullptr, *dQ = nullptr, *qInv = nullptr;
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d)) { print_bn_bits("d", d); BN_clear_free(d); }
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p)) { print_bn_bits("p", p); BN_clear_free(p); }
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q)) { print_bn_bits("q", q); BN_clear_free(q); }
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dP)) { print_bn_bits("dP", dP); BN_clear_free(dP); }
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dQ)) { print_bn_bits("dQ", dQ); BN_clear_free(dQ); }
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qInv)) { print_bn_bits("qInv", qInv); BN_clear_free(qInv); }
    }
    Bytes id = compute_key_id(key);
    print_hex("Key ID (SHA-256)", id.data(), id.size(), 32);
}

// Print key in PEM format to stdout
static inline void print_key_pem_stdout(EVP_PKEY* key) {
    if (!key) {
        std::printf("  No key loaded!\n");
        return;
    }
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    NOTNULL_KEY(out);
    if (is_private_key(key)) {
        std::printf("\n--- Private Key (PKCS#8 PEM) ---\n");
        PEM_write_bio_PrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr);
    }
    std::printf("\n--- Public Key (SubjectPublicKeyInfo PEM) ---\n");
    PEM_write_bio_PUBKEY(out, key);
    BIO_free(out);
}

#endif // RSA_KEY_H
