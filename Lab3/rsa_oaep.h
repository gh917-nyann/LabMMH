#ifndef RSA_OAEP_H
#define RSA_OAEP_H

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

[[noreturn]] static inline void die_oaep(const char* what) {
    std::fprintf(stderr, "FAILED: %s\n", what);
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

#define OK1_OAEP(call)    do { if ((call) != 1) die_oaep(#call); } while (0)
#define OKPOS_OAEP(call)  do { if ((call) <= 0) die_oaep(#call); } while (0)
#define NOTNULL_OAEP(ptr) do { if ((ptr) == nullptr) die_oaep(#ptr " is NULL"); } while (0)

static inline void print_hex_oaep(const char* label, const unsigned char* p, size_t n, size_t maxShown = 24) {
    std::printf("  %-16s", label);
    for (size_t i = 0; i < n && i < maxShown; ++i) std::printf("%02x", p[i]);
    if (n > maxShown) std::printf("... (%lu bytes)", static_cast<unsigned long>(n));
    std::printf("\n");
}

static inline void print_bn_oaep(const char* label, const BIGNUM* x) {
    char* s = BN_bn2dec(x);
    NOTNULL_OAEP(s);
    std::printf("  %-16s%s\n", label, s);
    OPENSSL_free(s);
}

// ============================================================================
// Part 1: Conversion Primitives (RFC 8017 Section 4)
// ============================================================================
static inline BIGNUM* os2ip(const Bytes& x) {
    BIGNUM* r = BN_bin2bn(x.data(), static_cast<int>(x.size()), nullptr);
    NOTNULL_OAEP(r);
    return r;
}

static inline bool i2osp(const BIGNUM* x, size_t len, Bytes& out) {
    out.assign(len, 0);
    return BN_bn2binpad(x, out.data(), static_cast<int>(len)) >= 0;
}

static inline Bytes hex_to_bytes(const char* h) {
    Bytes b;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
        char two[3] = {h[i], h[i + 1], 0};
        b.push_back(static_cast<unsigned char>(std::strtoul(two, nullptr, 16)));
    }
    return b;
}

// ============================================================================
// Part 2: Textbook RSA (c = m^e mod n, m = c^d mod n)
// ============================================================================
static inline void textbook_rsa_encrypt(BIGNUM* c, const BIGNUM* m, const BIGNUM* e, const BIGNUM* n, BN_CTX* ctx) {
    OK1_OAEP(BN_mod_exp(c, m, e, n, ctx));
}

static inline void textbook_rsa_decrypt(BIGNUM* m, const BIGNUM* c, const BIGNUM* d, const BIGNUM* n, BN_CTX* ctx) {
    OK1_OAEP(BN_mod_exp(m, c, d, n, ctx));
}

// ============================================================================
// Part 3: EME-OAEP (SHA-256 + MGF1) & OpenSSL RSA-OAEP
// ============================================================================
static const size_t hLen = 32; // SHA-256 digest length

static inline Bytes sha256(const Bytes& data) {
    Bytes out(hLen);
    unsigned int len = 0;
    OK1_OAEP(EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr));
    return out;
}

static inline Bytes mgf1(const Bytes& seed, size_t maskLen) {
    Bytes t;
    for (uint32_t counter = 0; t.size() < maskLen; ++counter) {
        Bytes block = seed;
        block.push_back(static_cast<unsigned char>(counter >> 24));
        block.push_back(static_cast<unsigned char>(counter >> 16));
        block.push_back(static_cast<unsigned char>(counter >> 8));
        block.push_back(static_cast<unsigned char>(counter));
        Bytes h = sha256(block);
        t.insert(t.end(), h.begin(), h.end());
    }
    t.resize(maskLen);
    return t;
}

static inline void xor_into(Bytes& a, const Bytes& b) {
    for (size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
}

// Custom EME-OAEP encoding: EM = 0x00 || maskedSeed || maskedDB
static inline Bytes oaep_encode(const Bytes& M, size_t k) {
    if (M.size() > k - 2 * hLen - 2) die_oaep("message too long for OAEP");
    const size_t dbLen = k - hLen - 1;
    Bytes db(dbLen, 0x00);
    Bytes lHash = sha256(Bytes{});
    std::memcpy(db.data(), lHash.data(), hLen);
    db[dbLen - M.size() - 1] = 0x01;
    if (!M.empty()) {
        std::memcpy(db.data() + dbLen - M.size(), M.data(), M.size());
    }

    Bytes seed(hLen);
    OK1_OAEP(RAND_bytes(seed.data(), static_cast<int>(hLen)));
    xor_into(db, mgf1(seed, dbLen));
    xor_into(seed, mgf1(db, hLen));

    Bytes em(k, 0x00);
    std::memcpy(em.data() + 1, seed.data(), hLen);
    std::memcpy(em.data() + 1 + hLen, db.data(), dbLen);
    OPENSSL_cleanse(seed.data(), seed.size());
    return em;
}

// Custom EME-OAEP decoding (Constant-time verification of padding & lHash)
static inline bool oaep_decode(const Bytes& em, size_t k, Bytes& M) {
    if (em.size() != k || k < 2 * hLen + 2) return false;
    const size_t dbLen = k - hLen - 1;
    Bytes seed(em.begin() + 1, em.begin() + 1 + hLen);
    Bytes db(em.begin() + 1 + hLen, em.end());
    xor_into(seed, mgf1(db, hLen));
    xor_into(db, mgf1(seed, dbLen));
    Bytes lHash = sha256(Bytes{});

    // Constant-time comparison for lHash to mitigate side-channel timing attacks
    bool good = (em[0] == 0x00) && (CRYPTO_memcmp(lHash.data(), db.data(), hLen) == 0);
    size_t i = hLen;
    while (i < db.size() && db[i] == 0x00) ++i;
    good = good && (i < db.size()) && (db[i] == 0x01);
    if (good) M.assign(db.begin() + i + 1, db.end());

    OPENSSL_cleanse(seed.data(), seed.size());
    OPENSSL_cleanse(db.data(), db.size());
    return good;
}

// Configure OpenSSL EVP OAEP padding parameters
static inline void configure_oaep(EVP_PKEY_CTX* ctx) {
    OKPOS_OAEP(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING));
    OKPOS_OAEP(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()));
    OKPOS_OAEP(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()));
}

// OpenSSL EVP_PKEY OAEP encryption
static inline Bytes evp_oaep_encrypt(EVP_PKEY* key, const Bytes& M) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    NOTNULL_OAEP(ctx);
    OKPOS_OAEP(EVP_PKEY_encrypt_init(ctx));
    configure_oaep(ctx);
    size_t outLen = 0;
    OKPOS_OAEP(EVP_PKEY_encrypt(ctx, nullptr, &outLen, M.data(), M.size()));
    Bytes out(outLen);
    OKPOS_OAEP(EVP_PKEY_encrypt(ctx, out.data(), &outLen, M.data(), M.size()));
    out.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

// OpenSSL EVP_PKEY OAEP decryption
static inline bool evp_oaep_decrypt(EVP_PKEY* key, const Bytes& C, Bytes& M) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    NOTNULL_OAEP(ctx);
    OKPOS_OAEP(EVP_PKEY_decrypt_init(ctx));
    configure_oaep(ctx);
    size_t outLen = 0;
    OKPOS_OAEP(EVP_PKEY_decrypt(ctx, nullptr, &outLen, C.data(), C.size()));
    M.assign(outLen, 0);
    bool ok = EVP_PKEY_decrypt(ctx, M.data(), &outLen, C.data(), C.size()) > 0;
    if (ok) M.resize(outLen); else ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// Raw RSA modular exponentiation: I2OSP(OS2IP(x)^exp mod n, k)
static inline Bytes rsa_raw(const Bytes& x, const BIGNUM* exp, const BIGNUM* n, size_t k) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *xi = os2ip(x), *yi = BN_new();
    NOTNULL_OAEP(ctx); NOTNULL_OAEP(yi);
    if (BN_cmp(xi, n) >= 0) die_oaep("representative out of range");
    OK1_OAEP(BN_mod_exp(yi, xi, exp, n, ctx));
    Bytes y;
    if (!i2osp(yi, k, y)) die_oaep("I2OSP failed");
    BN_free(xi); BN_clear_free(yi); BN_CTX_free(ctx);
    return y;
}

#endif // RSA_OAEP_H

