// rsa_kem.h -- Task 5: RSASVE KEM + HKDF-SHA-256 + AES-256-GCM
#ifndef RSA_KEM_H
#define RSA_KEM_H

#include "rsa_key.h"
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <cstdint>

static const char* const PROFILE_LABEL = "LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1";

// Endian helper functions
static inline void pack_u16_be(uint16_t v, unsigned char* p) {
    p[0] = static_cast<unsigned char>((v >> 8) & 0xFF);
    p[1] = static_cast<unsigned char>(v & 0xFF);
}
static inline uint16_t unpack_u16_be(const unsigned char* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
}
static inline void pack_u64_be(uint64_t v, unsigned char* p) {
    for (int i = 7; i >= 0; --i) { p[i] = static_cast<unsigned char>(v & 0xFF); v >>= 8; }
}
static inline uint64_t unpack_u64_be(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

// AES-256-GCM Encryption & Decryption
static inline bool gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& pt,
                               const Bytes& aad, Bytes& ct, Bytes& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len = 0;
    bool ok = (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr) == 1);
    if (ok && !aad.empty())
        ok = (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1);
    ct.resize(pt.size());
    if (ok && !pt.empty())
        ok = (EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), static_cast<int>(pt.size())) == 1);
    if (ok) {
        int finalLen = 0;
        ok = (EVP_EncryptFinal_ex(ctx, ct.data() + len, &finalLen) == 1);
    }
    tag.resize(16);
    if (ok) ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static inline bool gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ct,
                               const Bytes& aad, const Bytes& tag, Bytes& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int len = 0;
    bool ok = (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr) == 1);
    if (ok && !aad.empty())
        ok = (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1);
    pt.resize(ct.size());
    if (ok && !ct.empty())
        ok = (EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(), static_cast<int>(ct.size())) == 1);
    if (ok)
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(tag.data())) == 1);
    if (ok) {
        int finalLen = 0;
        ok = (EVP_DecryptFinal_ex(ctx, pt.data() + len, &finalLen) > 0);
    }
    if (!ok) {
        if (!pt.empty()) OPENSSL_cleanse(pt.data(), pt.size());
        pt.clear();
        ERR_clear_error();
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ============================================================================
// Part 1: RSASVE KEM (NIST SP 800-56B)
// ============================================================================
static inline bool evp_encaps(EVP_PKEY* pubKey, Bytes& kem_ct, Bytes& z) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pubKey, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0 ||
        EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE") <= 0) {
        EVP_PKEY_CTX_free(ctx); return false;
    }
    size_t wlen = 0, slen = 0;
    if (EVP_PKEY_encapsulate(ctx, nullptr, &wlen, nullptr, &slen) <= 0) {
        EVP_PKEY_CTX_free(ctx); return false;
    }
    kem_ct.resize(wlen); z.resize(slen);
    bool ok = (EVP_PKEY_encapsulate(ctx, kem_ct.data(), &wlen, z.data(), &slen) > 0);
    kem_ct.resize(wlen); z.resize(slen);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static inline bool evp_decaps(EVP_PKEY* privKey, const Bytes& kem_ct, Bytes& z) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, privKey, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0 ||
        EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE") <= 0) {
        EVP_PKEY_CTX_free(ctx); return false;
    }
    size_t slen = 0;
    if (EVP_PKEY_decapsulate(ctx, nullptr, &slen, kem_ct.data(), kem_ct.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx); return false;
    }
    z.resize(slen);
    bool ok = (EVP_PKEY_decapsulate(ctx, z.data(), &slen, kem_ct.data(), kem_ct.size()) > 0);
    if (ok) z.resize(slen); else { z.clear(); ERR_clear_error(); }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// Educational RSASVE using BIGNUM: z in [2, n-2], c = z^e mod n, z = c^d mod n
static inline bool edu_encaps(EVP_PKEY* pubKey, Bytes& kem_ct, Bytes& z) {
    BIGNUM *n = nullptr, *e = nullptr;
    if (EVP_PKEY_get_bn_param(pubKey, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(pubKey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        BN_free(n); BN_free(e); return false;
    }
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *z_bn = BN_new(), *c_bn = BN_new(), *range = BN_dup(n);
    BN_sub_word(range, 3);
    if (BN_rand_range(z_bn, range) != 1) {
        BN_free(n); BN_free(e); BN_clear_free(z_bn); BN_free(c_bn); BN_free(range);
        BN_CTX_free(ctx);
        return false;
    }
    BN_add_word(z_bn, 2);
    BN_mod_exp(c_bn, z_bn, e, n, ctx);

    int k = BN_num_bytes(n);
    kem_ct.assign(k, 0); z.assign(k, 0);
    BN_bn2binpad(c_bn, kem_ct.data(), k);
    BN_bn2binpad(z_bn, z.data(), k);

    BN_free(n); BN_free(e); BN_clear_free(z_bn); BN_free(c_bn); BN_free(range);
    BN_CTX_free(ctx);
    return true;
}

static inline bool edu_decaps(EVP_PKEY* privKey, const Bytes& kem_ct, Bytes& z) {
    BIGNUM *n = nullptr, *d = nullptr;
    if (EVP_PKEY_get_bn_param(privKey, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(privKey, OSSL_PKEY_PARAM_RSA_D, &d) != 1) {
        BN_free(n); BN_clear_free(d); return false;
    }
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* c_bn = BN_bin2bn(kem_ct.data(), static_cast<int>(kem_ct.size()), nullptr);
    BIGNUM* z_bn = BN_new();
    BN_mod_exp(z_bn, c_bn, d, n, ctx);

    int k = BN_num_bytes(n);
    z.assign(k, 0);
    BN_bn2binpad(z_bn, z.data(), k);

    BN_free(n); BN_clear_free(d); BN_free(c_bn); BN_clear_free(z_bn);
    BN_CTX_free(ctx);
    return true;
}

// ============================================================================
// Part 2: HKDF-SHA-256 (RFC 5869)
// ============================================================================
static inline Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    size_t outLen = 0;
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr,
                   key.data(), key.size(), data.data(), data.size(),
                   out.data(), out.size(), &outLen)) {
        die_rsa("EVP_Q_mac failed");
    }
    out.resize(outLen);
    return out;
}

static inline Bytes my_hkdf(const Bytes& salt, const Bytes& ikm, const Bytes& info, size_t outLen) {
    Bytes s = salt.empty() ? Bytes(32, 0x00) : salt;
    Bytes prk = hmac_sha256(s, ikm);
    Bytes okm, t;
    size_t n = (outLen + 31) / 32;
    for (size_t i = 1; i <= n; ++i) {
        Bytes d = t;
        d.insert(d.end(), info.begin(), info.end());
        d.push_back(static_cast<unsigned char>(i));
        t = hmac_sha256(prk, d);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(outLen);
    return okm;
}

static inline Bytes evp_hkdf(const Bytes& salt, const Bytes& ikm, const Bytes& info, size_t outLen) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) die_rsa("EVP_KDF_fetch failed");
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) die_rsa("EVP_KDF_CTX_new failed");

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    std::vector<OSSL_PARAM> p;
    p.push_back(OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode));
    p.push_back(OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0));
    p.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(ikm.data()), ikm.size()));
    if (!salt.empty()) {
        p.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size()));
    }
    if (!info.empty()) {
        p.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<unsigned char*>(info.data()), info.size()));
    }
    p.push_back(OSSL_PARAM_construct_end());

    Bytes out(outLen);
    if (EVP_KDF_derive(kctx, out.data(), outLen, p.data()) <= 0) {
        EVP_KDF_CTX_free(kctx);
        die_rsa("EVP_KDF_derive failed");
    }
    EVP_KDF_CTX_free(kctx);
    return out;
}

// ============================================================================
// Part 3: Package Mode 0x02 Format & Sealing
// ============================================================================
static inline Bytes derive_aes_key(const Bytes& z, const Bytes& key_id, uint16_t klen, const Bytes& kem_ct) {
    Bytes info;
    info.insert(info.end(), PROFILE_LABEL, PROFILE_LABEL + std::strlen(PROFILE_LABEL));
    info.push_back(0x00);
    info.insert(info.end(), key_id.begin(), key_id.end());
    unsigned char klen_b[2];
    pack_u16_be(klen, klen_b);
    info.insert(info.end(), klen_b, klen_b + 2);
    info.insert(info.end(), kem_ct.begin(), kem_ct.end());
    return evp_hkdf(Bytes{}, z, info, 32);
}

static inline bool seal_package_kem(EVP_PKEY* pubKey, const Bytes& pt, Bytes& pkg) {
    if (!pubKey) return false;
    Bytes kem_ct, z;
    if (!evp_encaps(pubKey, kem_ct, z)) return false;

    Bytes key_id = compute_key_id(pubKey);
    uint16_t klen = static_cast<uint16_t>(kem_ct.size());
    Bytes k_aes = derive_aes_key(z, key_id, klen, kem_ct);
    OPENSSL_cleanse(z.data(), z.size());

    Bytes nonce(12);
    if (RAND_bytes(nonce.data(), 12) != 1) {
        OPENSSL_cleanse(k_aes.data(), k_aes.size());
        return false;
    }

    uint64_t ct_len = pt.size();
    Bytes H;
    H.reserve(62 + klen);
    H.push_back('L'); H.push_back('2'); H.push_back('P'); H.push_back('K'); // Magic
    H.push_back(0x01); // Version
    H.push_back(0x02); // Mode: RSASVE KEM + HKDF + AES-256-GCM
    H.push_back(0x00); H.push_back(0x00); // Reserved
    unsigned char klen_b[2];
    pack_u16_be(klen, klen_b);
    H.insert(H.end(), klen_b, klen_b + 2);
    H.insert(H.end(), kem_ct.begin(), kem_ct.end());
    H.insert(H.end(), key_id.begin(), key_id.end());
    H.insert(H.end(), nonce.begin(), nonce.end());
    unsigned char ctlen_b[8];
    pack_u64_be(ct_len, ctlen_b);
    H.insert(H.end(), ctlen_b, ctlen_b + 8);

    Bytes C, tag;
    bool ok = gcm_encrypt(k_aes, nonce, pt, H, C, tag);
    OPENSSL_cleanse(k_aes.data(), k_aes.size());
    if (!ok) return false;

    pkg = std::move(H);
    pkg.insert(pkg.end(), C.begin(), C.end());
    pkg.insert(pkg.end(), tag.begin(), tag.end());
    return true;
}

static inline bool open_package_kem(EVP_PKEY* privKey, const Bytes& pkg, Bytes& pt) {
    if (!privKey || pkg.size() < 78) return false; // 62 (header min) + 16 (tag)
    if (pkg[0] != 'L' || pkg[1] != '2' || pkg[2] != 'P' || pkg[3] != 'K') return false;
    if (pkg[4] != 0x01 || pkg[5] != 0x02 || pkg[6] != 0x00 || pkg[7] != 0x00) return false;

    uint16_t klen = unpack_u16_be(&pkg[8]);
    if (pkg.size() < static_cast<size_t>(62 + klen + 16)) return false;

    const unsigned char* pKemCt = &pkg[10];
    const unsigned char* pKeyId = &pkg[10 + klen];
    const unsigned char* pNonce = &pkg[10 + klen + 32];
    const unsigned char* pCtLen = &pkg[10 + klen + 32 + 12];
    uint64_t ct_len = unpack_u64_be(pCtLen);

    size_t header_len = 62 + klen;
    if (pkg.size() != header_len + ct_len + 16) return false;

    Bytes my_key_id = compute_key_id(privKey);
    if (CRYPTO_memcmp(my_key_id.data(), pKeyId, 32) != 0) return false;

    Bytes kem_ct(pKemCt, pKemCt + klen);
    Bytes key_id(pKeyId, pKeyId + 32);
    Bytes nonce(pNonce, pNonce + 12);
    Bytes H(pkg.begin(), pkg.begin() + header_len);
    Bytes C(pkg.begin() + header_len, pkg.begin() + header_len + ct_len);
    Bytes tag(pkg.begin() + header_len + ct_len, pkg.end());

    Bytes z;
    if (!evp_decaps(privKey, kem_ct, z)) return false;

    Bytes k_aes = derive_aes_key(z, key_id, klen, kem_ct);
    OPENSSL_cleanse(z.data(), z.size());

    bool ok = gcm_decrypt(k_aes, nonce, C, H, tag, pt);
    OPENSSL_cleanse(k_aes.data(), k_aes.size());
    return ok;
}

// File I/O
static inline bool read_file_bytes(const char* path, Bytes& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    if (sz < 0) { std::fclose(f); return false; }
    std::fseek(f, 0, SEEK_SET);
    out.resize(static_cast<size_t>(sz));
    size_t n = std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return n == out.size();
}

static inline bool write_file_bytes(const char* path, const Bytes& in) {
    FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    size_t n = std::fwrite(in.data(), 1, in.size(), f);
    std::fclose(f);
    return n == in.size();
}

#endif // RSA_KEM_H
