// hybrid_crypto.h -- Task 4: Hybrid File Encryption (RSA-OAEP + AES-256-GCM)
#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H

#include "rsa_key.h"
#include "rsa_oaep.h"
#include <cstdint>

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

// AES-256-GCM Encryption with AAD
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
    if (ok)
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-256-GCM Decryption with AAD and Tag verification
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

// RSA-OAEP Key Wrapping & Unwrapping
static inline Bytes oaep_wrap(EVP_PKEY* pubKey, const Bytes& key) {
    return evp_oaep_encrypt(pubKey, key);
}

static inline bool oaep_unwrap(EVP_PKEY* privKey, const Bytes& wrapped, Bytes& key) {
    return evp_oaep_decrypt(privKey, wrapped, key);
}

// Seal Package v1 (L2PK): H || C || Tag
static inline bool seal_package(EVP_PKEY* pubKey, const Bytes& pt, Bytes& pkg) {
    if (!pubKey) return false;
    Bytes K(32), N(12);
    if (RAND_bytes(K.data(), 32) != 1 || RAND_bytes(N.data(), 12) != 1) return false;

    Bytes W = oaep_wrap(pubKey, K);
    if (W.empty()) { OPENSSL_cleanse(K.data(), 32); return false; }

    uint16_t klen = static_cast<uint16_t>(W.size());
    uint64_t ct_len = pt.size();

    Bytes H;
    H.reserve(30 + klen);
    H.push_back('L'); H.push_back('2'); H.push_back('P'); H.push_back('K'); // Magic
    H.push_back(0x01); // Version
    H.push_back(0x01); // Mode: AES-256-GCM + RSA-OAEP
    H.push_back(0x00); H.push_back(0x00); // Reserved
    unsigned char klen_b[2];
    pack_u16_be(klen, klen_b);
    H.insert(H.end(), klen_b, klen_b + 2);
    H.insert(H.end(), W.begin(), W.end());
    H.insert(H.end(), N.begin(), N.end());
    unsigned char ctlen_b[8];
    pack_u64_be(ct_len, ctlen_b);
    H.insert(H.end(), ctlen_b, ctlen_b + 8);

    Bytes C, tag;
    bool ok = gcm_encrypt(K, N, pt, H, C, tag);
    OPENSSL_cleanse(K.data(), 32);
    if (!ok) return false;

    pkg = std::move(H);
    pkg.insert(pkg.end(), C.begin(), C.end());
    pkg.insert(pkg.end(), tag.begin(), tag.end());
    return true;
}

// Open Package v1 (L2PK): Verify H, unwrap K, decrypt C, check Tag
static inline bool open_package(EVP_PKEY* privKey, const Bytes& pkg, Bytes& pt) {
    if (!privKey || pkg.size() < 46) return false;
    if (pkg[0] != 'L' || pkg[1] != '2' || pkg[2] != 'P' || pkg[3] != 'K') return false;
    if (pkg[4] != 0x01 || pkg[5] != 0x01 || pkg[6] != 0x00 || pkg[7] != 0x00) return false;

    uint16_t klen = unpack_u16_be(&pkg[8]);
    if (pkg.size() < static_cast<size_t>(30 + klen + 16)) return false;

    const unsigned char* pW = &pkg[10];
    const unsigned char* pN = &pkg[10 + klen];
    const unsigned char* pCtLen = &pkg[10 + klen + 12];
    uint64_t ct_len = unpack_u64_be(pCtLen);

    size_t header_len = 30 + klen;
    if (pkg.size() != header_len + ct_len + 16) return false;

    Bytes W(pW, pW + klen);
    Bytes N(pN, pN + 12);
    Bytes H(pkg.begin(), pkg.begin() + header_len);
    Bytes C(pkg.begin() + header_len, pkg.begin() + header_len + ct_len);
    Bytes tag(pkg.begin() + header_len + ct_len, pkg.end());

    Bytes K;
    if (!oaep_unwrap(privKey, W, K) || K.size() != 32) {
        if (!K.empty()) OPENSSL_cleanse(K.data(), K.size());
        return false;
    }

    bool ok = gcm_decrypt(K, N, C, H, tag, pt);
    OPENSSL_cleanse(K.data(), K.size());
    return ok;
}

// Binary File I/O Helpers
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

#endif // HYBRID_CRYPTO_H

