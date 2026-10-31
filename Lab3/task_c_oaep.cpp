// task_c_oaep.cpp -- Task 3 Test Runner: OS2IP/I2OSP, Textbook RSA & OAEP
#include "rsa_oaep.h"

static int g_failures = 0;

[[maybe_unused]] static void check(const char* name, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

static void part1Encoding() {
    std::printf("== Part 1: OS2IP and I2OSP Conversion Tests ==\n");
    struct Case { const char* id; const char* hex; size_t width; const char* expect; };
    const Case cases[] = {
        {"C-T1", "000001", 3, "000001"}, {"C-T2", "000001", 1, "01"},
        {"C-T3", "0100", 2, "0100"},     {"C-T4", "0100", 1, nullptr /* too large */},
        {"C-T5", "00ff00", 3, "00ff00"}, {"C-T6", "", 2, "0000"},
    };
    for (const Case& c : cases) {
        Bytes in = hex_to_bytes(c.hex), out;
        BIGNUM* x = os2ip(in);
        char* dec = BN_bn2dec(x);
        NOTNULL_OAEP(dec);
        bool fits = i2osp(x, c.width, out);
        std::string got;
        for (unsigned char v : out) { char t[3]; std::snprintf(t, 3, "%02x", v); got += t; }
        std::printf("  X=%-8s OS2IP=%-6s I2OSP(.,%lu)=%s\n", c.hex[0] ? c.hex : "(empty)",
                    dec, static_cast<unsigned long>(c.width), fits ? got.c_str() : "error: integer too large");
        check(c.id, c.expect ? (fits && got == c.expect) : !fits);
        OPENSSL_free(dec);
        BN_free(x);
    }
    std::printf("\n");
}

static void part2Textbook() {
    std::printf("== Part 2: Textbook RSA Vulnerability Analysis ==\n");
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *d = BN_new(), *m = BN_new();
    BIGNUM *c = BN_new(), *c2 = BN_new(), *r = BN_new(), *c6 = BN_new();
    BIGNUM *c7 = BN_new(), *forged = BN_new();
    OK1_OAEP(BN_set_word(n, 3233)); OK1_OAEP(BN_set_word(e, 17)); OK1_OAEP(BN_set_word(d, 2753));

    // Basic encryption & decryption
    OK1_OAEP(BN_set_word(m, 65));
    textbook_rsa_encrypt(c, m, e, n, ctx);
    textbook_rsa_decrypt(r, c, d, n, ctx);
    print_bn_oaep("Enc(65)", c);
    check("Enc(65) = 2790 and decrypts to 65", BN_is_word(c, 2790) && BN_is_word(r, 65));

    // Vulnerability 1: Determinism (identical ciphertexts)
    textbook_rsa_encrypt(c2, m, e, n, ctx);
    check("deterministic: Enc(65) == Enc(65)", BN_cmp(c, c2) == 0);

    // Vulnerability 2: Malleability (multiplication attack)
    BIGNUM *six = BN_new(), *seven = BN_new();
    OK1_OAEP(BN_set_word(six, 6)); OK1_OAEP(BN_set_word(seven, 7));
    textbook_rsa_encrypt(c6, six, e, n, ctx);
    textbook_rsa_encrypt(c7, seven, e, n, ctx);
    OK1_OAEP(BN_mod_mul(forged, c6, c7, n, ctx)); // Forged ciphertext without private key
    textbook_rsa_decrypt(r, forged, d, n, ctx);
    print_bn_oaep("Enc(6)", c6); print_bn_oaep("Enc(7)", c7); print_bn_oaep("Enc6*Enc7", forged);
    check("malleable: Dec(Enc(6)*Enc(7)) = 42", BN_is_word(r, 42));

    for (BIGNUM* x : {n, e, d, m, c, c2, r, c6, c7, forged, six, seven}) BN_free(x);
    BN_CTX_free(ctx);
    std::printf("\n");
}

static void part3Oaep() {
    std::printf("== Part 3: Custom RSA-OAEP vs OpenSSL Cross-Validation ==\n");
    EVP_PKEY* key = EVP_RSA_gen(2048);
    NOTNULL_OAEP(key);
    BIGNUM *n = nullptr, *e = nullptr, *d = nullptr;
    OK1_OAEP(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n));
    OK1_OAEP(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e));
    OK1_OAEP(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d));

    const size_t k = static_cast<size_t>(BN_num_bytes(n)); // 256 bytes for 2048-bit RSA
    const char* text = "attack at dawn";
    Bytes M(text, text + std::strlen(text));

    // 1. Two-way cross compatibility
    // (a) Custom encoding + raw RSA -> OpenSSL decrypts
    Bytes em = oaep_encode(M, k);
    print_hex_oaep("EM (ours)", em.data(), em.size());
    Bytes C1 = rsa_raw(em, e, n, k), back;
    check("OpenSSL decrypts our OAEP ciphertext", evp_oaep_decrypt(key, C1, back) && back == M);

    // (b) OpenSSL encrypts -> raw RSA + custom decoding
    Bytes C2 = evp_oaep_encrypt(key, M);
    Bytes em2 = rsa_raw(C2, d, n, k);
    print_hex_oaep("EM (OpenSSL)", em2.data(), em2.size());
    Bytes M2;
    check("our decoder recovers OpenSSL's message", oaep_decode(em2, k, M2) && M2 == M);

    // 2. Security Properties
    Bytes C3 = evp_oaep_encrypt(key, M);
    check("randomized: two encryptions differ", C2 != C3);

    // Max message length test: k - 2*hLen - 2 = 190 bytes
    Bytes big(k - 2 * hLen - 2, 'A');
    check("190-byte message accepted", evp_oaep_decrypt(key, evp_oaep_encrypt(key, big), back) && back == big);

    // Tamper check: altering 1 bit must fail decryption
    Bytes tampered = C2;
    tampered[10] ^= 0x01;
    check("tampered ciphertext is rejected", !evp_oaep_decrypt(key, tampered, back));

    // Anti-malleability check: multiplying by Enc(2) must fail padding verification
    BIGNUM *two = BN_new(), *c2i = os2ip(C2), *t = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    OK1_OAEP(BN_set_word(two, 2));
    OK1_OAEP(BN_mod_exp(t, two, e, n, ctx));
    OK1_OAEP(BN_mod_mul(t, t, c2i, n, ctx));
    Bytes mauled;
    if (!i2osp(t, k, mauled)) die_oaep("I2OSP failed");
    check("Enc(2)*C is rejected (padding check fails)", !evp_oaep_decrypt(key, mauled, back));

    for (BIGNUM* x : {n, e, two, c2i, t}) BN_free(x);
    BN_clear_free(d);
    BN_CTX_free(ctx);
    EVP_PKEY_free(key);
}

int main() {
    part1Encoding();
    part2Textbook();
    part3Oaep();

    std::printf("\n%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
