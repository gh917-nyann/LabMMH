// task_b_rsa_keys.cpp -- Task 2: RSA Key Management (PEM & DER) with CLI Menu
#include "rsa_key.h"

static int g_failures = 0;

[[maybe_unused]] static void check(const char* name, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

// Educational RSA parameter calculation
static int drawPrime(BIGNUM* prime, BIGNUM* primeMinus1, const BIGNUM* e, int bits, BN_CTX* ctx) {
    BIGNUM* g = BN_new();
    NOTNULL_KEY(g);
    int draws = 0;
    do {
        ++draws;
        OK1_KEY(BN_generate_prime_ex2(prime, bits, 0, nullptr, nullptr, nullptr, ctx));
        NOTNULL_KEY(BN_copy(primeMinus1, prime));
        OK1_KEY(BN_sub_word(primeMinus1, 1));
        OK1_KEY(BN_gcd(g, e, primeMinus1, ctx));
    } while (!BN_is_one(g));
    BN_free(g);
    return draws;
}

static void part1EducationalRsa(int bits) {
    std::printf("== Part 1: Educational RSA Parameters (%d-bit modulus) ==\n", bits);
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL_KEY(ctx);
    BIGNUM *e = BN_new(), *p = BN_new(), *q = BN_new(), *pm1 = BN_new(), *qm1 = BN_new();
    BIGNUM *g = BN_new(), *n = BN_new(), *phi = BN_new(), *lambda = BN_new();
    OK1_KEY(BN_set_word(e, 65537));

    int attempts = drawPrime(p, pm1, e, bits / 2, ctx);
    do { attempts += drawPrime(q, qm1, e, bits / 2, ctx); } while (BN_cmp(p, q) == 0);
    std::printf("  primes found after %d draw(s)\n", attempts);

    OK1_KEY(BN_mul(n, p, q, ctx));
    OK1_KEY(BN_mul(phi, pm1, qm1, ctx));
    OK1_KEY(BN_gcd(g, pm1, qm1, ctx));
    OK1_KEY(BN_div(lambda, nullptr, phi, g, ctx));

    BIGNUM* dPhi = BN_mod_inverse(nullptr, e, phi, ctx);
    BIGNUM* dLam = BN_mod_inverse(nullptr, e, lambda, ctx);
    NOTNULL_KEY(dPhi); NOTNULL_KEY(dLam);

    BIGNUM *dP = BN_new(), *dQ = BN_new(), *qInv = BN_mod_inverse(nullptr, q, p, ctx);
    OK1_KEY(BN_nnmod(dP, dLam, pm1, ctx));
    OK1_KEY(BN_nnmod(dQ, dLam, qm1, ctx));

    print_bn_bits("n", n);
    print_bn_dec("e", e);
    print_bn_bits("d (mod phi)", dPhi);
    print_bn_bits("d (mod lambda)", dLam);

    BIGNUM* t = BN_new();
    OK1_KEY(BN_mod_mul(t, e, dPhi, phi, ctx)); check("e * d_phi = 1 (mod phi)", BN_is_one(t));
    OK1_KEY(BN_mod_mul(t, e, dLam, lambda, ctx)); check("e * d_lambda = 1 (mod lambda)", BN_is_one(t));

    bool allOk = true;
    BIGNUM *m = BN_new(), *c = BN_new(), *r = BN_new(), *m1 = BN_new(), *m2 = BN_new(), *h = BN_new();
    for (int i = 0; i < 20; ++i) {
        OK1_KEY(BN_rand_range(m, n));
        OK1_KEY(BN_mod_exp(c, m, e, n, ctx));
        OK1_KEY(BN_mod_exp(r, c, dPhi, n, ctx)); allOk &= (BN_cmp(r, m) == 0);
        OK1_KEY(BN_mod_exp(r, c, dLam, n, ctx)); allOk &= (BN_cmp(r, m) == 0);
        OK1_KEY(BN_mod_exp(m1, c, dP, p, ctx));
        OK1_KEY(BN_mod_exp(m2, c, dQ, q, ctx));
        OK1_KEY(BN_mod_sub(h, m1, m2, p, ctx));
        OK1_KEY(BN_mod_mul(h, qInv, h, p, ctx));
        OK1_KEY(BN_mul(r, h, q, ctx));
        OK1_KEY(BN_add(r, r, m2));
        allOk &= (BN_cmp(r, m) == 0);
    }
    check("20 random messages decrypt with d_phi, d_lambda and CRT", allOk);

    for (BIGNUM* x : {e, p, q, pm1, qm1, g, n, phi, lambda, dPhi, dLam, dP, dQ, qInv, t, m, c, r, m1, m2, h})
        BN_clear_free(x);
    BN_CTX_free(ctx);
    std::printf("\n");
}

static EVP_PKEY* part2KeyFiles() {
    std::printf("== Part 2: Real RSA KeyGen (3072 bits) & PEM/DER File I/O ==\n");
    EVP_PKEY* key = generate_rsa_key(3072);
    NOTNULL_KEY(key);
    std::printf("  generated RSA-%d key pair\n", EVP_PKEY_get_bits(key));
    export_key_files(key);

    EVP_PKEY* privPem = load_key_from_file("private.pem", true, true);
    EVP_PKEY* privDer = load_key_from_file("private.der", true, false);
    EVP_PKEY* pubPem  = load_key_from_file("public.pem", false, true);
    EVP_PKEY* pubDer  = load_key_from_file("public.der", false, false);

    check("private.pem matches public.pem", EVP_PKEY_eq(privPem, pubPem) == 1);
    check("private.der matches public.der", EVP_PKEY_eq(privDer, pubDer) == 1);
    check("private.pem matches public.der", EVP_PKEY_eq(privPem, pubDer) == 1);
    check("private.der matches public.pem", EVP_PKEY_eq(privDer, pubPem) == 1);

    EVP_PKEY* other = generate_rsa_key(2048);
    check("different key does NOT match", EVP_PKEY_eq(other, pubPem) != 1);
    ERR_clear_error();

    Bytes id1 = compute_key_id(pubPem), id2 = compute_key_id(pubDer);
    print_hex("Key ID (PEM)", id1.data(), id1.size(), 32);
    check("Key ID matches 100% between PEM and DER", id1 == id2);

    for (EVP_PKEY* k : {privPem, privDer, pubPem, pubDer, other}) EVP_PKEY_free(k);
    std::printf("\n");
    return key;
}

static void part3InsideKey(EVP_PKEY* key) {
    std::printf("== Part 3: Inside OpenSSL Key - Parameters & Exponent Analysis ==\n");
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n = get_bn_param(key, OSSL_PKEY_PARAM_RSA_N);
    BIGNUM* e = get_bn_param(key, OSSL_PKEY_PARAM_RSA_E);
    BIGNUM* d = get_bn_param(key, OSSL_PKEY_PARAM_RSA_D);
    BIGNUM* p = get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1);
    BIGNUM* q = get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2);

    print_bn_bits("n", n);
    print_bn_dec("e", e);

    BIGNUM *pq = BN_new(), *pm1 = BN_dup(p), *qm1 = BN_dup(q), *phi = BN_new(), *g = BN_new(), *lambda = BN_new();
    OK1_KEY(BN_mul(pq, p, q, ctx)); check("n == p * q", BN_cmp(pq, n) == 0);

    OK1_KEY(BN_sub_word(pm1, 1));
    OK1_KEY(BN_sub_word(qm1, 1));
    OK1_KEY(BN_mul(phi, pm1, qm1, ctx));
    OK1_KEY(BN_gcd(g, pm1, qm1, ctx));
    OK1_KEY(BN_div(lambda, nullptr, phi, g, ctx));

    BIGNUM* dLam = BN_mod_inverse(nullptr, e, lambda, ctx);
    BIGNUM* dPhi = BN_mod_inverse(nullptr, e, phi, ctx);
    check("OpenSSL's d == e^-1 mod lambda(n)", BN_cmp(d, dLam) == 0);
    std::printf("  e^-1 mod phi(n) equals d this time? %s\n", BN_cmp(d, dPhi) == 0 ? "yes" : "no");

    for (BIGNUM* x : {n, e, d, p, q, pq, pm1, qm1, phi, g, lambda, dLam, dPhi})
        BN_clear_free(x);
    BN_CTX_free(ctx);
}

// Interactive CLI Menu for Task B
void print_menu(EVP_PKEY *pkey) {
    std::cout << "\n============================================================\n";
    std::cout << "               OpenSSL RSA CLI Tool (Task B)\n";
    std::cout << "============================================================\n";
    if (pkey) {
        std::cout << "Current key: RSA " << EVP_PKEY_get_bits(pkey) << "-bit ("
                  << (is_private_key(pkey) ? "private" : "public") << ")\n";
    } else {
        std::cout << "Current key: none\n";
    }
    std::cout << "============================================================\n";
    std::cout << "1. Generate a new RSA key pair (2048/3072 bit)\n";
    std::cout << "2. Export key to PEM file (private.pem / public.pem)\n";
    std::cout << "3. Export key to DER file (private.der / public.der)\n";
    std::cout << "4. Import key from file (Auto detect PEM/DER)\n";
    std::cout << "5. Show key information (n, e, d, p, q, dP, dQ, qInv)\n";
    std::cout << "6. Print key in PEM format to screen\n";
    std::cout << "0. Exit\n";
    std::cout << "Choose option: ";
}

static void runMenu() {
    EVP_PKEY* pkey = nullptr;
    int choice = -1;

    while (true) {
        print_menu(pkey);
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::string discard;
            std::cin >> discard;
            std::cout << "Invalid input!\n";
            continue;
        }

        if (choice == 0) {
            std::cout << "\nExiting program...\n";
            if (pkey) EVP_PKEY_free(pkey);
            break;
        }

        if (choice == 1) {
            std::cout << "Enter key size (2048 or 3072, default 3072): ";
            int bits = 3072;
            std::cin >> bits;
            if (bits != 2048 && bits != 3072) bits = 3072;
            std::cout << "Generating RSA " << bits << "-bit key pair, please wait...\n";
            EVP_PKEY* newKey = generate_rsa_key(bits);
            if (newKey) {
                if (pkey) EVP_PKEY_free(pkey);
                pkey = newKey;
                std::cout << "Generated new RSA " << bits << "-bit key pair successfully!\n";
            }
        } else if (choice == 2) {
            if (!pkey) {
                std::cout << "Error: No key loaded!\n";
            } else {
                if (is_private_key(pkey)) {
                    BIO* b = BIO_new_file("private.pem", "wb");
                    if (b) { PEM_write_bio_PrivateKey(b, pkey, nullptr, nullptr, 0, nullptr, nullptr); BIO_free(b); }
                    std::cout << "  - wrote private.pem (PKCS#8 PEM)\n";
                }
                BIO* b = BIO_new_file("public.pem", "wb");
                if (b) { PEM_write_bio_PUBKEY(b, pkey); BIO_free(b); }
                std::cout << "  - wrote public.pem (SubjectPublicKeyInfo PEM)\n";
                std::cout << "Exported key to PEM file(s) successfully!\n";
            }
        } else if (choice == 3) {
            if (!pkey) {
                std::cout << "Error: No key loaded!\n";
            } else {
                if (is_private_key(pkey)) {
                    BIO* b = BIO_new_file("private.der", "wb");
                    if (b) { i2d_PKCS8PrivateKey_bio(b, pkey, nullptr, nullptr, 0, nullptr, nullptr); BIO_free(b); }
                    std::cout << "  - wrote private.der (PKCS#8 DER)\n";
                }
                BIO* b = BIO_new_file("public.der", "wb");
                if (b) { i2d_PUBKEY_bio(b, pkey); BIO_free(b); }
                std::cout << "  - wrote public.der (SubjectPublicKeyInfo DER)\n";
                std::cout << "Exported key to DER file(s) successfully!\n";
            }
        } else if (choice == 4) {
            std::cout << "Enter file path to import: ";
            std::string path;
            std::cin >> path;
            EVP_PKEY* loaded = load_key_auto(path.c_str());
            if (loaded) {
                if (pkey) EVP_PKEY_free(pkey);
                pkey = loaded;
                std::cout << "Imported key successfully from " << path << "!\n";
            } else {
                std::cout << "Error: Failed to import key from " << path << "!\n";
            }
        } else if (choice == 5) {
            print_key_info(pkey);
        } else if (choice == 6) {
            print_key_pem_stdout(pkey);
        } else {
            std::cout << "Invalid option! Please choose again.\n";
        }
    }
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--test") == 0) {
        part1EducationalRsa(512);
        EVP_PKEY* key = part2KeyFiles();
        part3InsideKey(key);
        EVP_PKEY_free(key);
        std::printf("\n%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
        return g_failures ? 1 : 0;
    }

    // Default: run interactive CLI menu
    runMenu();
    return 0;
}
