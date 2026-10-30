// task_a_bignum.cpp -- Lab 3, Task A: Modular Arithmetic with BIGNUM
// Algorithms: Square-and-multiply, Extended Euclidean, OpenSSL BIGNUM CLI

#include <openssl/bn.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// ===== Minimal helpers (identical in every task file) =====================
static int g_failures = 0;

[[noreturn]] static void die(const char* what) {
    std::fprintf(stderr, "FAILED: %s\n", what);
    ERR_print_errors_fp(stderr); // OpenSSL's reason strings
    std::exit(1);
}

#define OK1(call)     do { if ((call) != 1) die(#call); } while (0)
#define NOTNULL(ptr)  do { if ((ptr) == nullptr) die(#ptr " is NULL"); } while (0)

[[maybe_unused]] static void printBn(const char* label, const BIGNUM* x) {
    char* s = BN_bn2dec(x);
    NOTNULL(s);
    std::printf("  %-16s%s\n", label, s);
    OPENSSL_free(s);
}

[[maybe_unused]] static void check(const char* name, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}
// ==========================================================================

// Parse a nonnegative decimal integer strictly.
static BIGNUM* parseDec(const char* s) {
    size_t len = std::strlen(s);
    if (len == 0 || len > 10000) die("number must have 1..10000 digits");
    for (size_t i = 0; i < len; ++i) {
        if (s[i] < '0' || s[i] > '9') die("not a nonnegative decimal integer");
    }
    BIGNUM* x = nullptr;
    if (BN_dec2bn(&x, s) != static_cast<int>(len)) die("BN_dec2bn");
    return x;
}

// Square-and-multiply (left to right): r = a^b mod m
static BIGNUM* myModExp(const BIGNUM* a, const BIGNUM* b, const BIGNUM* m, BN_CTX* ctx) {
    BIGNUM* r = BN_new();
    BIGNUM* base = BN_new();
    NOTNULL(r); NOTNULL(base);
    OK1(BN_one(r));
    OK1(BN_nnmod(base, a, m, ctx)); // reduce a into [0, m)
    for (int i = BN_num_bits(b) - 1; i >= 0; --i) {
        OK1(BN_mod_sqr(r, r, m, ctx)); // r = r^2 mod m
        if (BN_is_bit_set(b, i)) {
            OK1(BN_mod_mul(r, r, base, m, ctx)); // r = r*a mod m
        }
    }
    if (BN_is_one(m)) BN_zero(r);
    BN_free(base);
    return r;
}

// Extended Euclidean algorithm for a^-1 mod m. Returns NULL if gcd != 1.
static BIGNUM* myModInverse(const BIGNUM* a, const BIGNUM* m, BIGNUM* gcdOut, BN_CTX* ctx) {
    BIGNUM *r0 = BN_dup(m), *r1 = BN_new(), *t0 = BN_new(), *t1 = BN_new();
    BIGNUM *q = BN_new(), *tmp = BN_new(), *prod = BN_new();
    NOTNULL(r0); NOTNULL(r1); NOTNULL(t0); NOTNULL(t1);
    NOTNULL(q); NOTNULL(tmp); NOTNULL(prod);
    OK1(BN_nnmod(r1, a, m, ctx));
    BN_zero(t0);
    OK1(BN_one(t1));

    while (!BN_is_zero(r1)) {
        OK1(BN_div(q, tmp, r0, r1, ctx)); // q = r0 / r1, tmp = r0 mod r1
        BN_swap(r0, r1);
        BN_swap(r1, tmp);
        OK1(BN_mul(prod, q, t1, ctx));    // (t0, t1) = (t1, t0 - q*t1)
        OK1(BN_sub(tmp, t0, prod));
        BN_swap(t0, t1);
        BN_swap(t1, tmp);
    }
    NOTNULL(BN_copy(gcdOut, r0));
    BIGNUM* inv = nullptr;
    if (BN_is_one(r0)) {
        inv = BN_new();
        NOTNULL(inv);
        OK1(BN_nnmod(inv, t0, m, ctx)); // t0 may be negative
    }
    BN_free(r0); BN_free(r1); BN_free(t0); BN_free(t1);
    BN_free(q); BN_free(tmp); BN_free(prod);
    return inv;
}

// Helper to read a BIGNUM from stdin
static BIGNUM* readBn(const char* prompt) {
    char buf[10240];
    while (true) {
        std::printf("%s", prompt);
        if (std::scanf("%10239s", buf) != 1) return nullptr;
        bool ok = true;
        size_t len = std::strlen(buf);
        for (size_t i = 0; i < len; ++i) {
            if (buf[i] < '0' || buf[i] > '9') { ok = false; break; }
        }
        if (!ok || len == 0) {
            std::printf("Invalid input! Please enter a nonnegative integer.\n");
            continue;
        }
        BIGNUM* x = nullptr;
        if (BN_dec2bn(&x, buf) == static_cast<int>(len)) return x;
        if (x) BN_free(x);
        std::printf("Cannot convert number. Try again.\n");
    }
}

// Demo basic operations
static void demoOtherOps() {
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(ctx);
    BIGNUM *a = parseDec("3"), *b = parseDec("5"), *m = parseDec("7"), *r = BN_new();
    NOTNULL(r);
    OK1(BN_mod_add(r, a, b, m, ctx)); printBn("3+5 mod 7", r);
    OK1(BN_mod_sub(r, a, b, m, ctx)); printBn("3-5 mod 7", r);
    OK1(BN_mod_mul(r, a, b, m, ctx)); printBn("3*5 mod 7", r);
    BIGNUM *x = parseDec("252"), *y = parseDec("105");
    OK1(BN_gcd(r, x, y, ctx)); printBn("gcd(252,105)", r);
    check("gcd(252,105) == 21", BN_is_word(r, 21));
    BN_free(a); BN_free(b); BN_free(m); BN_free(r); BN_free(x); BN_free(y);
    BN_CTX_free(ctx);
    std::printf("\n");
}

// Run test vector
static void runCase(const char* sa, const char* sb, const char* sm,
                    const char* expectExp, const char* expectInv) {
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(ctx);
    BIGNUM *a = parseDec(sa), *b = parseDec(sb), *m = parseDec(sm);
    if (BN_is_zero(m)) die("modulus must be > 0");
    std::printf("a = %s, b = %s, m = %s\n", sa, sb, sm);

    BIGNUM* r1 = BN_new();
    NOTNULL(r1);
    OK1(BN_mod_exp(r1, a, b, m, ctx));
    BIGNUM* r2 = myModExp(a, b, m, ctx);
    printBn("a^b mod m", r1);
    check("square-and-multiply == BN_mod_exp", BN_cmp(r1, r2) == 0);
    if (expectExp) {
        BIGNUM* want = parseDec(expectExp);
        check("matches expected value", BN_cmp(r1, want) == 0);
        BN_free(want);
    }

    if (!BN_is_one(m)) {
        BIGNUM* g = BN_new();
        NOTNULL(g);
        BIGNUM* mine = myModInverse(a, m, g, ctx);
        BIGNUM* lib = BN_mod_inverse(nullptr, a, m, ctx);
        if (!lib) ERR_clear_error();
        if (mine) {
            printBn("a^-1 mod m", mine);
            check("extended Euclid == BN_mod_inverse", lib && BN_cmp(mine, lib) == 0);
            if (expectInv) {
                BIGNUM* want = parseDec(expectInv);
                check("matches expected inverse", BN_cmp(mine, want) == 0);
                BN_free(want);
            }
        } else {
            printBn("no inverse, gcd", g);
            check("BN_mod_inverse also reports no inverse", lib == nullptr);
        }
        BN_free(g); BN_free(mine); BN_free(lib);
    }
    BN_free(a); BN_free(b); BN_free(m); BN_free(r1); BN_free(r2);
    BN_CTX_free(ctx);
    std::printf("\n");
}

// Display menu matching the lab image
static void displayMenu() {
    std::printf("\n========================================\n");
    std::printf("        OpenSSL BIGNUM CLI Lab\n");
    std::printf("========================================\n");
    std::printf("1. Modular addition:        (a + b) mod m\n");
    std::printf("2. Modular subtraction:     (a - b) mod m\n");
    std::printf("3. Modular multiplication:  (a * b) mod m\n");
    std::printf("4. Greatest common divisor: gcd(a, b)\n");
    std::printf("5. Modular exponentiation:  a^b mod m\n");
    std::printf("6. Modular inverse:         a^(-1) mod m\n");
    std::printf("7. Generate a large prime for RSA\n");
    std::printf("0. Exit\n");
}

static void runMenu(BN_CTX* ctx) {
    int choice = -1;
    BIGNUM* r = BN_new();
    NOTNULL(r);

    while (true) {
        displayMenu();
        std::printf("Choose: ");
        if (std::scanf("%d", &choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {}
            std::printf("Invalid choice!\n");
            continue;
        }
        if (choice == 0) {
            std::printf("\nExiting program...\n");
            break;
        }

        if (choice == 1) {
            std::printf("\n--- Modular Addition ---\n");
            BIGNUM *a = readBn("Enter a: "), *b = readBn("Enter b: "), *m = readBn("Enter modulus m: ");
            if (BN_is_zero(m)) { std::printf("Error: Modulus must be greater than 0!\n"); }
            else { OK1(BN_mod_add(r, a, b, m, ctx)); printBn("Result = ", r); }
            BN_free(a); BN_free(b); BN_free(m);
        } else if (choice == 2) {
            std::printf("\n--- Modular Subtraction ---\n");
            BIGNUM *a = readBn("Enter a: "), *b = readBn("Enter b: "), *m = readBn("Enter modulus m: ");
            if (BN_is_zero(m)) { std::printf("Error: Modulus must be greater than 0!\n"); }
            else { OK1(BN_mod_sub(r, a, b, m, ctx)); printBn("Result = ", r); }
            BN_free(a); BN_free(b); BN_free(m);
        } else if (choice == 3) {
            std::printf("\n--- Modular Multiplication ---\n");
            BIGNUM *a = readBn("Enter a: "), *b = readBn("Enter b: "), *m = readBn("Enter modulus m: ");
            if (BN_is_zero(m)) { std::printf("Error: Modulus must be greater than 0!\n"); }
            else { OK1(BN_mod_mul(r, a, b, m, ctx)); printBn("Result = ", r); }
            BN_free(a); BN_free(b); BN_free(m);
        } else if (choice == 4) {
            std::printf("\n--- Greatest Common Divisor ---\n");
            BIGNUM *a = readBn("Enter a: "), *b = readBn("Enter b: ");
            OK1(BN_gcd(r, a, b, ctx)); printBn("GCD = ", r);
            BN_free(a); BN_free(b);
        } else if (choice == 5) {
            std::printf("\n--- Modular Exponentiation ---\n");
            BIGNUM *a = readBn("Enter base a: "), *b = readBn("Enter exponent b: "), *m = readBn("Enter modulus m: ");
            if (BN_is_zero(m)) { std::printf("Error: Modulus must be greater than 0!\n"); }
            else {
                BIGNUM* r1 = myModExp(a, b, m, ctx);
                BIGNUM* r2 = BN_new();
                OK1(BN_mod_exp(r2, a, b, m, ctx));
                check("square-and-multiply == BN_mod_exp", BN_cmp(r1, r2) == 0);
                printBn("Result = ", r1);
                BN_free(r1); BN_free(r2);
            }
            BN_free(a); BN_free(b); BN_free(m);
        } else if (choice == 6) {
            std::printf("\n--- Modular Inverse ---\n");
            BIGNUM *a = readBn("Enter a: "), *m = readBn("Enter modulus m: ");
            if (BN_is_zero(m) || BN_is_one(m)) { std::printf("Error: Modulus must be greater than 1!\n"); }
            else {
                BIGNUM* g = BN_new();
                BIGNUM* inv = myModInverse(a, m, g, ctx);
                BIGNUM* lib = BN_mod_inverse(nullptr, a, m, ctx);
                if (!lib) ERR_clear_error();
                if (inv) {
                    check("extended Euclid == BN_mod_inverse", lib && BN_cmp(inv, lib) == 0);
                    printBn("Modular inverse = ", inv);
                    BN_free(inv);
                } else {
                    printBn("No modular inverse. GCD = ", g);
                }
                BN_free(g); if (lib) BN_free(lib);
            }
            BN_free(a); BN_free(m);
        } else if (choice == 7) {
            std::printf("\n--- Generate Large Prime for RSA ---\n");
            int bits = 0;
            std::printf("Enter prime size (bits): ");
            if (std::scanf("%d", &bits) == 1 && bits >= 2 && bits <= 16384) {
                std::printf("Generating %d-bit prime...\n", bits);
                BIGNUM* prime = BN_new();
                OK1(BN_generate_prime_ex2(prime, bits, 0, nullptr, nullptr, nullptr, ctx));
                std::printf("\nPrime generated successfully!\n");
                std::printf("Number of bits: %d\n", BN_num_bits(prime));
                char* dec = BN_bn2dec(prime);
                if (dec) {
                    std::printf("P = %s\n", dec);
                    OPENSSL_free(dec);
                }
                BN_free(prime);
            } else {
                std::printf("Bit size must be between 2 and 16384.\n");
            }
        } else {
            std::printf("\nInvalid choice! Please choose again.\n");
        }
    }
    BN_free(r);
}

int main(int argc, char** argv) {
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(ctx);

    // Chế độ test tự động từ dòng lệnh: ./task_a --test
    if (argc == 2 && std::strcmp(argv[1], "--test") == 0) {
        std::printf("== Task A: handout test vectors ==\n\n");
        demoOtherOps();
        runCase("7", "13", "33", "13", "19");
        runCase("6", "2", "33", "3", nullptr);
        runCase("123456789012345678901234567890", "65537",
                "170141183460469231731687303715884105727",
                "43089841487593468092862748681566865937", nullptr);
        runCase("65537", "1",
                "170141183460469231731687303715884105727",
                "65537", "5192217631581220737344928932233215");
        std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
        BN_CTX_free(ctx);
        return g_failures ? 1 : 0;
    }

    // Chế độ nhận tham số tùy ý: ./task_a <a> <b> <m>
    if (argc == 4) {
        runCase(argv[1], argv[2], argv[3], nullptr, nullptr);
        BN_CTX_free(ctx);
        return g_failures ? 1 : 0;
    }

    // Chế độ mặc định: Chạy menu tương tác CLI (như trong ảnh)
    runMenu(ctx);

    BN_CTX_free(ctx);
    return 0;
}
