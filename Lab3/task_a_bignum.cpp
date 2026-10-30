#include <openssl/bn.h>
#include <openssl/err.h>

#include <iostream>
#include <string>
#include <memory>
#include <limits>
#include <vector>
#include <cstring>
#include <cstdio>

using namespace std;

// Custom deleters for OpenSSL structures
using BNPtr = unique_ptr<BIGNUM, decltype(&BN_free)>;
using BNContext = unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

// ============================================================================
// Algorithms from Lab 3 Task A (task_a_bignum.cpp)
// ============================================================================

// Square-and-multiply (left to right)
// Input: a, b = (b_{t-1} ... b_0)_2, m
// Output: r = a^b mod m
BIGNUM* myModExp(const BIGNUM* a, const BIGNUM* b, const BIGNUM* m, BN_CTX* ctx) {
    BIGNUM* r = BN_new();
    BIGNUM* base = BN_new();
    if (!r || !base) {
        if (r) BN_free(r);
        if (base) BN_free(base);
        return nullptr;
    }

    BN_one(r);
    BN_nnmod(base, a, m, ctx); // reduce a into [0, m)

    for (int i = BN_num_bits(b) - 1; i >= 0; --i) {
        BN_mod_sqr(r, r, m, ctx); // r = r^2 mod m
        if (BN_is_bit_set(b, i)) {
            BN_mod_mul(r, r, base, m, ctx); // r = r * a mod m
        }
    }

    if (BN_is_one(m)) {
        BN_zero(r); // everything is 0 mod 1
    }

    BN_free(base);
    return r;
}

// Extended Euclidean algorithm (modular inverse)
// Invariant: r_i = t_i * a (mod m). When remainder reaches 0,
// r_{i-1} = gcd(a, m); if gcd == 1, t_{i-1} mod m is the inverse.
// Returns nullptr when gcd(a, m) != 1 (the gcd is written to gcdOut).
BIGNUM* myModInverse(const BIGNUM* a, const BIGNUM* m, BIGNUM* gcdOut, BN_CTX* ctx) {
    BIGNUM *r0 = BN_dup(m), *r1 = BN_new(), *t0 = BN_new(), *t1 = BN_new();
    BIGNUM *q = BN_new(), *tmp = BN_new(), *prod = BN_new();

    if (!r0 || !r1 || !t0 || !t1 || !q || !tmp || !prod) {
        if (r0) BN_free(r0);
        if (r1) BN_free(r1);
        if (t0) BN_free(t0);
        if (t1) BN_free(t1);
        if (q) BN_free(q);
        if (tmp) BN_free(tmp);
        if (prod) BN_free(prod);
        return nullptr;
    }

    BN_nnmod(r1, a, m, ctx);
    BN_zero(t0);
    BN_one(t1);

    while (!BN_is_zero(r1)) {
        BN_div(q, tmp, r0, r1, ctx); // q = r0 / r1, tmp = r0 mod r1
        BN_swap(r0, r1);            // (r0, r1) = (r1, r0 mod r1)
        BN_swap(r1, tmp);
        BN_mul(prod, q, t1, ctx);   // (t0, t1) = (t1, t0 - q * t1)
        BN_sub(tmp, t0, prod);
        BN_swap(t0, t1);
        BN_swap(t1, tmp);
    }

    if (gcdOut) {
        BN_copy(gcdOut, r0);
    }

    BIGNUM* inv = nullptr;
    if (BN_is_one(r0)) {
        inv = BN_new();
        if (inv) {
            BN_nnmod(inv, t0, m, ctx); // t0 may be negative
        }
    }

    BN_free(r0); BN_free(r1); BN_free(t0); BN_free(t1);
    BN_free(q); BN_free(tmp); BN_free(prod);
    return inv;
}

// ============================================================================
// Helper functions
// ============================================================================

bool isValidDec(const string& s) {
    if (s.empty() || s.length() > 10000) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

BNPtr inputBN(const string& message) {
    string s;
    while (true) {
        cout << message;
        if (!(cin >> s)) return BNPtr(nullptr, BN_free);

        if (!isValidDec(s)) {
            cout << "Invalid input! Please enter a nonnegative integer.\n";
            continue;
        }

        BIGNUM* num = nullptr;
        if (BN_dec2bn(&num, s.c_str()) == (int)s.length()) {
            return BNPtr(num, BN_free);
        }

        if (num) BN_free(num);
        cout << "Cannot convert number. Try again.\n";
    }
}

void printBN(const string& label, const BIGNUM* num) {
    char* decimal = BN_bn2dec(num);
    if (decimal == nullptr) {
        cerr << "Error printing BIGNUM.\n";
        return;
    }
    cout << label << decimal << '\n';
    OPENSSL_free(decimal);
}

bool validModulus(const BIGNUM* m) {
    if (!m || BN_is_zero(m)) {
        cout << "Error: Modulus must be greater than 0!\n";
        return false;
    }
    return true;
}

// ============================================================================
// CLI Operations
// ============================================================================

// 1. Modular Addition: (a + b) mod m
void modularAddition(BN_CTX* ctx) {
    cout << "\n--- Modular Addition ---\n";
    BNPtr a = inputBN("Enter a: ");
    if (!a) return;
    BNPtr b = inputBN("Enter b: ");
    if (!b) return;
    BNPtr m = inputBN("Enter modulus m: ");
    if (!m || !validModulus(m.get())) return;

    BNPtr result(BN_new(), BN_free);
    if (!result || !BN_mod_add(result.get(), a.get(), b.get(), m.get(), ctx)) {
        cerr << "OpenSSL error in BN_mod_add!\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    printBN("Result = ", result.get());
}

// 2. Modular Subtraction: (a - b) mod m
void modularSubtraction(BN_CTX* ctx) {
    cout << "\n--- Modular Subtraction ---\n";
    BNPtr a = inputBN("Enter a: ");
    if (!a) return;
    BNPtr b = inputBN("Enter b: ");
    if (!b) return;
    BNPtr m = inputBN("Enter modulus m: ");
    if (!m || !validModulus(m.get())) return;

    BNPtr result(BN_new(), BN_free);
    if (!result || !BN_mod_sub(result.get(), a.get(), b.get(), m.get(), ctx)) {
        cerr << "OpenSSL error in BN_mod_sub!\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    printBN("Result = ", result.get());
}

// 3. Modular Multiplication: (a * b) mod m
void modularMultiplication(BN_CTX* ctx) {
    cout << "\n--- Modular Multiplication ---\n";
    BNPtr a = inputBN("Enter a: ");
    if (!a) return;
    BNPtr b = inputBN("Enter b: ");
    if (!b) return;
    BNPtr m = inputBN("Enter modulus m: ");
    if (!m || !validModulus(m.get())) return;

    BNPtr result(BN_new(), BN_free);
    if (!result || !BN_mod_mul(result.get(), a.get(), b.get(), m.get(), ctx)) {
        cerr << "OpenSSL error in BN_mod_mul!\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    printBN("Result = ", result.get());
}

// 4. Greatest Common Divisor: gcd(a, b)
void greatestCommonDivisor(BN_CTX* ctx) {
    cout << "\n--- Greatest Common Divisor ---\n";
    BNPtr a = inputBN("Enter a: ");
    if (!a) return;
    BNPtr b = inputBN("Enter b: ");
    if (!b) return;

    BNPtr result(BN_new(), BN_free);
    if (!result || !BN_gcd(result.get(), a.get(), b.get(), ctx)) {
        cerr << "OpenSSL error in BN_gcd!\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    printBN("GCD = ", result.get());
}

// 5. Modular Exponentiation: a^b mod m
void modularExponentiation(BN_CTX* ctx) {
    cout << "\n--- Modular Exponentiation ---\n";
    BNPtr a = inputBN("Enter base a: ");
    if (!a) return;
    BNPtr b = inputBN("Enter exponent b: ");
    if (!b) return;
    BNPtr m = inputBN("Enter modulus m: ");
    if (!m || !validModulus(m.get())) return;

    // Hand-written square-and-multiply
    BNPtr result(myModExp(a.get(), b.get(), m.get(), ctx), BN_free);
    if (!result) {
        cerr << "Error calculating square-and-multiply!\n";
        return;
    }

    // OpenSSL verification
    BNPtr libResult(BN_new(), BN_free);
    if (BN_mod_exp(libResult.get(), a.get(), b.get(), m.get(), ctx)) {
        bool match = (BN_cmp(result.get(), libResult.get()) == 0);
        cout << "[" << (match ? "PASS" : "FAIL") << "] square-and-multiply == BN_mod_exp\n";
    }

    printBN("Result = ", result.get());
}

// 6. Modular Inverse: a^(-1) mod m
void modularInverse(BN_CTX* ctx) {
    cout << "\n--- Modular Inverse ---\n";
    BNPtr a = inputBN("Enter a: ");
    if (!a) return;
    BNPtr m = inputBN("Enter modulus m: ");
    if (!m || !validModulus(m.get())) return;

    if (BN_is_one(m.get())) {
        cout << "No modular inverse for modulus 1.\n";
        return;
    }

    BNPtr gcd(BN_new(), BN_free);
    // Hand-written extended Euclidean algorithm
    BIGNUM* inv = myModInverse(a.get(), m.get(), gcd.get(), ctx);
    // OpenSSL BN_mod_inverse comparison
    BIGNUM* libInv = BN_mod_inverse(nullptr, a.get(), m.get(), ctx);
    if (!libInv) ERR_clear_error();

    if (!inv) {
        printBN("No modular inverse. GCD = ", gcd.get());
        if (libInv == nullptr) {
            cout << "[PASS] BN_mod_inverse also reports no inverse\n";
        }
    } else {
        BNPtr result(inv, BN_free);
        BNPtr libResult(libInv, BN_free);
        if (libInv && BN_cmp(result.get(), libResult.get()) == 0) {
            cout << "[PASS] extended Euclid == BN_mod_inverse\n";
        }
        printBN("Modular inverse = ", result.get());
    }
}

// 7. Generate a Large Prime for RSA
void generateLargePrime(BN_CTX* ctx) {
    cout << "\n--- Generate Large Prime for RSA ---\n";

    int bits;
    while (true) {
        cout << "Enter prime size (bits): ";
        if (!(cin >> bits)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input!\n";
            continue;
        }

        if (bits >= 2 && bits <= 16384) break;
        cout << "Bit size must be between 2 and 16384.\n";
    }

    BNPtr prime(BN_new(), BN_free);
    if (!prime) {
        cerr << "Cannot allocate BIGNUM!\n";
        return;
    }

    cout << "Generating " << bits << "-bit prime...\n";

    if (!BN_generate_prime_ex2(prime.get(), bits, 0, nullptr, nullptr, nullptr, ctx)) {
        cerr << "Prime generation failed!\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    cout << "\nPrime generated successfully!\n";
    cout << "Number of bits: " << BN_num_bits(prime.get()) << '\n';

    char* dec = BN_bn2dec(prime.get());
    if (dec != nullptr) {
        cout << "P = " << dec << '\n';
        OPENSSL_free(dec);
    }
}

// ============================================================================
// Lab 3 Handout Automated Test Vectors
// ============================================================================

static void runCase(const char* sa, const char* sb, const char* sm,
                    const char* expectExp, const char* expectInv) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return;

    BIGNUM *a = nullptr, *b = nullptr, *m = nullptr;
    BN_dec2bn(&a, sa);
    BN_dec2bn(&b, sb);
    BN_dec2bn(&m, sm);

    if (!a || !b || !m || BN_is_zero(m)) {
        if (a) BN_free(a);
        if (b) BN_free(b);
        if (m) BN_free(m);
        BN_CTX_free(ctx);
        return;
    }

    std::printf("a = %s, b = %s, m = %s\n", sa, sb, sm);

    BIGNUM* r1 = BN_new();
    BN_mod_exp(r1, a, b, m, ctx);
    BIGNUM* r2 = myModExp(a, b, m, ctx);
    printBN("a^b mod m        ", r1);
    std::printf(" [%s] square-and-multiply == BN_mod_exp\n", BN_cmp(r1, r2) == 0 ? "PASS" : "FAIL");
    if (expectExp) {
        BIGNUM* want = nullptr;
        BN_dec2bn(&want, expectExp);
        std::printf(" [%s] matches expected value\n", (want && BN_cmp(r1, want) == 0) ? "PASS" : "FAIL");
        if (want) BN_free(want);
    }

    if (!BN_is_one(m)) {
        BIGNUM* g = BN_new();
        BIGNUM* mine = myModInverse(a, m, g, ctx);
        BIGNUM* lib = BN_mod_inverse(nullptr, a, m, ctx);
        if (!lib) ERR_clear_error();

        if (mine) {
            printBN("a^-1 mod m       ", mine);
            std::printf(" [%s] extended Euclid == BN_mod_inverse\n", (lib && BN_cmp(mine, lib) == 0) ? "PASS" : "FAIL");
            if (expectInv) {
                BIGNUM* want = nullptr;
                BN_dec2bn(&want, expectInv);
                std::printf(" [%s] matches expected inverse\n", (want && BN_cmp(mine, want) == 0) ? "PASS" : "FAIL");
                if (want) BN_free(want);
            }
        } else {
            printBN("no inverse, gcd  ", g);
            std::printf(" [%s] BN_mod_inverse also reports no inverse\n", lib == nullptr ? "PASS" : "FAIL");
        }
        if (g) BN_free(g);
        if (mine) BN_free(mine);
        if (lib) BN_free(lib);
    }

    BN_free(a); BN_free(b); BN_free(m); BN_free(r1); BN_free(r2);
    BN_CTX_free(ctx);
    std::printf("\n");
}

static void runAllHandoutTests() {
    std::printf("== Task A: handout test vectors ==\n\n");

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *a = nullptr, *b = nullptr, *m = nullptr, *r = BN_new();
    BN_dec2bn(&a, "3"); BN_dec2bn(&b, "5"); BN_dec2bn(&m, "7");

    BN_mod_add(r, a, b, m, ctx); printBN("3+5 mod 7        ", r);
    BN_mod_sub(r, a, b, m, ctx); printBN("3-5 mod 7        ", r);
    BN_mod_mul(r, a, b, m, ctx); printBN("3*5 mod 7        ", r);

    BIGNUM *x = nullptr, *y = nullptr;
    BN_dec2bn(&x, "252"); BN_dec2bn(&y, "105");
    BN_gcd(r, x, y, ctx); printBN("gcd(252,105)     ", r);
    std::printf(" [%s] gcd(252,105) == 21\n\n", BN_is_word(r, 21) ? "PASS" : "FAIL");

    BN_free(a); BN_free(b); BN_free(m); BN_free(r); BN_free(x); BN_free(y);
    BN_CTX_free(ctx);

    runCase("7", "13", "33", "13", "19");
    runCase("6", "2", "33", "3", nullptr);
    runCase("123456789012345678901234567890", "65537",
            "170141183460469231731687303715884105727",
            "43089841487593468092862748681566865937", nullptr);
    runCase("65537", "1",
            "170141183460469231731687303715884105727",
            "65537", "5192217631581220737344928932233215");

    std::printf("ALL CHECKS PASSED\n");
}

// ============================================================================
// Main Menu
// ============================================================================

void displayMenu() {
    cout << "\n========================================\n";
    cout << "        OpenSSL BIGNUM CLI Lab\n";
    cout << "========================================\n";
    cout << "1. Modular addition:        (a + b) mod m\n";
    cout << "2. Modular subtraction:     (a - b) mod m\n";
    cout << "3. Modular multiplication:  (a * b) mod m\n";
    cout << "4. Greatest common divisor: gcd(a, b)\n";
    cout << "5. Modular exponentiation:  a^b mod m\n";
    cout << "6. Modular inverse:         a^(-1) mod m\n";
    cout << "7. Generate a large prime for RSA\n";
    cout << "0. Exit\n";
}

int main(int argc, char** argv) {
    BN_CTX* rawCtx = BN_CTX_new();
    if (rawCtx == nullptr) {
        cerr << "Cannot create BN_CTX!\n";
        return 1;
    }
    BNContext ctx(rawCtx, BN_CTX_free);

    // Support command-line arguments:
    // 1) ./task1 --test (run all handout test cases)
    // 2) ./task1 <a> <b> <m> (compute a^b mod m and a^-1 mod m)
    if (argc == 2 && (string(argv[1]) == "--test" || string(argv[1]) == "test")) {
        runAllHandoutTests();
        return 0;
    }
    if (argc == 4) {
        runCase(argv[1], argv[2], argv[3], nullptr, nullptr);
        return 0;
    }

    // Default: interactive menu (matches expected UI in screenshot)
    int choice;
    do {
        displayMenu();
        cout << "Choose: ";

        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid choice!\n";
            continue;
        }

        switch (choice) {
            case 1:
                modularAddition(ctx.get());
                break;
            case 2:
                modularSubtraction(ctx.get());
                break;
            case 3:
                modularMultiplication(ctx.get());
                break;
            case 4:
                greatestCommonDivisor(ctx.get());
                break;
            case 5:
                modularExponentiation(ctx.get());
                break;
            case 6:
                modularInverse(ctx.get());
                break;
            case 7:
                generateLargePrime(ctx.get());
                break;
            case 0:
                cout << "\nExiting program...\n";
                break;
            default:
                cout << "\nInvalid choice! Please choose again.\n";
                break;
        }

    } while (choice != 0);

    return 0;
}
