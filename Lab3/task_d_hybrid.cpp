// task_d_hybrid.cpp -- Task 4: Hybrid File Encryption Test Runner & CLI
#include "hybrid_crypto.h"

static int g_failures = 0;

[[maybe_unused]] static void check(const char* name, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

static void runSelfTest() {
    std::printf("== Running Task D Hybrid Crypto Self-Test ==\n");
    g_failures = 0;

    std::printf("  generating 2 distinct RSA-2048 key pairs for testing...\n");
    EVP_PKEY* k1 = generate_rsa_key(2048);
    EVP_PKEY* k2 = generate_rsa_key(2048);
    NOTNULL_KEY(k1); NOTNULL_KEY(k2);

    const std::string msg = "Antigravity Lab 3 Hybrid Encryption AES-256-GCM + RSA-OAEP test vector.";
    Bytes pt(msg.begin(), msg.end());

    // 1. Round-trip test
    Bytes pkg1;
    bool okSeal1 = seal_package(k1, pt, pkg1);
    check("seal_package with RSA-2048 public key", okSeal1);

    Bytes dec1;
    bool okOpen1 = open_package(k1, pkg1, dec1);
    check("open_package recovers exact plaintext", okOpen1 && dec1 == pt);

    // 2. Randomness test (fresh AES key + nonce each time)
    Bytes pkg2;
    bool okSeal2 = seal_package(k1, pt, pkg2);
    check("seal_package produces non-deterministic output (pkg1 != pkg2)", okSeal2 && pkg1 != pkg2);

    Bytes dec2;
    bool okOpen2 = open_package(k1, pkg2, dec2);
    check("second package opens cleanly to same plaintext", okOpen2 && dec2 == pt);

    // 3. Tamper tests
    uint16_t klen = unpack_u16_be(&pkg1[8]);
    size_t header_len = 30 + klen;
    Bytes pkgBad, decBad;

    // 3.1 Tamper ciphertext
    pkgBad = pkg1;
    pkgBad[header_len + 2] ^= 0x40;
    check("tampered ciphertext rejected by GCM tag verification", !open_package(k1, pkgBad, decBad));

    // 3.2 Tamper tag
    pkgBad = pkg1;
    pkgBad.back() ^= 0x01;
    check("tampered GCM authentication tag rejected", !open_package(k1, pkgBad, decBad));

    // 3.3 Tamper nonce
    pkgBad = pkg1;
    pkgBad[10 + klen + 3] ^= 0x08;
    check("tampered nonce rejected by GCM authentication", !open_package(k1, pkgBad, decBad));

    // 3.4 Tamper wrapped key
    pkgBad = pkg1;
    pkgBad[10 + 5] ^= 0x55;
    check("tampered wrapped key rejected during OAEP unwrap", !open_package(k1, pkgBad, decBad));

    // 3.5 Tamper version header
    pkgBad = pkg1;
    pkgBad[4] = 0x02;
    check("invalid header version (0x02) rejected", !open_package(k1, pkgBad, decBad));

    // 3.6 Tamper reserved header bytes
    pkgBad = pkg1;
    pkgBad[6] = 0x01;
    check("non-zero reserved header bytes rejected", !open_package(k1, pkgBad, decBad));

    // 4. Wrong private key test
    check("package rejected when decrypted with different private key", !open_package(k2, pkg1, decBad));

    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    std::printf("\n%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
}

static void encryptFileCli() {
    std::string keyPath, inPath, outPath;
    std::cout << "Enter Public/Private Key path: "; std::cin >> keyPath;
    std::cout << "Enter Input File path: ";         std::cin >> inPath;
    std::cout << "Enter Output Package path (.l2pk): "; std::cin >> outPath;

    EVP_PKEY* key = load_key_auto(keyPath.c_str());
    if (!key) { std::cout << "Error: Could not load key from " << keyPath << "\n"; return; }

    Bytes pt;
    if (!read_file_bytes(inPath.c_str(), pt)) {
        std::cout << "Error: Could not read file " << inPath << "\n";
        EVP_PKEY_free(key);
        return;
    }

    Bytes pkg;
    if (!seal_package(key, pt, pkg) || !write_file_bytes(outPath.c_str(), pkg)) {
        std::cout << "Error: Failed to seal or write package!\n";
    } else {
        std::cout << "File encrypted successfully! (" << pt.size() << " bytes -> "
                  << pkg.size() << " bytes package written to " << outPath << ")\n";
    }
    EVP_PKEY_free(key);
}

static void decryptFileCli() {
    std::string keyPath, pkgPath, outPath;
    std::cout << "Enter Private Key path: "; std::cin >> keyPath;
    std::cout << "Enter Package File path (.l2pk): "; std::cin >> pkgPath;
    std::cout << "Enter Output File path: ";  std::cin >> outPath;

    EVP_PKEY* key = load_key_auto(keyPath.c_str());
    if (!key || !is_private_key(key)) {
        std::cout << "Error: Invalid or non-private key loaded from " << keyPath << "\n";
        if (key) EVP_PKEY_free(key);
        return;
    }

    Bytes pkg;
    if (!read_file_bytes(pkgPath.c_str(), pkg)) {
        std::cout << "Error: Could not read package file " << pkgPath << "\n";
        EVP_PKEY_free(key);
        return;
    }

    Bytes pt;
    if (!open_package(key, pkg, pt) || !write_file_bytes(outPath.c_str(), pt)) {
        std::cout << "Error: Package decryption/verification failed! (Tampered data or wrong key)\n";
    } else {
        std::cout << "Package decrypted successfully! (" << pt.size()
                  << " bytes recovered and written to " << outPath << ")\n";
    }
    EVP_PKEY_free(key);
}

static void printMenu() {
    std::cout << "============================================================\n";
    std::cout << "                 OpenSSL Hybrid Crypto\n";
    std::cout << "============================================================\n";
    std::cout << "1. Encrypt a file (seal_package)\n";
    std::cout << "2. Decrypt a package (open_package)\n";
    std::cout << "3. Run Self-Test & Tamper Verification\n";
    std::cout << "0. Exit\n";
    std::cout << "Choose option: ";
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--test") == 0) {
        runSelfTest();
        return g_failures ? 1 : 0;
    }

    int choice = -1;
    while (true) {
        printMenu();
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::string discard;
            std::cin >> discard;
            std::cout << "Invalid input!\n";
            continue;
        }
        if (choice == 0) { std::cout << "\nExiting program...\n"; break; }
        if (choice == 1) encryptFileCli();
        else if (choice == 2) decryptFileCli();
        else if (choice == 3) runSelfTest();
        else std::cout << "Invalid option! Please choose again.\n";
    }
    return 0;
}

