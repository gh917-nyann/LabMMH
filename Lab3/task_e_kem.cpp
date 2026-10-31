// task_e_kem.cpp -- Task 5: RSASVE KEM + HKDF-SHA-256 + AES-256-GCM Test Runner & CLI
#include "rsa_kem.h"
#include <set>

static int g_failures = 0;

[[maybe_unused]] static void check(const char* name, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

static inline Bytes hex_to_bytes(const char* h) {
    Bytes b;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
        char two[3] = {h[i], h[i + 1], 0};
        b.push_back(static_cast<unsigned char>(std::strtoul(two, nullptr, 16)));
    }
    return b;
}

static void runSelfTest() {
    std::printf("== Running Task E RSASVE KEM Self-Test ==\n");
    g_failures = 0;

    std::printf("  generating 2 distinct RSA-2048 key pairs for testing...\n");
    EVP_PKEY* k1 = generate_rsa_key(2048);
    EVP_PKEY* k2 = generate_rsa_key(2048);
    NOTNULL_KEY(k1); NOTNULL_KEY(k2);

    // 1. 100 rounds RSASVE encaps/decaps (correctness & uniqueness)
    bool all100Ok = true;
    std::set<std::string> seenCts;
    for (int i = 0; i < 100; ++i) {
        Bytes ct, z, z_dec;
        if (!evp_encaps(k1, ct, z) || !evp_decaps(k1, ct, z_dec) || z != z_dec) {
            all100Ok = false; break;
        }
        seenCts.insert(std::string(ct.begin(), ct.end()));
    }
    check("100 rounds RSASVE encaps/decaps correctness", all100Ok);
    check("100 rounds RSASVE encaps ciphertexts are distinct", seenCts.size() == 100);

    // 2. Cross-validation: edu vs evp
    Bytes ct_edu, z_edu, z_dec1;
    bool okEdu1 = edu_encaps(k1, ct_edu, z_edu) && evp_decaps(k1, ct_edu, z_dec1);
    check("edu_encaps -> evp_decaps cross-match", okEdu1 && z_edu == z_dec1);

    Bytes ct_evp, z_evp, z_dec2;
    bool okEdu2 = evp_encaps(k1, ct_evp, z_evp) && edu_decaps(k1, ct_evp, z_dec2);
    check("evp_encaps -> edu_decaps cross-match", okEdu2 && z_evp == z_dec2);

    // 3. HKDF RFC 5869 Test Case 1
    Bytes ikm(22, 0x0b);
    Bytes salt = hex_to_bytes("000102030405060708090a0b0c");
    Bytes info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
    Bytes expOkm = hex_to_bytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    Bytes okm1 = my_hkdf(salt, ikm, info, 42);
    Bytes okm2 = evp_hkdf(salt, ikm, info, 42);
    check("my_hkdf matches RFC 5869 Test Case 1", CRYPTO_memcmp(okm1.data(), expOkm.data(), 42) == 0);
    check("evp_hkdf matches RFC 5869 Test Case 1", CRYPTO_memcmp(okm2.data(), expOkm.data(), 42) == 0);

    // 4. KEM Round-trip File/Message Encryption
    const std::string msg = "Antigravity Lab 3 Task E: RSASVE KEM + HKDF + AES-256-GCM test vector.";
    Bytes pt(msg.begin(), msg.end()), pkg, dec;
    bool okSeal = seal_package_kem(k1, pt, pkg);
    check("seal_package_kem succeeds", okSeal);
    bool okOpen = open_package_kem(k1, pkg, dec);
    check("open_package_kem recovers exact plaintext", okOpen && dec == pt);

    // 5. Tamper C_kem: decaps still computes Z', but GCM tag verification rejects
    Bytes badPkg = pkg, badDec;
    badPkg[10 + 5] ^= 0x40; // mutate 1 bit in kem_ct
    check("tampered C_kem rejected by AES-GCM tag verification", !open_package_kem(k1, badPkg, badDec));

    // 6. Distinct key_id produces distinct AES keys and rejects mismatched key
    Bytes zSample(256, 0x42), id1 = compute_key_id(k1), id2 = compute_key_id(k2);
    Bytes kAes1 = derive_aes_key(zSample, id1, 256, ct_evp);
    Bytes kAes2 = derive_aes_key(zSample, id2, 256, ct_evp);
    check("distinct key_id binds to distinct derived AES keys", kAes1 != kAes2);
    check("package rejected when opened with wrong private key (key_id mismatch)", !open_package_kem(k2, pkg, badDec));

    OPENSSL_cleanse(zSample.data(), zSample.size());
    OPENSSL_cleanse(kAes1.data(), kAes1.size());
    OPENSSL_cleanse(kAes2.data(), kAes2.size());

    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    std::printf("\n%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
}

static void encryptFileCli() {
    std::string keyPath, inPath, outPath;
    std::cout << "Enter Public Key path: ";  std::cin >> keyPath;
    std::cout << "Enter Input File path: ";  std::cin >> inPath;
    std::cout << "Enter Output Package path (.kem): "; std::cin >> outPath;

    EVP_PKEY* key = load_key_auto(keyPath.c_str());
    if (!key) { std::cout << "Error: Could not load key from " << keyPath << "\n"; return; }
    if (is_private_key(key)) {
        std::cout << "  [Notice: A private key was provided; using its public components (n, e) for KEM encaps.]\n";
    }

    Bytes pt;
    if (!read_file_bytes(inPath.c_str(), pt)) {
        std::cout << "Error: Could not read file " << inPath << "\n";
        EVP_PKEY_free(key);
        return;
    }

    Bytes pkg;
    if (!seal_package_kem(key, pt, pkg) || !write_file_bytes(outPath.c_str(), pkg)) {
        std::cout << "Error: Failed to seal or write KEM package!\n";
    } else {
        std::cout << "File encrypted successfully! (" << pt.size() << " bytes -> "
                  << pkg.size() << " bytes package written to " << outPath << ")\n";
    }
    EVP_PKEY_free(key);
}

static void decryptFileCli() {
    std::string keyPath, pkgPath, outPath;
    std::cout << "Enter Private Key path: "; std::cin >> keyPath;
    std::cout << "Enter Package File path (.kem): "; std::cin >> pkgPath;
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
    if (!open_package_kem(key, pkg, pt) || !write_file_bytes(outPath.c_str(), pt)) {
        std::cout << "Error: KEM package decryption failed! (Tampered data or wrong key)\n";
    } else {
        std::cout << "Package decrypted successfully! (" << pt.size()
                  << " bytes recovered and written to " << outPath << ")\n";
    }
    EVP_PKEY_free(key);
}

static void printMenu() {
    std::cout << "============================================================\n";
    std::cout << "                 OpenSSL RSASVE KEM CLI\n";
    std::cout << "============================================================\n";
    std::cout << "1. Encrypt a file (seal_package_kem)\n";
    std::cout << "2. Decrypt a package (open_package_kem)\n";
    std::cout << "3. Run Self-Test & Verification\n";
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

