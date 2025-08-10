#include <iostream>
#include <iomanip>
#include <cassert>
#include <string>
#include <vector>
#include "encryption.h"

using namespace crypto;

// Helper function to print test results
void print_test_result(const std::string& test_name, bool passed) {
    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << test_name << std::endl;
}

// Helper function to compare vectors
bool vectors_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

void test_utilities() {
    std::cout << "\n=== Testing Utilities ===\n";
    
    // Test hex conversion
    std::string hex = "deadbeef";
    std::vector<uint8_t> bytes = hex2bytes(hex);
    std::string back_to_hex = bytes2hex(bytes);
    print_test_result("Hex conversion round trip", hex == back_to_hex);
    
    // Test PKCS#7 padding
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::vector<uint8_t> padded = data;
    pkcs7_pad(padded, 8);
    print_test_result("PKCS#7 padding size", padded.size() == 8);
    print_test_result("PKCS#7 padding values", 
                     padded[5] == 3 && padded[6] == 3 && padded[7] == 3);
    
    bool unpad_success = pkcs7_unpad(padded);
    print_test_result("PKCS#7 unpadding", unpad_success && vectors_equal(padded, data));
}

void test_aes() {
    std::cout << "\n=== Testing AES ===\n";
    
    // Test AES-128 ECB
    AES aes;
    std::vector<uint8_t> key128 = hex2bytes("000102030405060708090a0b0c0d0e0f");
    aes.key_expansion(key128.data(), key128.size());
    
    std::vector<uint8_t> plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    
    // Test single block encryption/decryption
    uint8_t block[16];
    std::copy(plaintext.begin(), plaintext.end(), block);
    aes.encrypt_block(block);
    aes.decrypt_block(block);
    
    bool block_test_passed = true;
    for (int i = 0; i < 16; i++) {
        if (block[i] != plaintext[i]) {
            block_test_passed = false;
            break;
        }
    }
    print_test_result("AES-128 single block encrypt/decrypt", block_test_passed);
    
    // Test ECB mode
    std::vector<uint8_t> test_data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
    std::vector<uint8_t> encrypted = aes.encrypt_ecb(test_data);
    std::vector<uint8_t> decrypted = aes.decrypt_ecb(encrypted);
    print_test_result("AES-128 ECB mode", vectors_equal(test_data, decrypted));
    
    // Test CBC mode
    std::vector<uint8_t> iv(16, 0);
    random_bytes(iv.data(), 16);
    std::vector<uint8_t> cbc_encrypted = aes.encrypt_cbc(test_data, iv);
    std::vector<uint8_t> cbc_decrypted = aes.decrypt_cbc(cbc_encrypted, iv);
    print_test_result("AES-128 CBC mode", vectors_equal(test_data, cbc_decrypted));
    
    // Test AES-192
    std::vector<uint8_t> key192 = hex2bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
    aes.key_expansion(key192.data(), key192.size());
    encrypted = aes.encrypt_ecb(test_data);
    decrypted = aes.decrypt_ecb(encrypted);
    print_test_result("AES-192 ECB mode", vectors_equal(test_data, decrypted));
    
    // Test AES-256
    std::vector<uint8_t> key256 = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    aes.key_expansion(key256.data(), key256.size());
    encrypted = aes.encrypt_ecb(test_data);
    decrypted = aes.decrypt_ecb(encrypted);
    print_test_result("AES-256 ECB mode", vectors_equal(test_data, decrypted));
}

void test_rc4() {
    std::cout << "\n=== Testing RC4 ===\n";
    
    std::vector<uint8_t> key = {1, 2, 3, 4, 5};
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    
    std::vector<uint8_t> data = plaintext;
    RC4 rc4_encrypt(key.data(), key.size());
    rc4_encrypt.process(data);
    
    // Decrypt (RC4 is symmetric)
    RC4 rc4_decrypt(key.data(), key.size());
    rc4_decrypt.process(data);
    
    print_test_result("RC4 encrypt/decrypt", vectors_equal(plaintext, data));
}

void test_chacha20() {
    std::cout << "\n=== Testing ChaCha20 ===\n";
    
    uint8_t key[32];
    uint8_t nonce[12];
    random_bytes(key, 32);
    random_bytes(nonce, 12);
    
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    std::vector<uint8_t> data = plaintext;
    
    ChaCha20 chacha_encrypt(key, 0, nonce);
    chacha_encrypt.process(data);
    
    // Decrypt (stream cipher is symmetric with same key/nonce/counter)
    ChaCha20 chacha_decrypt(key, 0, nonce);
    chacha_decrypt.process(data);
    
    print_test_result("ChaCha20 encrypt/decrypt", vectors_equal(plaintext, data));
    
    // Test with longer data
    std::vector<uint8_t> long_data(100, 0x42);
    std::vector<uint8_t> long_original = long_data;
    
    ChaCha20 chacha1(key, 1, nonce);
    chacha1.process(long_data);
    ChaCha20 chacha2(key, 1, nonce);
    chacha2.process(long_data);
    
    print_test_result("ChaCha20 long data", vectors_equal(long_original, long_data));
}

void test_sha256() {
    std::cout << "\n=== Testing SHA-256 ===\n";
    
    // Test empty string
    std::vector<uint8_t> empty;
    std::vector<uint8_t> hash_empty = SHA256::hash(empty);
    print_test_result("SHA-256 empty string", hash_empty.size() == 32);
    
    // Test "abc"
    std::vector<uint8_t> abc = {0x61, 0x62, 0x63}; // "abc"
    std::vector<uint8_t> hash_abc = SHA256::hash(abc);
    print_test_result("SHA-256 'abc'", hash_abc.size() == 32);
    
    // Test consistency
    std::vector<uint8_t> hash_abc2 = SHA256::hash(abc);
    print_test_result("SHA-256 consistency", vectors_equal(hash_abc, hash_abc2));
    
    std::cout << "SHA-256 of 'abc': " << bytes2hex(hash_abc) << std::endl;
}

void test_hmac() {
    std::cout << "\n=== Testing HMAC-SHA256 ===\n";
    
    std::vector<uint8_t> key = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint8_t> message = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    
    std::vector<uint8_t> hmac1 = hmac_sha256(key, message);
    std::vector<uint8_t> hmac2 = hmac_sha256(key, message);
    
    print_test_result("HMAC-SHA256 consistency", vectors_equal(hmac1, hmac2));
    print_test_result("HMAC-SHA256 output length", hmac1.size() == 32);
    
    // Test with different message
    std::vector<uint8_t> message2 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21}; // "Hello!"
    std::vector<uint8_t> hmac3 = hmac_sha256(key, message2);
    print_test_result("HMAC-SHA256 different inputs", !vectors_equal(hmac1, hmac3));
}

void test_pbkdf2() {
    std::cout << "\n=== Testing PBKDF2 ===\n";
    
    std::vector<uint8_t> password = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64}; // "password"
    std::vector<uint8_t> salt = {0x73, 0x61, 0x6c, 0x74}; // "salt"
    
    std::vector<uint8_t> key1 = pbkdf2_hmac_sha256(password, salt, 1000, 32);
    std::vector<uint8_t> key2 = pbkdf2_hmac_sha256(password, salt, 1000, 32);
    
    print_test_result("PBKDF2 consistency", vectors_equal(key1, key2));
    print_test_result("PBKDF2 output length", key1.size() == 32);
    
    // Test different iterations
    std::vector<uint8_t> key3 = pbkdf2_hmac_sha256(password, salt, 1001, 32);
    print_test_result("PBKDF2 different iterations", !vectors_equal(key1, key3));
    
    std::cout << "PBKDF2 result: " << bytes2hex(key1) << std::endl;
}

void test_rsa() {
    std::cout << "\n=== Testing RSA ===\n";
    
    // Simple test with small numbers (not secure, just functional test)
    RSAKey pub = {77, 7, 0}; // n=77=7*11, e=7
    RSAKey priv = {77, 0, 43}; // d=43 (computed as modinv(7, (7-1)*(11-1)))
    
    uint64_t message = 42;
    uint64_t ciphertext = rsa_encrypt(message, pub);
    uint64_t decrypted = rsa_decrypt(ciphertext, priv);
    
    print_test_result("RSA encrypt/decrypt", message == decrypted);
    
    std::cout << "RSA: " << message << " -> " << ciphertext << " -> " << decrypted << std::endl;
}

void test_elgamal() {
    std::cout << "\n=== Testing ElGamal ===\n";
    
    // Simple test with small prime
    ElGamalKey key = {23, 5, 7, 0}; // p=23, g=5, x=7
    key.y = modexp(key.g, key.x, key.p); // y = g^x mod p
    
    uint64_t message = 10;
    uint64_t k = 3; // random value for encryption
    
    try {
        auto ciphertext = elgamal_encrypt(message, key, k);
        uint64_t decrypted = elgamal_decrypt(ciphertext, key);
        
        print_test_result("ElGamal encrypt/decrypt", message == decrypted);
        std::cout << "ElGamal: " << message << " -> (" << ciphertext.first << "," << ciphertext.second << ") -> " << decrypted << std::endl;
    } catch (const std::exception& e) {
        print_test_result("ElGamal encrypt/decrypt", false);
        std::cout << "ElGamal error: " << e.what() << std::endl;
    }
}

void test_ecdsa() {
    std::cout << "\n=== Testing ECDSA ===\n";
    
    try {
        uint64_t priv_key = 12345;
        ECPoint G(SECP256K1_GX, SECP256K1_GY);
        ECPoint pub_key = ec_scalar_mul(priv_key, G, SECP256K1_P);
        
        uint64_t msg_hash = 98765;
        uint64_t k = 54321; // nonce for signing
        
        ECDSASignature sig = ecdsa_sign(priv_key, msg_hash, k);
        bool verified = ecdsa_verify(pub_key, msg_hash, sig);
        
        print_test_result("ECDSA sign/verify", verified);
        
        // Test with wrong message
        bool wrong_verify = ecdsa_verify(pub_key, msg_hash + 1, sig);
        print_test_result("ECDSA wrong message rejection", !wrong_verify);
        
        std::cout << "ECDSA signature: r=" << sig.r << ", s=" << sig.s << std::endl;
    } catch (const std::exception& e) {
        print_test_result("ECDSA sign/verify", false);
        std::cout << "ECDSA error: " << e.what() << std::endl;
    }
}

void test_aesgcm() {
    std::cout << "\n=== Testing AES-GCM (Simplified) ===\n";
    
    std::vector<uint8_t> key = hex2bytes("000102030405060708090a0b0c0d0e0f");
    std::vector<uint8_t> iv(16);
    random_bytes(iv.data(), 16);
    
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    
    try {
        AESGCM gcm(key);
        auto [ciphertext, tag] = gcm.encrypt(plaintext, iv);
        std::vector<uint8_t> decrypted = gcm.decrypt(ciphertext, iv, tag);
        
        print_test_result("AES-GCM encrypt/decrypt", vectors_equal(plaintext, decrypted));
        
        // Test tampered ciphertext
        if (!ciphertext.empty()) {
            std::vector<uint8_t> tampered = ciphertext;
            tampered[0] ^= 1; // flip a bit
            
            bool caught_tampering = false;
            try {
                gcm.decrypt(tampered, iv, tag);
            } catch (const std::exception&) {
                caught_tampering = true;
            }
            print_test_result("AES-GCM tamper detection", caught_tampering);
        }
        
    } catch (const std::exception& e) {
        print_test_result("AES-GCM encrypt/decrypt", false);
        std::cout << "AES-GCM error: " << e.what() << std::endl;
    }
}

void performance_test() {
    std::cout << "\n=== Performance Test ===\n";
    
    // Test AES with larger data
    std::vector<uint8_t> large_data(1024 * 1024, 0x42); // 1MB of data
    std::vector<uint8_t> key = hex2bytes("000102030405060708090a0b0c0d0e0f");
    
    auto start = std::chrono::high_resolution_clock::now();
    
    AES aes;
    aes.key_expansion(key.data(), key.size());
    std::vector<uint8_t> encrypted = aes.encrypt_ecb(large_data);
    std::vector<uint8_t> decrypted = aes.decrypt_ecb(encrypted);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    print_test_result("Performance test (1MB AES)", vectors_equal(large_data, decrypted));
    std::cout << "Time taken: " << duration.count() << " ms" << std::endl;
}

int main() {
    std::cout << "Educational Crypto Library Test Suite\n";
    std::cout << "======================================\n";
    std::cout << "WARNING: This is for educational/CTF use only!\n";
    std::cout << "Not suitable for production use!\n";
    
    try {
        test_utilities();
        test_aes();
        test_rc4();
        test_chacha20();
        test_sha256();
        test_hmac();
        test_pbkdf2();
        test_rsa();
        test_elgamal();
        test_ecdsa();
        test_aesgcm();
        performance_test();
        
        std::cout << "\n=== Test Suite Complete ===\n";
        std::cout << "Check output above for any FAIL results.\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Test suite error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
