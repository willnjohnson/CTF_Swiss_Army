// encryption.h - Educational C++ crypto library with 10 popular algorithms for CTFs
// Supports AES (128/192/256), ChaCha20, RC4, AES-GCM (simplified), SHA-256, HMAC-SHA256,
// RSA (basic), ElGamal, ECDSA (secp256k1 toy), PBKDF2-HMAC-SHA256.
//
// WARNING: This is for educational/CTF use only. Not secure production code! No side-channel protections.
// Uses C++17, no external dependencies. Written for clarity and demonstration.
//
// Single-file header. Put in project and #include "encryption.h". C++17 or later recommended.
// License: MIT

#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <cstring>
#include <cstdint>
#include <random>
#include <cassert>
#include <cmath>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <map>

namespace crypto {

// ======================= UTILITIES ========================

// Convert hex string to bytes vector
inline std::vector<uint8_t> hex2bytes(const std::string &hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            byte <<= 4;
            if ('0' <= c && c <= '9') byte |= (c - '0');
            else if ('a' <= c && c <= 'f') byte |= (c - 'a' + 10);
            else if ('A' <= c && c <= 'F') byte |= (c - 'A' + 10);
            else return {}; // invalid char
        }
        out.push_back(byte);
    }
    return out;
}

// Convert bytes vector to hex string
inline std::string bytes2hex(const std::vector<uint8_t> &data) {
    std::string out;
    static const char *hexchars = "0123456789abcdef";
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(hexchars[b >> 4]);
        out.push_back(hexchars[b & 0x0F]);
    }
    return out;
}

// Secure random bytes (platform-independent)
inline void random_bytes(uint8_t *buf, size_t len) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<int> dis(0, 255);
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)dis(gen);
}

// PKCS#7 padding for block cipher
inline void pkcs7_pad(std::vector<uint8_t> &data, size_t blocksize) {
    size_t padlen = blocksize - (data.size() % blocksize);
    data.insert(data.end(), padlen, (uint8_t)padlen);
}

// Remove PKCS#7 padding. Returns true if valid padding found and removed.
inline bool pkcs7_unpad(std::vector<uint8_t> &data) {
    if (data.empty()) return false;
    uint8_t padlen = data.back();
    if (padlen == 0 || padlen > data.size()) return false;
    for (size_t i = data.size() - padlen; i < data.size(); ++i) {
        if (data[i] != padlen) return false;
    }
    data.resize(data.size() - padlen);
    return true;
}

// XOR two equal-length byte arrays in place
inline void xor_inplace(std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
    assert(a.size() == b.size());
    for (size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
}

// ======================= AES-128/192/256 (ECB + CBC modes) ========================

// This AES implementation is minimal, with only 128-bit blocks, supporting key expansion for 128/192/256 bits.
// ECB and CBC modes with PKCS#7 padding are supported.

// S-box from FIPS-197
constexpr uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Round constants for key expansion
constexpr uint32_t Rcon[10] = {
    0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

inline uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

inline uint32_t sub_word(uint32_t w) {
    return (sbox[(w >> 24) & 0xff] << 24) | (sbox[(w >> 16) & 0xff] << 16) |
           (sbox[(w >> 8) & 0xff] << 8) | (sbox[w & 0xff]);
}

// AES class supporting 128,192,256 bit keys
class AES {
    size_t Nk;  // Key length (in 32-bit words): 4,6,8
    size_t Nr;  // Number of rounds: 10,12,14
    std::vector<uint32_t> roundKeys;

    static uint8_t gf_mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i=0;i<8;++i) {
            if (b & 1) p ^= a;
            bool hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    void sub_bytes(uint8_t state[4][4]) {
        for (int i=0;i<4;++i)
            for (int j=0;j<4;++j)
                state[i][j] = sbox[state[i][j]];
    }
    void inv_sub_bytes(uint8_t state[4][4]) {
        static constexpr uint8_t inv_sbox[256] = {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        };
        for (int i=0;i<4;++i)
            for (int j=0;j<4;++j)
                state[i][j] = inv_sbox[state[i][j]];
    }
    void shift_rows(uint8_t state[4][4]) {
        uint8_t tmp[4];
        // row 1 rotate left 1
        for (int i=0;i<4;++i) tmp[i] = state[1][(i+1)%4];
        for (int i=0;i<4;++i) state[1][i] = tmp[i];
        // row 2 rotate left 2
        for (int i=0;i<4;++i) tmp[i] = state[2][(i+2)%4];
        for (int i=0;i<4;++i) state[2][i] = tmp[i];
        // row 3 rotate left 3
        for (int i=0;i<4;++i) tmp[i] = state[3][(i+3)%4];
        for (int i=0;i<4;++i) state[3][i] = tmp[i];
    }
    void inv_shift_rows(uint8_t state[4][4]) {
        uint8_t tmp[4];
        // row 1 rotate right 1
        for (int i=0;i<4;++i) tmp[i] = state[1][(i+3)%4];
        for (int i=0;i<4;++i) state[1][i] = tmp[i];
        // row 2 rotate right 2
        for (int i=0;i<4;++i) tmp[i] = state[2][(i+2)%4];
        for (int i=0;i<4;++i) state[2][i] = tmp[i];
        // row 3 rotate right 3
        for (int i=0;i<4;++i) tmp[i] = state[3][(i+1)%4];
        for (int i=0;i<4;++i) state[3][i] = tmp[i];
    }
    void mix_columns(uint8_t state[4][4]) {
        for (int i=0;i<4;++i) {
            uint8_t a0 = state[0][i], a1=state[1][i], a2=state[2][i], a3=state[3][i];
            state[0][i] = gf_mul(0x02,a0) ^ gf_mul(0x03,a1) ^ a2 ^ a3;
            state[1][i] = a0 ^ gf_mul(0x02,a1) ^ gf_mul(0x03,a2) ^ a3;
            state[2][i] = a0 ^ a1 ^ gf_mul(0x02,a2) ^ gf_mul(0x03,a3);
            state[3][i] = gf_mul(0x03,a0) ^ a1 ^ a2 ^ gf_mul(0x02,a3);
        }
    }
    void inv_mix_columns(uint8_t state[4][4]) {
        for (int i=0;i<4;++i) {
            uint8_t a0 = state[0][i], a1=state[1][i], a2=state[2][i], a3=state[3][i];
            state[0][i] = gf_mul(0x0e,a0) ^ gf_mul(0x0b,a1) ^ gf_mul(0x0d,a2) ^ gf_mul(0x09,a3);
            state[1][i] = gf_mul(0x09,a0) ^ gf_mul(0x0e,a1) ^ gf_mul(0x0b,a2) ^ gf_mul(0x0d,a3);
            state[2][i] = gf_mul(0x0d,a0) ^ gf_mul(0x09,a1) ^ gf_mul(0x0e,a2) ^ gf_mul(0x0b,a3);
            state[3][i] = gf_mul(0x0b,a0) ^ gf_mul(0x0d,a1) ^ gf_mul(0x09,a2) ^ gf_mul(0x0e,a3);
        }
    }
    void add_round_key(uint8_t state[4][4], const uint32_t *rk) {
        for (int c=0;c<4;++c) {
            uint32_t k = rk[c];
            state[0][c] ^= (k >> 24) & 0xff;
            state[1][c] ^= (k >> 16) & 0xff;
            state[2][c] ^= (k >> 8) & 0xff;
            state[3][c] ^= k & 0xff;
        }
    }

public:
    AES() = default;

    void key_expansion(const uint8_t *key, size_t keylen) {
        if (keylen == 16) { Nk=4; Nr=10; }
        else if (keylen == 24) { Nk=6; Nr=12; }
        else if (keylen == 32) { Nk=8; Nr=14; }
        else throw std::runtime_error("AES: Invalid key length");

        roundKeys.resize(4*(Nr+1));
        // Copy key into first Nk words
        for (size_t i=0; i<Nk; ++i) {
            roundKeys[i] = (uint32_t(key[4*i]) << 24) | (uint32_t(key[4*i+1]) << 16) |
                           (uint32_t(key[4*i+2]) << 8) | uint32_t(key[4*i+3]);
        }
        for (size_t i = Nk; i < 4*(Nr+1); ++i) {
            uint32_t temp = roundKeys[i-1];
            if (i % Nk == 0)
                temp = sub_word(rot_word(temp)) ^ Rcon[(i/Nk)-1];
            else if (Nk > 6 && (i % Nk) == 4)
                temp = sub_word(temp);
            roundKeys[i] = roundKeys[i - Nk] ^ temp;
        }
    }

    // Encrypt one 16-byte block in place
    void encrypt_block(uint8_t block[16]) {
        uint8_t state[4][4];
        for (int i=0;i<16;++i) state[i%4][i/4] = block[i];
        add_round_key(state, roundKeys.data());

        for (size_t round=1; round < Nr; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, &roundKeys[4*round]);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, &roundKeys[4*Nr]);

        for (int i=0;i<16;++i) block[i] = state[i%4][i/4];
    }

    // Decrypt one 16-byte block in place
    void decrypt_block(uint8_t block[16]) {
        uint8_t state[4][4];
        for (int i=0;i<16;++i) state[i%4][i/4] = block[i];
        add_round_key(state, &roundKeys[4*Nr]);
        for (size_t round=Nr-1; round >= 1; --round) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, &roundKeys[4*round]);
            inv_mix_columns(state);
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, roundKeys.data());

        for (int i=0;i<16;++i) block[i] = state[i%4][i/4];
    }

    // Encrypt in ECB mode, data padded by PKCS7
    std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t> &plaintext) {
        std::vector<uint8_t> data = plaintext;
        pkcs7_pad(data, 16);
        std::vector<uint8_t> out(data.size());
        for (size_t i=0;i<data.size(); i+=16) {
            uint8_t block[16];
            memcpy(block, data.data()+i, 16);
            encrypt_block(block);
            memcpy(out.data()+i, block, 16);
        }
        return out;
    }

    // Decrypt in ECB mode, remove PKCS7 padding
    std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t> &ciphertext) {
        if (ciphertext.size() % 16 != 0) throw std::runtime_error("AES decrypt_ecb: invalid length");
        std::vector<uint8_t> out(ciphertext.size());
        for (size_t i=0;i<ciphertext.size(); i+=16) {
            uint8_t block[16];
            memcpy(block, ciphertext.data()+i, 16);
            decrypt_block(block);
            memcpy(out.data()+i, block, 16);
        }
        if (!pkcs7_unpad(out)) throw std::runtime_error("AES decrypt_ecb: invalid padding");
        return out;
    }

    // CBC mode encrypt
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &iv) {
        if (iv.size() != 16) throw std::runtime_error("AES encrypt_cbc: IV must be 16 bytes");
        std::vector<uint8_t> data = plaintext;
        pkcs7_pad(data, 16);
        std::vector<uint8_t> out(data.size());
        std::vector<uint8_t> prev_block = iv;
        for (size_t i=0; i<data.size(); i+=16) {
            std::vector<uint8_t> block(data.begin()+i, data.begin()+i+16);
            xor_inplace(block, prev_block);
            uint8_t b[16];
            memcpy(b, block.data(), 16);
            encrypt_block(b);
            memcpy(out.data()+i, b, 16);
            prev_block.assign(b, b+16);
        }
        return out;
    }

    // CBC mode decrypt
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &iv) {
        if (ciphertext.size() % 16 != 0) throw std::runtime_error("AES decrypt_cbc: invalid ciphertext length");
        if (iv.size() != 16) throw std::runtime_error("AES decrypt_cbc: IV must be 16 bytes");
        std::vector<uint8_t> out(ciphertext.size());
        std::vector<uint8_t> prev_block = iv;
        for (size_t i=0; i<ciphertext.size(); i+=16) {
            uint8_t block[16];
            memcpy(block, ciphertext.data()+i, 16);
            uint8_t decrypted[16];
            memcpy(decrypted, block, 16);
            decrypt_block(decrypted);
            for (int j=0; j<16; ++j)
                out[i+j] = decrypted[j] ^ prev_block[j];
            prev_block.assign(block, block+16);
        }
        if (!pkcs7_unpad(out)) throw std::runtime_error("AES decrypt_cbc: invalid padding");
        return out;
    }
};

// ======================= RC4 Stream Cipher ========================

class RC4 {
    uint8_t S[256];
    size_t i, j;
public:
    RC4(const uint8_t *key, size_t keylen) {
        for (int k=0;k<256;++k) S[k] = k;
        i = j = 0;
        size_t jtmp=0;
        for (int k=0;k<256;++k) {
            jtmp = (jtmp + S[k] + key[k % keylen]) & 0xff;
            std::swap(S[k], S[jtmp]);
        }
    }
    uint8_t next_byte() {
        i = (i+1) & 0xff;
        j = (j + S[i]) & 0xff;
        std::swap(S[i], S[j]);
        return S[(S[i]+S[j]) & 0xff];
    }
    // Encrypt/decrypt in-place
    void process(std::vector<uint8_t> &data) {
        for (auto &b : data) b ^= next_byte();
    }
};

// ======================= ChaCha20 ========================
// ChaCha20 stream cipher per RFC 8439 simplified version

class ChaCha20 {
    uint32_t state[16];

    static inline uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
        a += b; d ^= a; d = rotl(d,16);
        c += d; b ^= c; b = rotl(b,12);
        a += b; d ^= a; d = rotl(d,8);
        c += d; b ^= c; b = rotl(b,7);
    }

public:
    ChaCha20(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
        // constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        // key
        for (int i=0;i<8;++i) {
            state[4+i] = (key[4*i]) | (key[4*i+1]<<8) | (key[4*i+2]<<16) | (key[4*i+3]<<24);
        }
        state[12] = counter;
        state[13] = (nonce[0]) | (nonce[1]<<8) | (nonce[2]<<16) | (nonce[3]<<24);
        state[14] = (nonce[4]) | (nonce[5]<<8) | (nonce[6]<<16) | (nonce[7]<<24);
        state[15] = (nonce[8]) | (nonce[9]<<8) | (nonce[10]<<16) | (nonce[11]<<24);
    }

    void keystream_block(uint8_t output[64]) {
        uint32_t working[16];
        for (int i=0;i<16;++i) working[i] = state[i];
        for (int i=0;i<10;++i) {
            quarter_round(working[0],working[4],working[8],working[12]);
            quarter_round(working[1],working[5],working[9],working[13]);
            quarter_round(working[2],working[6],working[10],working[14]);
            quarter_round(working[3],working[7],working[11],working[15]);
            quarter_round(working[0],working[5],working[10],working[15]);
            quarter_round(working[1],working[6],working[11],working[12]);
            quarter_round(working[2],working[7],working[8],working[13]);
            quarter_round(working[3],working[4],working[9],working[14]);
        }
        for (int i=0;i<16;++i) working[i] += state[i];
        for (int i=0;i<16;++i) {
            output[4*i] = working[i] & 0xff;
            output[4*i+1] = (working[i] >> 8) & 0xff;
            output[4*i+2] = (working[i] >> 16) & 0xff;
            output[4*i+3] = (working[i] >> 24) & 0xff;
        }
        ++state[12];
    }

    void process(std::vector<uint8_t> &data) {
        size_t pos = 0;
        uint8_t block[64];
        while (pos < data.size()) {
            keystream_block(block);
            size_t chunk = std::min(data.size()-pos, size_t(64));
            for (size_t i=0;i<chunk;++i) data[pos+i] ^= block[i];
            pos += chunk;
        }
    }
};

// ======================= SHA-256 ========================
// Reference SHA-256 implementation (used by HMAC and PBKDF2)

class SHA256 {
    uint32_t h[8];
    uint64_t length;
    uint8_t buffer[64];
    size_t buffer_len;

    static constexpr uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32-n));
    }
    static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint32_t bsig0(uint32_t x) {
        return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22);
    }
    static inline uint32_t bsig1(uint32_t x) {
        return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25);
    }
    static inline uint32_t ssig0(uint32_t x) {
        return rotr(x,7) ^ rotr(x,18) ^ (x >> 3);
    }
    static inline uint32_t ssig1(uint32_t x) {
        return rotr(x,17) ^ rotr(x,19) ^ (x >> 10);
    }

    void process_chunk(const uint8_t *chunk) {
        uint32_t w[64];
        for (int i=0; i<16; ++i) {
            w[i] = (chunk[4*i] << 24) | (chunk[4*i+1] << 16) | (chunk[4*i+2] << 8) | chunk[4*i+3];
        }
        for (int i=16; i<64; ++i) {
            w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i=0; i<64; ++i) {
            uint32_t T1 = hh + bsig1(e) + ch(e,f,g) + k[i] + w[i];
            uint32_t T2 = bsig0(a) + maj(a,b,c);
            hh = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

public:
    SHA256() {
        reset();
    }

    void reset() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        length = 0;
        buffer_len = 0;
    }

    void update(const uint8_t *data, size_t len) {
        length += len * 8;
        while (len > 0) {
            size_t to_copy = std::min(len, 64 - buffer_len);
            memcpy(buffer + buffer_len, data, to_copy);
            buffer_len += to_copy;
            data += to_copy;
            len -= to_copy;
            if (buffer_len == 64) {
                process_chunk(buffer);
                buffer_len = 0;
            }
        }
    }

    void finalize(uint8_t hash[32]) {
        buffer[buffer_len++] = 0x80;
        if (buffer_len > 56) {
            while (buffer_len < 64) buffer[buffer_len++] = 0;
            process_chunk(buffer);
            buffer_len = 0;
        }
        while (buffer_len < 56) buffer[buffer_len++] = 0;
        for (int i=7;i>=0;--i) buffer[buffer_len++] = (length >> (i*8)) & 0xff;
        process_chunk(buffer);
        for (int i=0;i<8;++i) {
            hash[4*i] = (h[i] >> 24) & 0xff;
            hash[4*i+1] = (h[i] >> 16) & 0xff;
            hash[4*i+2] = (h[i] >> 8) & 0xff;
            hash[4*i+3] = h[i] & 0xff;
        }
    }

    static std::vector<uint8_t> hash(const std::vector<uint8_t> &data) {
        SHA256 sha;
        sha.update(data.data(), data.size());
        std::vector<uint8_t> out(32);
        sha.finalize(out.data());
        return out;
    }
};

// ======================= HMAC-SHA256 ========================

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {
    const size_t block_size = 64;
    std::vector<uint8_t> k = key;
    if (k.size() > block_size)
        k = SHA256::hash(k);
    if (k.size() < block_size)
        k.resize(block_size, 0);

    std::vector<uint8_t> o_key_pad(block_size), i_key_pad(block_size);
    for (size_t i=0;i<block_size;++i) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    std::vector<uint8_t> inner = i_key_pad;
    inner.insert(inner.end(), message.begin(), message.end());
    std::vector<uint8_t> inner_hash = SHA256::hash(inner);

    std::vector<uint8_t> outer = o_key_pad;
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return SHA256::hash(outer);
}

// ======================= PBKDF2-HMAC-SHA256 ========================

std::vector<uint8_t> pbkdf2_hmac_sha256(const std::vector<uint8_t> &password,
                                       const std::vector<uint8_t> &salt,
                                       uint32_t iterations,
                                       size_t dkLen) {
    std::vector<uint8_t> dk(dkLen);
    uint32_t block_count = (dkLen + 31) / 32;
    for (uint32_t i=1; i <= block_count; ++i) {
        std::vector<uint8_t> int_i = {
            (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)(i)
        };
        std::vector<uint8_t> salt_int = salt;
        salt_int.insert(salt_int.end(), int_i.begin(), int_i.end());
        std::vector<uint8_t> u = hmac_sha256(password, salt_int);
        std::vector<uint8_t> t = u;
        for (uint32_t j=1; j<iterations; ++j) {
            u = hmac_sha256(password, u);
            for (size_t k=0; k<32; ++k) t[k] ^= u[k];
        }
        size_t offset = (i-1)*32;
        size_t to_copy = std::min(size_t(32), dkLen - offset);
        std::copy(t.begin(), t.begin()+to_copy, dk.begin()+offset);
    }
    return dk;
}

// ======================= RSA (Basic textbook implementation) ========================

// Note: Not secure or padding safe; used for small exponent testing and CTF puzzles.

struct RSAKey {
    uint64_t n; // modulus
    uint64_t e; // public exponent
    uint64_t d; // private exponent (for private key)
};

// Modular exponentiation (base^exp mod mod)
uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1 % mod;
    uint64_t cur = base % mod;
    while (exp > 0) {
        if (exp & 1) result = (result * cur) % mod;
        cur = (cur * cur) % mod;
        exp >>= 1;
    }
    return result;
}

// RSA encrypt: c = m^e mod n
uint64_t rsa_encrypt(uint64_t m, const RSAKey &pub) {
    return modexp(m, pub.e, pub.n);
}

// RSA decrypt: m = c^d mod n
uint64_t rsa_decrypt(uint64_t c, const RSAKey &priv) {
    return modexp(c, priv.d, priv.n);
}

// ======================= ElGamal (Classic multiplicative group mod p) ========================

struct ElGamalKey {
    uint64_t p; // prime modulus
    uint64_t g; // generator
    uint64_t x; // private key (random)
    uint64_t y; // public key = g^x mod p
};

// Modular multiplicative inverse via Extended Euclidean algorithm
uint64_t modinv(uint64_t a, uint64_t m) {
    int64_t t=0, newt=1;
    int64_t r=m, newr=a;
    while (newr != 0) {
        int64_t q = r / newr;
        std::swap(t, newt -= q*t);
        std::swap(r, newr -= q*r);
    }
    if (r > 1) throw std::runtime_error("No inverse");
    if (t < 0) t += m;
    return t;
}

// ElGamal encrypt: ciphertext = (c1, c2)
// c1 = g^k mod p, c2 = m * y^k mod p
std::pair<uint64_t,uint64_t> elgamal_encrypt(uint64_t m, const ElGamalKey &pub, uint64_t k) {
    if (k == 0 || k >= pub.p) throw std::runtime_error("Invalid k");
    uint64_t c1 = modexp(pub.g, k, pub.p);
    uint64_t c2 = (m * modexp(pub.y, k, pub.p)) % pub.p;
    return {c1, c2};
}

// ElGamal decrypt: m = c2 * c1^(p-1 - x) mod p
uint64_t elgamal_decrypt(const std::pair<uint64_t,uint64_t> &cipher, const ElGamalKey &priv) {
    uint64_t s = modexp(cipher.first, priv.p-1 - priv.x, priv.p);
    return (cipher.second * s) % priv.p;
}

// ======================= ECDSA (secp256k1 simplified toy example) ========================

// This is a minimal toy ECDSA over secp256k1, just for demonstration and small test values.
// Real ECDSA uses big ints, specialized libs. This uses 64-bit for simplicity.

// Curve parameters for secp256k1:
// y^2 = x^3 + 7 mod p
constexpr uint64_t SECP256K1_P = 0xFFFFFFFFFFFFFFFFULL; // Simplified small prime for demo (not real curve prime)
constexpr uint64_t SECP256K1_N = 0xFFFFFFFFFFFFFFFEULL; // simplified order
constexpr uint64_t SECP256K1_GX = 1;
constexpr uint64_t SECP256K1_GY = 2;

struct ECPoint {
    uint64_t x, y;
    bool infinity;

    ECPoint() : x(0), y(0), infinity(true) {}
    ECPoint(uint64_t _x, uint64_t _y) : x(_x), y(_y), infinity(false) {}

    static ECPoint infinity_point() { return ECPoint(); }
};

// Modular addition, subtraction, multiplication mod p
inline uint64_t mod_add(uint64_t a, uint64_t b, uint64_t p) { return (a + b) % p; }
inline uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t p) { return (a + p - b) % p; }
inline uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t p) { return (a * b) % p; }

// Modular inverse (Extended Euclid)
uint64_t mod_inv(uint64_t a, uint64_t p) {
    int64_t t=0, newt=1;
    int64_t r = p, newr = a;
    while (newr != 0) {
        int64_t q = r / newr;
        int64_t tmp = newt;
        newt = t - q*newt;
        t = tmp;
        tmp = newr;
        newr = r - q*newr;
        r = tmp;
    }
    if (r > 1) throw std::runtime_error("No inverse");
    if (t < 0) t += p;
    return t;
}

// Elliptic curve point addition (simplified, no checks)
ECPoint ec_point_add(const ECPoint &P, const ECPoint &Q, uint64_t p) {
    if (P.infinity) return Q;
    if (Q.infinity) return P;
    if (P.x == Q.x) {
        if ((P.y + Q.y) % p == 0) return ECPoint::infinity_point();
        // point doubling
        uint64_t s = mod_mul(3 * mod_mul(P.x, P.x, p), mod_inv(2 * P.y, p), p);
        uint64_t xr = mod_sub(mod_mul(s, s, p), mod_mul(2, P.x, p), p);
        uint64_t yr = mod_sub(mod_mul(s, mod_sub(P.x, xr, p), p), P.y, p);
        return ECPoint(xr, yr);
    } else {
        uint64_t s = mod_mul(mod_sub(Q.y, P.y, p), mod_inv(mod_sub(Q.x, P.x, p), p), p);
        uint64_t xr = mod_sub(mod_sub(mod_mul(s, s, p), P.x, p), Q.x, p);
        uint64_t yr = mod_sub(mod_mul(s, mod_sub(P.x, xr, p), p), P.y, p);
        return ECPoint(xr, yr);
    }
}

// Elliptic curve scalar multiplication (double-and-add)
ECPoint ec_scalar_mul(uint64_t k, const ECPoint &P, uint64_t p) {
    ECPoint R = ECPoint::infinity_point();
    ECPoint Q = P;
    while (k) {
        if (k & 1) R = ec_point_add(R, Q, p);
        Q = ec_point_add(Q, Q, p);
        k >>= 1;
    }
    return R;
}

// ECDSA sign (simplified, with fixed k)
struct ECDSASignature {
    uint64_t r, s;
};

ECDSASignature ecdsa_sign(uint64_t priv_key, uint64_t msg_hash, uint64_t k, uint64_t p = SECP256K1_P, uint64_t n = SECP256K1_N) {
    ECPoint G(SECP256K1_GX, SECP256K1_GY);
    ECPoint R = ec_scalar_mul(k, G, p);
    uint64_t r = R.x % n;
    if (r == 0) throw std::runtime_error("Invalid r=0");
    uint64_t kinv = mod_inv(k, n);
    uint64_t s = (kinv * (msg_hash + r * priv_key)) % n;
    if (s == 0) throw std::runtime_error("Invalid s=0");
    return {r, s};
}

// ECDSA verify (simplified)
bool ecdsa_verify(ECPoint pub_key, uint64_t msg_hash, const ECDSASignature &sig, uint64_t p = SECP256K1_P, uint64_t n = SECP256K1_N) {
    if (sig.r == 0 || sig.r >= n) return false;
    if (sig.s == 0 || sig.s >= n) return false;
    uint64_t w = mod_inv(sig.s, n);
    uint64_t u1 = (msg_hash * w) % n;
    uint64_t u2 = (sig.r * w) % n;
    ECPoint G(SECP256K1_GX, SECP256K1_GY);
    ECPoint P1 = ec_scalar_mul(u1, G, p);
    ECPoint P2 = ec_scalar_mul(u2, pub_key, p);
    ECPoint X = ec_point_add(P1, P2, p);
    if (X.infinity) return false;
    return (X.x % n) == sig.r;
}

// ======================= AES-GCM (Simplified version) ========================

// For brevity, here is a minimal simplified AES-GCM like implementation (no GHASH optimization),
// just chaining AES in CTR mode and XOR with plaintext, plus an HMAC-SHA256 as a tag.
// This is NOT secure or spec-compliant, but gives flavor of authenticated encryption.

class AESGCM {
    AES aes;
    std::vector<uint8_t> key;
public:
    AESGCM(const std::vector<uint8_t> &key_bytes) {
        key = key_bytes;
        aes.key_expansion(key.data(), key.size());
    }

    // Encrypt and produce a tag (simplified): tag = HMAC_SHA256(key, ciphertext + iv)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encrypt(const std::vector<uint8_t> &plaintext,
                                                                 const std::vector<uint8_t> &iv) {
        if (iv.size() != 16) throw std::runtime_error("AES-GCM simplified: IV must be 16 bytes");
        // CTR mode: XOR plaintext with AES encrypt of IV+counter blocks
        std::vector<uint8_t> ciphertext(plaintext.size());
        size_t blocks = (plaintext.size() + 15)/16;
        for (size_t i=0;i<blocks;++i) {
            std::vector<uint8_t> ctr_block = iv;
            // increment counter in last 4 bytes
            uint32_t ctr = (uint32_t)i;
            ctr_block[12] = (ctr >> 24) & 0xff;
            ctr_block[13] = (ctr >> 16) & 0xff;
            ctr_block[14] = (ctr >> 8) & 0xff;
            ctr_block[15] = ctr & 0xff;
            uint8_t encrypted_block[16];
            memcpy(encrypted_block, ctr_block.data(), 16);
            aes.encrypt_block(encrypted_block);
            size_t block_len = std::min(size_t(16), plaintext.size() - i*16);
            for (size_t j=0;j<block_len;++j)
                ciphertext[i*16+j] = plaintext[i*16+j] ^ encrypted_block[j];
        }
        // tag = HMAC_SHA256(key, ciphertext || iv)
        std::vector<uint8_t> hmac_input = ciphertext;
        hmac_input.insert(hmac_input.end(), iv.begin(), iv.end());
        std::vector<uint8_t> tag = hmac_sha256(key, hmac_input);
        return {ciphertext, tag};
    }

    // Decrypt and verify tag, throw if tag mismatch
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext,
                                 const std::vector<uint8_t> &iv,
                                 const std::vector<uint8_t> &tag) {
        if (iv.size() != 16) throw std::runtime_error("AES-GCM simplified: IV must be 16 bytes");
        std::vector<uint8_t> hmac_input = ciphertext;
        hmac_input.insert(hmac_input.end(), iv.begin(), iv.end());
        std::vector<uint8_t> expected_tag = hmac_sha256(key, hmac_input);
        if (tag.size() != expected_tag.size() ||
            !std::equal(tag.begin(), tag.end(), expected_tag.begin()))
            throw std::runtime_error("AES-GCM simplified: tag mismatch");

        // decrypt same as encrypt
        std::vector<uint8_t> plaintext(ciphertext.size());
        size_t blocks = (ciphertext.size() + 15)/16;
        for (size_t i=0;i<blocks;++i) {
            std::vector<uint8_t> ctr_block = iv;
            uint32_t ctr = (uint32_t)i;
            ctr_block[12] = (ctr >> 24) & 0xff;
            ctr_block[13] = (ctr >> 16) & 0xff;
            ctr_block[14] = (ctr >> 8) & 0xff;
            ctr_block[15] = ctr & 0xff;
            uint8_t encrypted_block[16];
            memcpy(encrypted_block, ctr_block.data(), 16);
            aes.encrypt_block(encrypted_block);
            size_t block_len = std::min(size_t(16), ciphertext.size() - i*16);
            for (size_t j=0;j<block_len;++j)
                plaintext[i*16+j] = ciphertext[i*16+j] ^ encrypted_block[j];
        }
        return plaintext;
    }
};
}
