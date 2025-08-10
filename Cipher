#!/usr/bin/env python3
"""
cipher.py - CTF-friendly cipher suite
Provides encode/decode functions for common classical ciphers:
- Caesar
- Vigenère
- Atbash
- ROT13
- Base64
- Morse Code
"""

import base64
import string

# -----------------
# Caesar Cipher
# -----------------
def caesar_encrypt(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            alpha = string.ascii_uppercase if ch.isupper() else string.ascii_lowercase
            result.append(alpha[(alpha.index(ch) + shift) % 26])
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# -----------------
# Vigenère Cipher
# -----------------
def vigenere_encrypt(text, key):
    result = []
    key = key.lower()
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            alpha = string.ascii_uppercase if ch.isupper() else string.ascii_lowercase
            shift = ord(key[key_idx % len(key)]) - ord('a')
            result.append(alpha[(alpha.index(ch) + shift) % 26])
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decrypt(text, key):
    result = []
    key = key.lower()
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            alpha = string.ascii_uppercase if ch.isupper() else string.ascii_lowercase
            shift = ord(key[key_idx % len(key)]) - ord('a')
            result.append(alpha[(alpha.index(ch) - shift) % 26])
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

# -----------------
# Atbash Cipher
# -----------------
def atbash(text):
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        elif ch.islower():
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            result.append(ch)
    return ''.join(result)

# -----------------
# ROT13 (special case of Caesar)
# -----------------
def rot13(text):
    return caesar_encrypt(text, 13)

# -----------------
# Base64 Encode/Decode
# -----------------
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(text):
    return base64.b64decode(text.encode()).decode()

# -----------------
# Morse Code
# -----------------
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.',  'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-',  'L': '.-..', 'M': '--',  'N': '-.',  'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-',  'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', 
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '&': '.-...', "'": '.----.', '@': '.--.-.', ')': '-.--.-', '(': '-.--.',
    ':': '---...', ',': '--..--', '=': '-...-', '!': '-.-.--', '.': '.-.-.-', 
    '-': '-....-', '+': '.-.-.', '"': '.-..-.', '?': '..--..', '/': '-..-.'
}
INV_MORSE_CODE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

def morse_encode(text):
    return ' '.join(MORSE_CODE_DICT.get(ch.upper(), '') for ch in text)

def morse_decode(code):
    return ''.join(INV_MORSE_CODE_DICT.get(c, '') for c in code.split(' '))

# -----------------
# Quick demo when run directly
# -----------------
if __name__ == "__main__":
    sample = "Hello World"
    print("Caesar(+3):", caesar_encrypt(sample, 3))
    print("Caesar Decoded:", caesar_decrypt(caesar_encrypt(sample, 3), 3))
    print("Vigenere(KEY):", vigenere_encrypt(sample, "KEY"))
    print("Vigenere Decoded:", vigenere_decrypt(vigenere_encrypt(sample, "KEY"), "KEY"))
    print("Atbash:", atbash(sample))
    print("ROT13:", rot13(sample))
    print("Base64 Encoded:", base64_encode(sample))
    print("Base64 Decoded:", base64_decode(base64_encode(sample)))
    print("Morse Encoded:", morse_encode(sample))
    print("Morse Decoded:", morse_decode(morse_encode(sample)))
