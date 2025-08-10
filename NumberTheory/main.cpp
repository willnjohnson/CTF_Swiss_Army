// main.cpp — test program for theory.h
// Make sure your header file is available as "theory.h" in the same directory.

#include "theory.h"
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>

using namespace nt;

// Helper: convert i128 to string for printing
static std::string i128_to_string(i128 v) {
    if (v == 0) return "0";
    bool neg = v < 0;
    unsigned __int128 uv = neg ? (unsigned __int128)(-v) : (unsigned __int128)v;
    std::string s;
    while (uv) {
        int d = (int)(uv % 10);
        s.push_back(char('0' + d));
        uv /= 10;
    }
    if (neg) s.push_back('-');
    std::reverse(s.begin(), s.end());
    return s;
}

// Pretty-print for factor pairs (prime^exp)
std::ostream& operator<<(std::ostream& os, const std::pair<uint64_t,int>& p) {
    os << p.first << "^" << p.second;
    return os;
}

// Simple vector printer
template<class T>
void print_vec(const std::vector<T>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) std::cout << ' ';
        std::cout << v[i];
    }
    std::cout << '\n';
}

int main() {
    // Basic integer utilities
    uint64_t a = 1071, b = 462;
    std::cout << "gcd(" << a << ", " << b << ") = " << gcd((i64)a, (i64)b) << "\n";
    std::cout << "lcm(" << a << ", " << b << ") = " << lcm((i64)a, (i64)b) << "\n";

    i64 x = 0, y = 0;
    i64 g = extended_gcd((i64)a, (i64)b, x, y);
    std::cout << "extended_gcd: gcd = " << g << ", x = " << x << ", y = " << y << "\n";

    // Modular arithmetic
    uint64_t mod = 1000000007ULL;
    std::cout << "modpow(2,10,mod) = " << modpow(2, 10, mod) << "\n";
    std::cout << "modinv(3,mod) = " << modinv(3, (i64)mod) << "\n";

    // Primality
    uint64_t prime_test = 104729;
    std::cout << prime_test << " is_probable_prime? " << (is_probable_prime(prime_test) ? "yes" : "no") << "\n";
    std::cout << prime_test << " is_prime_certified? " << (is_prime_certified(prime_test) ? "yes" : "no") << "\n";

    // Factorization & multiplicative functions
    uint64_t composite = 600851475143ULL;
    std::cout << "factor(" << composite << ") = ";
    auto facs = factor(composite);
    for (size_t i = 0; i < facs.size(); ++i) {
        if (i) std::cout << " * ";
        std::cout << facs[i];
    }
    std::cout << "\n";

    std::cout << "euler_phi(" << composite << ") = " << euler_phi(composite) << "\n";
    std::cout << "mobius(" << composite << ") = " << mobius(composite) << "\n";

    // Sieve examples
    std::cout << "primes up to 50: ";
    auto primes50 = sieve_eratosthenes(50);
    print_vec(primes50);

    std::cout << "primes in [100,150]: ";
    auto seg = segmented_sieve(100,150);
    print_vec(seg);

    // Chinese Remainder: x ≡ 2 (mod 3), x ≡ 3 (mod 5) -> x ≡ 8 (mod 15)
    i128 a1 = 2, m1 = 3, a2 = 3, m2 = 5;
    auto crt_res = crt(std::vector<i128>{a1, a2}, std::vector<i128>{m1, m2});
    std::cout << "CRT solution: x = " << i128_to_string(crt_res.first) << " (mod " << i128_to_string(crt_res.second) << ")\n";

    // Legendre & Tonelli-Shanks
    int leg = legendre_symbol(5, 29);
    std::cout << "Legendre(5,29) = " << leg << "\n";
    i64 root = tonelli_shanks(5,29);
    if (root == -1) std::cout << "No square root of 5 mod 29\n";
    else std::cout << "Square roots of 5 mod 29: " << root << " and " << (29 - root) << "\n";

    // Continued fraction expansion of 355/113 (approximation to pi)
    auto cf = contfrac_expand((i128)355, (i128)113);
    std::cout << "continued fraction of 355/113: ";
    for (auto &q : cf) std::cout << i128_to_string(q) << " ";
    std::cout << "\n";

    // Discrete log: 5^x ≡ 8 (mod 23)
    i64 dlog = discrete_log(5, 8, 23);
    std::cout << "discrete_log: 5^x = 8 (mod 23) -> x = " << dlog << "\n";

    // Solve linear congruence: 14 x ≡ 30 (mod 100)
    i64 x0, mod_out;
    bool has_sol = solve_linear_congruence(14, 30, 100, x0, mod_out);
    if (has_sol) std::cout << "Solutions to 14 x ≡ 30 (mod 100): x ≡ " << x0 << " (mod " << mod_out << ")\n";
    else std::cout << "No solution to 14 x ≡ 30 (mod 100)\n";

    // Diophantine: 15 x + 25 y = 100
    i64 y0;
    if (solve_diophantine(15, 25, 100, x0, y0)) std::cout << "Diophantine solution: x = " << x0 << ", y = " << y0 << "\n";
    else std::cout << "No integer solution to 15 x + 25 y = 100\n";

    // Matrix exponentiation example (Fibonacci): [[1,1],[1,0]]^10
    Matrix fib_base = {{(i128)1,(i128)1},{(i128)1,(i128)0}};
    Matrix fib_pow = mat_pow(fib_base, 10);
    std::cout << "Fibonacci F(10) (from matrix) = " << i128_to_string(fib_pow[0][1]) << "\n";

    std::cout << "All tests complete.\n";
    return 0;
}
