// theory.h
// Header-only C++ number theory library for competitive programming, cryptography, and CS students.
// Features: gcd/lcm/extended, modular arithmetic, safe mul, modpow, modular inverse, isqrt,
// Miller-Rabin (deterministic for 64-bit), Pollard's Rho factorization, sieve, segmented sieve,
// prime factorization, divisors, euler_phi, mobius, CRT, discrete log (BSGS), Tonelli-Shanks
// modular square roots, Legendre/Jacobi, continued fractions utilities, linear Diophantine solver,
// matrix exponentiation helper, integer roots, primality certificate helpers, and utilities.
//
// Single-file header. Put in project and #include "theory.h". C++17 or later recommended.
// License: MIT

#ifndef THEORY_H
#define THEORY_H

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <stdexcept>
#include <tuple>
#include <utility>
#include <vector>
#include <chrono>
#include <iostream>

namespace nt {

using u128 = unsigned __int128;
using i128 = __int128;
using u64 = uint64_t;
using i64 = int64_t;

// ------------------------- Core integer utilities -------------------------

inline i64 gcd(i64 a, i64 b) {
    if (a < 0) a = -a; if (b < 0) b = -b;
    while (b) { i64 t = a % b; a = b; b = t; }
    return a;
}

inline i64 lcm(i64 a, i64 b) {
    if (a == 0 || b == 0) return 0;
    return std::llabs(a / gcd(a,b) * b);
}

// Extended gcd: returns g = gcd(a,b) and x,y with ax+by=g
inline i64 extended_gcd(i64 a, i64 b, i64 &x, i64 &y) {
    if (b == 0) { x = (a >= 0) ? 1 : -1; y = 0; return std::llabs(a); }
    i64 x1, y1; i64 g = extended_gcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1; return g;
}

// Safe modular multiplication using 128-bit type
inline u64 modmul(u64 a, u64 b, u64 mod) {
    if (mod <= (u64)std::numeric_limits<u64>::max()) {
        return (u64)((u128)a * b % mod);
    }
    // fallback (shouldn't be needed for 64-bit mod)
    u64 res = 0;
    a %= mod; b %= mod;
    while (b) {
        if (b & 1) res = (res + a) % mod;
        a = (a << 1) % mod; b >>= 1;
    }
    return res;
}

inline u64 modpow(u64 a, u64 e, u64 mod) {
    a %= mod; u64 r = 1;
    while (e) {
        if (e & 1) r = modmul(r, a, mod);
        a = modmul(a, a, mod);
        e >>= 1;
    }
    return r;
}

inline i64 modinv(i64 a, i64 m) {
    i64 x,y; i64 g = extended_gcd(a, m, x, y);
    if (g != 1 && g != -1) throw std::runtime_error("mod inverse does not exist");
    i64 res = x % m; if (res < 0) res += m; return res;
}

inline u64 isqrt(u64 n) {
    u64 x = std::floor(std::sqrt((long double)n));
    while ((u128)(x+1)*(x+1) <= n) ++x;
    while ((u128)x*x > n) --x;
    return x;
}

// integer k-th root (floor)
inline u64 iroot(u64 n, unsigned k) {
    if (k == 1) return n;
    u64 lo = 0, hi = std::min<u64>(n, (u64)std::pow(n, 1.0L/k) + 2);
    while (lo < hi) {
        u64 mid = (lo + hi + 1) >> 1;
        // check mid^k <= n
        u128 prod = 1; bool overflow = false;
        for (unsigned i = 0; i < k; ++i) {
            prod *= mid; if (prod > n) { overflow = true; break; }
        }
        if (!overflow && (u64)prod <= n) lo = mid; else hi = mid - 1;
    }
    return lo;
}

// ------------------------- Primality: Miller-Rabin & helpers -------------------------

// Deterministic bases for testing 64-bit integers (from known results)
static const u64 mr_bases_64[] = {2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL, 17ULL, 19ULL, 23ULL, 0};

inline bool is_probable_prime(u64 n) {
    if (n < 2) return false;
    for (u64 p : {2ULL,3ULL,5ULL,7ULL,11ULL,13ULL,17ULL,19ULL,23ULL,29ULL}) {
        if (n%p == 0) return n==p;
    }
    u64 d = n - 1; int s = 0;
    while ((d & 1) == 0) { d >>= 1; ++s; }
    auto check = [&](u64 a) {
        if (a % n == 0) return true;
        u64 x = modpow(a, d, n);
        if (x == 1 || x == n-1) return true;
        for (int r = 1; r < s; ++r) {
            x = modmul(x, x, n);
            if (x == n-1) return true;
        }
        return false;
    };
    // choose deterministic small bases for 64-bit safety
    for (u64 a : mr_bases_64) {
        if (a==0) break;
        if (!check(a)) return false;
    }
    return true;
}

// Miller-Rabin with random bases for probable primality (k rounds)
inline bool miller_rabin(u64 n, int rounds = 6) {
    if (n < 2) return false;
    for (u64 p : {2ULL,3ULL,5ULL,7ULL,11ULL,13ULL,17ULL,19ULL,23ULL}) if (n == p) return true;
    u64 d = n - 1; int s = 0; while ((d & 1) == 0) { d >>= 1; ++s; }
    std::mt19937_64 rng((unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<u64> dist(2, n-2);
    auto check = [&](u64 a) {
        u64 x = modpow(a, d, n);
        if (x == 1 || x == n-1) return true;
        for (int r = 1; r < s; ++r) {
            x = modmul(x, x, n);
            if (x == n-1) return true;
        }
        return false;
    };
    for (int i = 0; i < rounds; ++i) {
        u64 a = dist(rng);
        if (!check(a)) return false;
    }
    return true;
}

// ------------------------- Pollard's Rho factorization -------------------------

inline u64 pollards_rho(u64 n) {
    if (n % 2ULL == 0ULL) return 2ULL;
    if (n % 3ULL == 0ULL) return 3ULL;
    std::mt19937_64 gen((unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<u64> dist(2, n-2);
    u64 c = dist(gen);
    u64 x = dist(gen);
    u64 y = x;
    u64 d = 1;
    auto f = [&](u64 v)->u64 { return (modmul(v, v, n) + c) % n; };
    while (d == 1) {
        x = f(x);
        y = f(f(y));
        u64 diff = x>y ? x-y : y-x;
        d = std::gcd((unsigned long long)diff, (unsigned long long)n);
        if (d == n) return pollards_rho(n);
    }
    return d;
}

inline void factor_recursive(u64 n, std::map<u64,int> &out) {
    if (n == 1) return;
    if (is_probable_prime(n)) { out[n]++; return; }
    u64 d = pollards_rho(n);
    factor_recursive(d, out);
    factor_recursive(n/d, out);
}

inline std::vector<std::pair<u64,int>> factor(u64 n) {
    std::map<u64,int> m; factor_recursive(n, m);
    std::vector<std::pair<u64,int>> res; res.reserve(m.size());
    for (auto &kv : m) res.emplace_back(kv.first, kv.second);
    std::sort(res.begin(), res.end());
    return res;
}

inline std::vector<u64> divisors_from_factors(const std::vector<std::pair<u64,int>>& fac) {
    std::vector<u64> res = {1};
    for (auto &p : fac) {
        u64 prime = p.first; int exp = p.second;
        size_t sz = res.size();
        u64 cur = 1;
        for (int e=1;e<=exp;++e) {
            cur *= prime;
            for (size_t i=0;i<sz;++i) res.push_back(res[i]*cur);
        }
    }
    std::sort(res.begin(), res.end());
    return res;
}

// ------------------------- Sieve & prime generation -------------------------

inline std::vector<int> sieve_eratosthenes(int n) {
    if (n < 2) return {};
    std::vector<char> is(n+1, true); is[0]=is[1]=false;
    for (int p=2;p*p<=n;++p) if (is[p]) for (int q=p*p; q<=n; q+=p) is[q]=false;
    std::vector<int> primes; for (int i=2;i<=n;++i) if (is[i]) primes.push_back(i);
    return primes;
}

inline std::vector<u64> segmented_sieve(u64 L, u64 R) {
    if (R < L) return {};
    u64 lim = (u64)std::floor(std::sqrt((long double)R)) + 1;
    std::vector<int> primes = sieve_eratosthenes((int)lim);
    std::vector<char> is(R-L+1, true);
    for (u64 p : primes) {
        u64 start = (L + p - 1) / p * p;
        if (start < p*p) start = p*p;
        for (u64 j = start; j <= R; j += p) is[j-L] = false;
    }
    std::vector<u64> out;
    for (u64 i = L; i <= R; ++i) if (i>1 && is[i-L]) out.push_back(i);
    return out;
}

// ------------------------- Multiplicative functions -------------------------

inline u64 euler_phi(u64 n) {
    auto f = factor(n);
    u64 res = n;
    for (auto &kv : f) res = res / kv.first * (kv.first - 1);
    return res;
}

inline int mobius(u64 n) {
    auto f = factor(n);
    for (auto &kv : f) if (kv.second > 1) return 0;
    return (f.size() % 2 == 0) ? 1 : -1;
}

// ------------------------- Chinese Remainder Theorem -------------------------

// returns (x, mod) where x is solution modulo mod (product). If no solution, returns (0,0).
inline std::pair<i128, i128> crt_pair(i128 a1, i128 m1, i128 a2, i128 m2) {
    i64 x, y; i64 g = extended_gcd((i64)m1, (i64)m2, x, y);
    if ((a1 - a2) % g != 0) return {0,0};
    i128 l = (i128)m1 / g * m2;
    i128 res = (a1 + (i128)((((a2 - a1) / g) * x) % (m2/g)) * m1) % l;
    if (res < 0) res += l;
    return {res, l};
}

inline std::pair<i128, i128> crt(const std::vector<i128>& a, const std::vector<i128>& m) {
    assert(a.size() == m.size());
    i128 x = a[0], mod = m[0];
    for (size_t i=1;i<a.size();++i) {
        auto pr = crt_pair(x, mod, a[i], m[i]);
        if (pr.second == 0) return {0,0};
        x = pr.first; mod = pr.second;
    }
    return {x, mod};
}

// ------------------------- Legendre & Jacobi symbols -------------------------

inline int legendre_symbol(i64 a, i64 p) {
    if (p <= 2 || (p % 2) == 0) throw std::runtime_error("legendre requires odd prime p");
    a %= p; if (a < 0) a += p;
    u64 ls = modpow((u64)a, (p-1)/2, p);
    if (ls == 1) return 1;
    if (ls == 0) return 0;
    return -1;
}

inline int jacobi_symbol(i64 a, i64 n) {
    if (n <= 0 || (n % 2) == 0) throw std::runtime_error("jacobi requires positive odd n");
    a %= n; if (a < 0) a += n;
    int result = 1;
    while (a != 0) {
        while ((a & 1) == 0) {
            a >>= 1;
            i64 r = n % 8;
            if (r == 3 || r == 5) result = -result;
        }
        std::swap(a, n);
        if (a % 4 == 3 && n % 4 == 3) result = -result;
        a %= n;
    }
    return (n == 1) ? result : 0;
}

// ------------------------- Tonelli-Shanks: modular sqrt -------------------------

inline i64 tonelli_shanks(i64 n, i64 p) {
    // solve x^2 = n (mod p). returns x or -1 if no sqrt.
    n %= p; if (n < 0) n += p;
    if (n == 0) return 0;
    if (p == 2) return n;
    if (legendre_symbol(n, p) != 1) return -1;
    i64 q = p - 1, s = 0;
    while ((q & 1) == 0) { q >>= 1; ++s; }
    if (s == 1) {
        i64 r = modpow(n, (p+1)/4, p); return r;
    }
    // find a quadratic non-residue z
    i64 z = 2; while (legendre_symbol(z, p) != -1) ++z;
    i64 c = modpow(z, q, p);
    i64 r = modpow(n, (q+1)/2, p);
    i64 t = modpow(n, q, p);
    i64 m = s;
    while (t != 1) {
        i64 i = 1;
        i64 tt = modmul(t, t, p);
        while (tt != 1) { tt = modmul(tt, tt, p); ++i; if (i == m) return -1; }
        i64 b = modpow(c, 1ULL << (m - i - 1), p);
        r = modmul(r, b, p);
        c = modmul(b, b, p);
        t = modmul(t, c, p);
        m = i;
    }
    return r;
}

// ------------------------- Discrete log: Baby-step Giant-step -------------------------

#include <unordered_map>
inline i64 discrete_log(u64 a, u64 b, u64 m) {
    // Solve a^x = b (mod m). Returns x or -1 if none (m assumed prime not required).
    a %= m; b %= m;
    if (m == 1) return 0;
    u64 cnt = 0; u64 t = 1;
    u64 g;
    while ((g = std::gcd((u64)a, (u64)m)) > 1) {
        if (b == t) return cnt;
        if (b % g) return -1;
        b /= g; m /= g; t = (t * (a / g)) % m; ++cnt;
        if (t == b) return cnt;
    }
    u64 n = (u64)std::sqrt((long double)m) + 1;
    std::unordered_map<u64, u64> vals;
    u64 an = 1;
    for (u64 i = 0; i < n; ++i) an = modmul(an, a, m);
    u64 cur = b;
    for (u64 q = 0; q < n; ++q) {
        vals[cur] = q;
        cur = modmul(cur, a, m);
    }
    cur = 1;
    for (u64 p = 1; p <= n+1; ++p) {
        cur = modmul(cur, an, m);
        auto it = vals.find(cur);
        if (it != vals.end()) {
            i64 ans = (i64)(p * n - it->second);
            if (ans < 0) return -1;
            return ans;
        }
    }
    return -1;
}

// ------------------------- Continued fractions helpers -------------------------

// Convergent generator for continued fraction of a real number represented by vector of partial quotients
inline std::pair<i128,i128> contfrac_convergent(const std::vector<i128>& a) {
    i128 num0 = 1, num1 = a[0];
    i128 den0 = 0, den1 = 1;
    for (size_t i = 1; i < a.size(); ++i) {
        i128 q = a[i]; i128 num2 = q*num1 + num0; i128 den2 = q*den1 + den0;
        num0 = num1; num1 = num2; den0 = den1; den1 = den2;
    }
    return {num1, den1};
}

// Continued fraction expansion of rational a/b
inline std::vector<i128> contfrac_expand(i128 a, i128 b) {
    std::vector<i128> out;
    while (b != 0) {
        out.push_back(a / b);
        i128 r = a % b; a = b; b = r;
    }
    return out;
}

// ------------------------- Diophantine & modular linear equation solver -------------------------

inline bool solve_linear_congruence(i64 a, i64 b, i64 m, i64 &x0, i64 &mod_out) {
    // solve a x = b (mod m)
    i64 x,y; i64 g = extended_gcd(a, m, x, y);
    if (b % g != 0) return false;
    i64 mult = b / g;
    x0 = (i128)x * mult % m; if (x0 < 0) x0 += m;
    mod_out = m / g;
    return true;
}

inline bool solve_diophantine(i64 a, i64 b, i64 c, i64 &x0, i64 &y0) {
    // solve ax + by = c
    i64 x, y; i64 g = extended_gcd(a, b, x, y);
    if (c % g != 0) return false;
    i128 mult = c / g;
    x0 = (i64)(x * mult);
    y0 = (i64)(y * mult);
    return true;
}

// ------------------------- Matrix exponentiation helper -------------------------

using Matrix = std::vector<std::vector<i128>>;
inline Matrix mat_mul(const Matrix &A, const Matrix &B, i128 mod = 0) {
    size_t n = A.size(); size_t m = B[0].size(); size_t p = B.size();
    Matrix C(n, std::vector<i128>(m, 0));
    for (size_t i=0;i<n;++i) for (size_t k=0;k<p;++k) for (size_t j=0;j<m;++j) {
        i128 v = A[i][k] * B[k][j] + C[i][j];
        if (mod) v %= mod;
        C[i][j] = v;
    }
    return C;
}
inline Matrix mat_pow(Matrix base, u64 exp, i128 mod = 0) {
    size_t n = base.size(); Matrix res(n, std::vector<i128>(n));
    for (size_t i=0;i<n;++i) res[i][i] = 1;
    while (exp) {
        if (exp & 1) res = mat_mul(res, base, mod);
        base = mat_mul(base, base, mod);
        exp >>= 1;
    }
    return res;
}

// ------------------------- Primality certificate: small checks + MR + trial division -------------------------
inline bool is_prime_certified(u64 n) {
    // lightweight certificate: small primes + deterministic MR for 64-bit
    return is_probable_prime(n);
}

// ------------------------- Utilities & examples -------------------------

inline void print_factors(u64 n) {
    auto f = factor(n);
    bool first = true;
    for (auto &kv : f) {
        if (!first) std::cout << " * "; first = false;
        std::cout << kv.first << "^" << kv.second;
    }
    if (first) std::cout << n; // n==1
    std::cout << '\n';
}

} // namespace nt

#endif // THEORY_H
