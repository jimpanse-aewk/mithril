// ecc.hpp — minimal in-tree elliptic-curve arithmetic for the key-weakness pass.
//
// The EC analog of keyweak.hpp's RSA checks. keyweak answers "is this RSA key's
// private half obtainable" (ROCA / Fermat / Wiener / undersized modulus); this
// module answers the same question for a short-Weierstrass EC public key, where
// the dominant real-world failure is a catastrophically small private scalar —
// the key is generated as d*G for a tiny integer d, so d is recoverable by a
// bounded search d = 1,2,3,... comparing d*G to the public point Q. This is the
// October 2026 eMudhra intermediate-CA compromise (P-384 scalars 4..237), and
// the general "broken RNG produced a near-zero scalar" class.
//
// All arithmetic is over the in-tree BigUint (zero dependency, like sha256/
// inflate/bigint). The small-scalar search accumulates Q candidates in Jacobian
// coordinates so no modular inverse runs in the hot loop; the point comparison is
// a cross-multiplication. Only the ops the checks need — no general ECC.
#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "bigint.hpp"

namespace ft {

// A named short-Weierstrass curve y^2 = x^3 + a*x + b over GF(p), generator G.
struct EcCurve {
    std::string name;    // "secp384r1" / "secp256r1" / "secp521r1" / "secp256k1"
    size_t field_bytes;  // size of one coordinate (48 for P-384, ...)
    BigUint p, a, b, gx, gy;
};

// Look up a curve by the name pubkey.cpp records (secp256r1/secp384r1/secp521r1/
// secp256k1, or the OpenSSH wire names nistp256/384/521). Returns nullptr if the
// curve is not one we carry parameters for.
const EcCurve* ec_curve_by_name(const std::string& name);

// True if the affine point (x,y) satisfies the curve equation mod p. x and y are
// big-endian, already reduced into [0,p). A point that is not on the curve is a
// malformed key, and the small-scalar search is not meaningful for it.
bool ec_point_on_curve(const EcCurve& c, std::span<const uint8_t> x_be,
                       std::span<const uint8_t> y_be);

// Bounded small-scalar recovery: if the public point Q = (x,y) equals d*G for some
// 1 <= d <= limit, set d_out and return true. A false return means "not found
// within the bound", never "secure". Work is O(limit) point additions, each a few
// field multiplications (no modular inverse), so limit caps the cost; the caller
// keeps limit modest (a legitimate 384-bit scalar is astronomically larger than
// any feasible bound, so a hit is proof of a broken key, not a lucky guess).
bool ec_recover_small_scalar(const EcCurve& c, std::span<const uint8_t> x_be,
                             std::span<const uint8_t> y_be, uint64_t limit,
                             uint64_t& d_out);

}  // namespace ft
