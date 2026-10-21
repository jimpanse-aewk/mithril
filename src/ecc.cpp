// ecc.cpp — minimal in-tree elliptic-curve arithmetic. See ecc.hpp.
#include "ecc.hpp"

#include <array>

namespace ft {

namespace {

// hex (big-endian) -> BigUint. Authoring-time constants only; skips non-hex.
BigUint from_hex(const char* h) {
    std::vector<uint8_t> bytes;
    int hi = -1;
    for (const char* q = h; *q; ++q) {
        int v;
        if (*q >= '0' && *q <= '9') v = *q - '0';
        else if (*q >= 'a' && *q <= 'f') v = *q - 'a' + 10;
        else if (*q >= 'A' && *q <= 'F') v = *q - 'A' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { bytes.push_back(uint8_t((hi << 4) | v)); hi = -1; }
    }
    return BigUint::from_be(bytes);
}

// The curves mithril's pubkey extractor can name. a = p-3 for the NIST curves,
// a = 0 for secp256k1. Standard domain parameters (SEC 2 / FIPS 186-4).
const std::array<EcCurve, 4>& curves() {
    static const std::array<EcCurve, 4> tbl = {{
        {"secp256r1", 32,
         from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
         from_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
         from_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
         from_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
         from_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")},
        {"secp384r1", 48,
         from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                  "ffffffff0000000000000000ffffffff"),
         from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                  "ffffffff0000000000000000fffffffc"),
         from_hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
                  "c656398d8a2ed19d2a85c8edd3ec2aef"),
         from_hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
                  "5502f25dbf55296c3a545e3872760ab7"),
         from_hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
                  "0a60b1ce1d7e819d7a431d7c90ea0e5f")},
        {"secp521r1", 66,
         from_hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
         from_hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc"),
         from_hex("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
                  "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
         from_hex("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
                  "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
         from_hex("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
                  "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")},
        {"secp256k1", 32,
         from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
         from_hex("0000000000000000000000000000000000000000000000000000000000000000"),
         from_hex("0000000000000000000000000000000000000000000000000000000000000007"),
         from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
         from_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")},
    }};
    return tbl;
}

// ---- field arithmetic mod p (operands kept reduced in [0,p)) ----------------
//
// The small-scalar search does ~10 modular multiplications per point addition over
// the whole search bound, so the reduction must not be the bit-by-bit divmod in
// BigUint (that turned a single healthy-key miss into minutes). Barrett reduction
// precomputes mu = floor(2^(2k) / p) once per curve, then reduces a product with
// two multiplications and at most a few subtractions — no division in the hot loop
// and no change to the shared BigUint.
struct Field {
    const BigUint& p;
    size_t k;     // bit length of p
    BigUint mu;   // floor(2^(2k) / p)

    explicit Field(const BigUint& modulus) : p(modulus), k(modulus.bit_length()) {
        BigUint r2 = BigUint(1).shl_bits(2 * k);  // 2^(2k)
        BigUint q, rem;
        r2.divmod(p, q, rem);  // one divmod, at construction
        mu = q;
    }

    // Reduce x (x < 2^(2k), i.e. any product of two field elements) into [0,p).
    BigUint reduce(const BigUint& x) const {
        if (BigUint::cmp(x, p) < 0) return x;
        // Barrett is valid only for x < 2^(2k); anything larger (a malformed
        // oversized coordinate reaching here) falls back to exact division so the
        // correction loop below can never spin. Callers keep inputs in range.
        if (x.bit_length() > 2 * k) return x % p;
        BigUint q1 = x.shr_bits(k - 1);
        BigUint q3 = (q1 * mu).shr_bits(k + 1);
        BigUint r = x - q3 * p;  // x - q3*p, within a few p of the result
        for (int i = 0; i < 6 && BigUint::cmp(r, p) >= 0; ++i) r = r - p;  // ~2 expected
        if (BigUint::cmp(r, p) >= 0) r = r % p;  // guaranteed exit (never expected)
        return r;
    }

    BigUint add(const BigUint& x, const BigUint& y) const {
        BigUint r = x + y;
        if (BigUint::cmp(r, p) >= 0) r = r - p;  // x,y < p -> r < 2p
        return r;
    }
    BigUint sub(const BigUint& x, const BigUint& y) const {
        return (BigUint::cmp(x, y) >= 0) ? x - y : (x + p) - y;  // x,y < p
    }
    BigUint mul(const BigUint& x, const BigUint& y) const { return reduce(x * y); }
    BigUint sqr(const BigUint& x) const { return reduce(x * x); }
};

// Jacobian point (X:Y:Z) representing affine (X/Z^2, Y/Z^3); Z==0 is infinity.
struct Jac {
    BigUint X, Y, Z;
    bool inf() const { return Z.is_zero(); }
};

const BigUint kTwo(2), kThree(3), kFour(4), kEight(8);

// Point doubling (dbl-2007-bl: works for any curve coefficient a).
Jac dbl(const Field& f, const BigUint& a, const Jac& P) {
    if (P.inf() || P.Y.is_zero()) return {BigUint(), BigUint(), BigUint()};
    BigUint XX = f.sqr(P.X);
    BigUint YY = f.sqr(P.Y);
    BigUint YYYY = f.sqr(YY);
    BigUint ZZ = f.sqr(P.Z);
    BigUint S = f.mul(kTwo, f.sub(f.sub(f.sqr(f.add(P.X, YY)), XX), YYYY));
    BigUint M = f.add(f.mul(kThree, XX), f.mul(a, f.sqr(ZZ)));
    BigUint T = f.sub(f.sqr(M), f.mul(kTwo, S));
    Jac R;
    R.X = T;
    R.Y = f.sub(f.mul(M, f.sub(S, T)), f.mul(kEight, YYYY));
    R.Z = f.sub(f.sub(f.sqr(f.add(P.Y, P.Z)), YY), ZZ);
    return R;
}

// Mixed addition P(Jacobian) + Q(affine x2,y2) (madd-2007-bl); falls back to
// doubling when P == Q, returns infinity when P == -Q.
Jac madd(const Field& f, const BigUint& a, const Jac& P, const BigUint& x2, const BigUint& y2) {
    if (P.inf()) return {x2, y2, BigUint(1)};
    BigUint Z1Z1 = f.sqr(P.Z);
    BigUint U2 = f.mul(x2, Z1Z1);
    BigUint S2 = f.mul(f.mul(y2, P.Z), Z1Z1);
    BigUint H = f.sub(U2, P.X);
    BigUint rr = f.sub(S2, P.Y);
    if (H.is_zero()) {
        if (rr.is_zero()) return dbl(f, a, P);
        return {BigUint(), BigUint(), BigUint()};  // P == -Q
    }
    BigUint HH = f.sqr(H);
    BigUint I = f.mul(kFour, HH);
    BigUint J = f.mul(H, I);
    BigUint r = f.mul(kTwo, rr);
    BigUint V = f.mul(P.X, I);
    Jac R;
    R.X = f.sub(f.sub(f.sqr(r), J), f.mul(kTwo, V));
    R.Y = f.sub(f.mul(r, f.sub(V, R.X)), f.mul(kTwo, f.mul(P.Y, J)));
    R.Z = f.sub(f.sub(f.sqr(f.add(P.Z, H)), Z1Z1), HH);
    return R;
}

// True if Jacobian P equals affine (x,y) — cross-multiplication, no inverse.
bool jac_eq_affine(const Field& f, const Jac& P, const BigUint& x, const BigUint& y) {
    if (P.inf()) return false;  // Q is a real affine point
    BigUint Z2 = f.sqr(P.Z);
    BigUint Z3 = f.mul(Z2, P.Z);
    return f.mul(x, Z2) == P.X && f.mul(y, Z3) == P.Y;
}

}  // namespace

const EcCurve* ec_curve_by_name(const std::string& name) {
    std::string n = name;
    // Accept the OpenSSH wire names too.
    if (n == "nistp256") n = "secp256r1";
    else if (n == "nistp384") n = "secp384r1";
    else if (n == "nistp521") n = "secp521r1";
    else if (n == "prime256v1") n = "secp256r1";
    for (const auto& c : curves())
        if (c.name == n) return &c;
    return nullptr;
}

namespace {
bool on_curve(const Field& f, const BigUint& a, const BigUint& b, const BigUint& x,
              const BigUint& y) {
    BigUint lhs = f.sqr(y);                                     // y^2
    BigUint rhs = f.add(f.add(f.mul(f.sqr(x), x), f.mul(a, x)), b);  // x^3 + a x + b
    return lhs == rhs;
}
}  // namespace

bool ec_point_on_curve(const EcCurve& c, std::span<const uint8_t> x_be,
                       std::span<const uint8_t> y_be) {
    Field f(c.p);
    return on_curve(f, c.a, c.b, f.reduce(BigUint::from_be(x_be)),
                    f.reduce(BigUint::from_be(y_be)));
}

bool ec_recover_small_scalar(const EcCurve& c, std::span<const uint8_t> x_be,
                             std::span<const uint8_t> y_be, uint64_t limit, uint64_t& d_out) {
    if (limit == 0) return false;
    Field f(c.p);  // precomputes the Barrett modulus once for this key
    BigUint qx = f.reduce(BigUint::from_be(x_be));
    BigUint qy = f.reduce(BigUint::from_be(y_be));
    // Not on the curve -> no scalar can produce it; skip the (then meaningless) walk.
    if (!on_curve(f, c.a, c.b, qx, qy)) return false;

    Jac R{BigUint(), BigUint(), BigUint()};  // infinity (0*G)
    for (uint64_t d = 1; d <= limit; ++d) {
        R = madd(f, c.a, R, c.gx, c.gy);  // R = d*G
        if (jac_eq_affine(f, R, qx, qy)) { d_out = d; return true; }
    }
    return false;
}

}  // namespace ft
