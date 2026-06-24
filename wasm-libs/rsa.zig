const std = @import("std");
const bi = @import("bigint.zig");
const key = @import("key.zig");

// PKCS#1 v1.5 DigestInfo prefix for SHA-256.
const sha256_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

const WINDOW = 7;
const TABLE_SIZE = 1 << (WINDOW - 1); // odd powers x^1, x^3, ... x^(2^w-1)

// PKCS#1 v1.5 + SHA-256 RSA signing for a given modulus size, specialized at
// comptime. `modulus_bits` is 2048, 3072 or 4096; the CRT primes are half that
// width, so the limb arithmetic runs on N = modulus_bits/128 limbs. With every
// size a compile-time constant, RSA-4096 lowers to exactly the same code it did
// before this became parametric.
pub fn Rsa(comptime modulus_bits: usize) type {
    if (modulus_bits % 128 != 0) @compileError("modulus_bits must be a multiple of 128");
    const N = modulus_bits / 128; // limbs per CRT prime
    const K = modulus_bits / 8; // modulus bytes
    const B = bi.BigInt(N);
    const M = bi.BigInt(2 * N); // full-width modulus, for the public verify path
    const Fe = B.Fe;

    return struct {
        pub const Key = key.Key(N);
        pub const modulus_bits_ = modulus_bits;
        pub const signature_len = K;

        // Build the PKCS#1 v1.5 padded message as a 2N-limb little-endian integer.
        fn encodeMessage(msg: []const u8) [2 * N]u64 {
            var em: [K]u8 = undefined;
            em[0] = 0x00;
            em[1] = 0x01;
            const tlen = sha256_prefix.len + 32;
            const ps_len = K - 3 - tlen;
            @memset(em[2 .. 2 + ps_len], 0xff);
            em[2 + ps_len] = 0x00;
            @memcpy(em[3 + ps_len ..][0..sha256_prefix.len], &sha256_prefix);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            @memcpy(em[3 + ps_len + sha256_prefix.len ..][0..32], &digest);

            return M.fromBytesBE(&em);
        }

        // Reduce a full 2N-limb value into Montgomery form mod m: returns (M mod m)*R mod m.
        fn reduceToMont(full: *const [2 * N]u64, m: *const Fe, n0inv: u64, rr: *const Fe) Fe {
            var mlo: Fe = full[0..N].*;
            var mhi: Fe = full[N .. 2 * N].*;
            B.condSub(&mlo, m); // each half < R < 2m, one subtraction reduces mod m
            B.condSub(&mhi, m);
            const tlo = B.montMul(&mlo, rr, m, n0inv); // mlo * R mod m
            const thi = B.montMul(&mhi, rr, m, n0inv); // mhi * R mod m
            const thiR = B.montMul(&thi, rr, m, n0inv); // mhi * R^2 mod m
            return B.addModNoMont(&thiR, &tlo, m);
        }

        inline fn bitAt(exp: *const Fe, idx: usize) u1 {
            return @truncate(exp[idx >> 6] >> @intCast(idx & 63));
        }

        // Montgomery exponentiation with sliding window. base_mont is in Montgomery domain.
        fn montExp(base_mont: *const Fe, exp: *const Fe, m: *const Fe, n0inv: u64, mont_one: *const Fe) Fe {
            var table: [TABLE_SIZE]Fe = undefined;
            table[0] = base_mont.*;
            const x2 = B.montSqr(base_mont, m, n0inv);
            for (1..TABLE_SIZE) |k| {
                table[k] = B.montMul(&table[k - 1], &x2, m, n0inv);
            }

            // find highest set bit
            var top: isize = -1;
            {
                var li: usize = N;
                while (li > 0) {
                    li -= 1;
                    if (exp[li] != 0) {
                        top = @intCast(li * 64 + 63 - @clz(exp[li]));
                        break;
                    }
                }
            }
            if (top < 0) return mont_one.*;

            var result = mont_one.*;
            var i: isize = top;
            while (i >= 0) {
                if (bitAt(exp, @intCast(i)) == 0) {
                    result = B.montSqr(&result, m, n0inv);
                    i -= 1;
                    continue;
                }
                // sliding window: find lowest index l >= i-WINDOW+1 with a set bit
                var l: isize = i - WINDOW + 1;
                if (l < 0) l = 0;
                while (bitAt(exp, @intCast(l)) == 0) l += 1;
                const wbits: usize = @intCast(i - l + 1);
                for (0..wbits) |_| result = B.montSqr(&result, m, n0inv);
                // extract window value (bits l..i)
                var val: usize = 0;
                var b: isize = i;
                while (b >= l) : (b -= 1) {
                    val = (val << 1) | bitAt(exp, @intCast(b));
                }
                result = B.montMul(&result, &table[(val - 1) >> 1], m, n0inv);
                i = l - 1;
            }
            return result;
        }

        inline fn montOne(m: *const Fe, n0inv: u64, rr: *const Fe) Fe {
            // R mod m = (1 in Montgomery domain) = montMul(1, rr)
            return B.montMul(&B.one, rr, m, n0inv);
        }

        // Sign: returns the K-byte big-endian signature.
        pub fn sign(k: *const Key, msg: []const u8) [K]u8 {
            const m_full = encodeMessage(msg);

            // CRT bases in Montgomery domain.
            const base_p = reduceToMont(&m_full, &k.p, k.p_n0inv, &k.p_rr);
            const base_q = reduceToMont(&m_full, &k.q, k.q_n0inv, &k.q_rr);

            const mont_one_p = montOne(&k.p, k.p_n0inv, &k.p_rr);
            const mont_one_q = montOne(&k.q, k.q_n0inv, &k.q_rr);

            const sp_mont = montExp(&base_p, &k.p_exp, &k.p, k.p_n0inv, &mont_one_p);
            const sq_mont = montExp(&base_q, &k.q_exp, &k.q, k.q_n0inv, &mont_one_q);

            // convert out of Montgomery domain
            const sp = B.montMul(&sp_mont, &B.one, &k.p, k.p_n0inv);
            const sq = B.montMul(&sq_mont, &B.one, &k.q, k.q_n0inv);

            // Garner: h = (sp - sq) * qinv mod p ; s = sq + q*h
            var sq_modp = sq;
            B.condSub(&sq_modp, &k.p); // sq mod p
            const diff = B.subMod(&sp, &sq_modp, &k.p);
            const h = B.montMul(&diff, &k.qinv_mont, &k.p, k.p_n0inv); // diff*qinv mod p

            // s = sq + q*h  (full 2N-limb result)
            const qh = B.mulFull(&k.q, &h);
            var s: [2 * N]u64 = qh;
            var carry: u128 = 0;
            for (0..N) |i| {
                const t = @as(u128, s[i]) + @as(u128, sq[i]) + carry;
                s[i] = @truncate(t);
                carry = t >> 64;
            }
            var i: usize = N;
            while (i < 2 * N and carry != 0) : (i += 1) {
                const t = @as(u128, s[i]) + carry;
                s[i] = @truncate(t);
                carry = t >> 64;
            }

            // I2OSP: little-endian limbs -> big-endian bytes
            return M.toBytesBE(&s);
        }

        // Verify a PKCS#1 v1.5 + SHA-256 signature against the public key (n, e).
        // The public operation s^e mod n runs over the full 2N-limb modulus, so it
        // gets its own BigInt instance separate from the CRT half-width signing
        // path. e is small (typically 65537), so a plain square-and-multiply over
        // its bits is enough; verification is not on the hot path.
        pub fn verify(n_be: []const u8, e: u64, msg: []const u8, sig: []const u8) bool {
            if (sig.len != K or n_be.len > K or e == 0) return false;

            const n = M.fromBytesBE(n_be);
            if (n[0] & 1 == 0) return false; // RSA modulus is odd
            const s = M.fromBytesBE(sig);
            if (M.geq(&s, &n)) return false; // signature must be in [0, n)

            const n0inv = key.negInv64(n[0]);
            const rr = M.rSquared(&n);

            const base_mont = M.montMul(&s, &rr, &n, n0inv); // s -> Montgomery domain
            var result = M.montMul(&M.one, &rr, &n, n0inv); // 1 -> Montgomery domain
            var bit: isize = 63 - @as(isize, @clz(e));
            while (bit >= 0) : (bit -= 1) {
                result = M.montSqr(&result, &n, n0inv);
                if ((e >> @intCast(bit)) & 1 == 1) {
                    result = M.montMul(&result, &base_mont, &n, n0inv);
                }
            }
            const recovered = M.montMul(&result, &M.one, &n, n0inv); // leave Montgomery domain

            const em = encodeMessage(msg);
            var diff: u64 = 0;
            for (0..2 * N) |i| diff |= recovered[i] ^ em[i];
            return diff == 0;
        }
    };
}

pub const Rsa2048 = Rsa(2048);
pub const Rsa3072 = Rsa(3072);
pub const Rsa4096 = Rsa(4096);

fn expectReferenceSignature(comptime R: type, comptime d: type) !void {
    const k = try R.Key.fromHex(d.p_hex, d.q_hex, d.dp_hex, d.dq_hex, d.qinv_hex);
    var expected: [R.signature_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, d.sig_hex);
    const sig = R.sign(&k, "hello rsa wasm benchmark message");
    try std.testing.expectEqualSlices(u8, &expected, &sig);
}

test "RSA-2048 sign matches the OpenSSL reference signature" {
    try expectReferenceSignature(Rsa2048, key.default2048);
}

test "RSA-3072 sign matches the OpenSSL reference signature" {
    try expectReferenceSignature(Rsa3072, key.default3072);
}

test "RSA-4096 sign matches the OpenSSL reference signature" {
    try expectReferenceSignature(Rsa4096, key.default4096);
}

fn expectReferenceVerify(comptime R: type, comptime d: type) !void {
    const N = R.modulus_bits_ / 128;
    const B = bi.BigInt(N);
    const M = bi.BigInt(2 * N);
    const K = R.signature_len;
    const k = try R.Key.fromHex(d.p_hex, d.q_hex, d.dp_hex, d.dq_hex, d.qinv_hex);

    // n = p * q, little-endian limbs -> big-endian bytes.
    const n_limbs = B.mulFull(&k.p, &k.q);
    const n_be = M.toBytesBE(&n_limbs);

    const msg = "hello rsa wasm benchmark message";
    var sig: [K]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig, d.sig_hex);
    try std.testing.expect(R.verify(&n_be, 65537, msg, &sig));

    // A flipped signature bit must be rejected.
    sig[K - 1] ^= 1;
    try std.testing.expect(!R.verify(&n_be, 65537, msg, &sig));
    sig[K - 1] ^= 1;

    // A changed message must be rejected.
    try std.testing.expect(!R.verify(&n_be, 65537, "hello rsa wasm benchmark messagf", &sig));
}

test "RSA-2048 verify accepts the reference signature and rejects tampering" {
    try expectReferenceVerify(Rsa2048, key.default2048);
}

test "RSA-3072 verify accepts the reference signature and rejects tampering" {
    try expectReferenceVerify(Rsa3072, key.default3072);
}

test "RSA-4096 verify accepts the reference signature and rejects tampering" {
    try expectReferenceVerify(Rsa4096, key.default4096);
}
