const std = @import("std");
const bi = @import("bigint.zig");
const key = @import("key.zig");

// PKCS#1 v1.5 DigestInfo prefix for SHA-256.
const sha256_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

// PKCS#1 v1.5 + SHA-256 signing and verification for one key size.
pub fn Rsa(comptime modulus_bits: usize) type {
    if (modulus_bits % 128 != 0) @compileError("modulus_bits must be a multiple of 128");
    const N = modulus_bits / 128; // limbs per CRT prime
    const K = modulus_bits / 8; // modulus bytes
    const B = bi.BigInt(N);
    const M = bi.PublicBigInt(2 * N); // full modulus size, for verify
    const Fe = B.Fe;
    // Window sizes, for the default and the constant-time exponentiation.
    // The larger ones are faster for 4096-bit keys, the smaller ones below that.
    const WINDOW = if (modulus_bits >= 4096) 7 else 6;
    const TABLE_SIZE = 1 << (WINDOW - 1); // the table only holds odd powers
    const CT_WINDOW = if (modulus_bits >= 4096) 6 else 5;

    return struct {
        pub const Key = key.Key(N);
        pub const modulus_bits_ = modulus_bits;
        pub const signature_len = K;

        // SHA-256 of msg with PKCS#1 v1.5 padding, as a full-size number.
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

        fn reduceToMont(full: *const [2 * N]u64, m: *const Fe, n0inv: u64, rr: *const Fe) Fe {
            var mlo: Fe = full[0..N].*;
            var mhi: Fe = full[N .. 2 * N].*;
            // Key.init makes sure m has its top bit set, so one subtraction is enough here.
            B.condSub(&mlo, m);
            B.condSub(&mhi, m);
            const tlo = B.montMul(&mlo, rr, m, n0inv);
            const thi = B.montMul(&mhi, rr, m, n0inv);
            const thiR = B.montMul(&thi, rr, m, n0inv);
            return B.addModNoMont(&thiR, &tlo, m);
        }

        inline fn bitAt(exp: *const Fe, idx: usize) u1 {
            return @truncate(exp[idx >> 6] >> @intCast(idx & 63));
        }

        // base^exp mod m, with base and result in Montgomery form.
        fn montExp(base_mont: *const Fe, exp: *const Fe, m: *const Fe, n0inv: u64, mont_one: *const Fe) Fe {
            if (std.options.side_channels_mitigations != .none) return montExpConstantTime(base_mont, exp, m, n0inv, mont_one);
            var table: [TABLE_SIZE]Fe = undefined;
            table[0] = base_mont.*;
            const x2 = B.montSqr(base_mont, m, n0inv);
            for (1..TABLE_SIZE) |k| {
                table[k] = B.montMul(&table[k - 1], &x2, m, n0inv);
            }

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
                // End the window on a set bit, since the table only has odd powers.
                var l: isize = i - WINDOW + 1;
                if (l < 0) l = 0;
                while (bitAt(exp, @intCast(l)) == 0) l += 1;
                const wbits: usize = @intCast(i - l + 1);
                for (0..wbits) |_| result = B.montSqr(&result, m, n0inv);
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

        // Does the same work for every exponent, and its table lookups read every entry.
        fn montExpConstantTime(base_mont: *const Fe, exp: *const Fe, m: *const Fe, n0inv: u64, mont_one: *const Fe) Fe {
            var table: [1 << CT_WINDOW]Fe = undefined;
            table[0] = mont_one.*;
            table[1] = base_mont.*;
            for (2..table.len) |k| {
                table[k] = B.montMul(&table[k - 1], base_mont, m, n0inv);
            }

            const windows = (64 * N + CT_WINDOW - 1) / CT_WINDOW;
            var result = bi.ct.lookup(&table, windowAt(exp, (windows - 1) * CT_WINDOW));
            var w: usize = windows - 1;
            while (w > 0) {
                w -= 1;
                for (0..CT_WINDOW) |_| result = B.montSqr(&result, m, n0inv);
                const entry = bi.ct.lookup(&table, windowAt(exp, w * CT_WINDOW));
                result = B.montMul(&result, &entry, m, n0inv);
            }
            return result;
        }

        fn windowAt(exp: *const Fe, pos: usize) usize {
            const lo = exp[pos / 64];
            const hi: u64 = if (pos / 64 + 1 < N) exp[pos / 64 + 1] else 0;
            const bits = ((@as(u128, hi) << 64) | lo) >> @intCast(pos % 64);
            return @intCast(bits & ((1 << CT_WINDOW) - 1));
        }

        inline fn montOne(m: *const Fe, n0inv: u64, rr: *const Fe) Fe {
            return B.montMul(&B.one, rr, m, n0inv);
        }

        pub fn sign(k: *const Key, msg: []const u8) [K]u8 {
            const m_full = encodeMessage(msg);

            const base_p = reduceToMont(&m_full, &k.p, k.p_n0inv, &k.p_rr);
            const base_q = reduceToMont(&m_full, &k.q, k.q_n0inv, &k.q_rr);

            const mont_one_p = montOne(&k.p, k.p_n0inv, &k.p_rr);
            const mont_one_q = montOne(&k.q, k.q_n0inv, &k.q_rr);

            const sp_mont = montExp(&base_p, &k.p_exp, &k.p, k.p_n0inv, &mont_one_p);
            const sq_mont = montExp(&base_q, &k.q_exp, &k.q, k.q_n0inv, &mont_one_q);

            const sp = B.montMul(&sp_mont, &B.one, &k.p, k.p_n0inv);
            const sq = B.montMul(&sq_mont, &B.one, &k.q, k.q_n0inv);

            // Combine both halves: s = sq + q * ((sp - sq) * qinv mod p)
            var sq_modp = sq;
            B.condSub(&sq_modp, &k.p); // sq can be larger than p
            const diff = B.subMod(&sp, &sq_modp, &k.p);
            const h = B.montMul(&diff, &k.qinv_mont, &k.p, k.p_n0inv);

            const qh = B.mulFull(&k.q, &h);
            var s: [2 * N]u64 = qh;
            var carry: u128 = 0;
            for (0..N) |i| {
                const t = @as(u128, s[i]) + sq[i] + carry;
                s[i] = @truncate(t);
                carry = t >> 64;
            }
            // In constant-time mode, go through every limb, even once the carry is zero.
            var i: usize = N;
            while (i < 2 * N and (std.options.side_channels_mitigations != .none or carry != 0)) : (i += 1) {
                const t = s[i] + carry;
                s[i] = @truncate(t);
                carry = t >> 64;
            }

            return M.toBytesBE(&s);
        }

        // Not optimized: e is small, and only signing gets benchmarked.
        pub fn verify(n_be: []const u8, e: u64, msg: []const u8, sig: []const u8) bool {
            if (sig.len != K or n_be.len > K or e < 3 or e & 1 == 0) return false;

            const n = M.fromBytesBE(n_be);
            if (n[0] & 1 == 0) return false; // a real RSA modulus is always odd
            const s = M.fromBytesBE(sig);
            if (M.geq(&s, &n)) return false;

            const n0inv = key.negInv64(n[0]);
            const rr = M.rSquared(&n);

            const base_mont = M.montMul(&s, &rr, &n, n0inv);
            var result = M.montMul(&M.one, &rr, &n, n0inv);
            var bit: isize = 63 - @as(isize, @clz(e));
            while (bit >= 0) : (bit -= 1) {
                result = M.montSqr(&result, &n, n0inv);
                if ((e >> @intCast(bit)) & 1 == 1) {
                    result = M.montMul(&result, &base_mont, &n, n0inv);
                }
            }
            const recovered = M.montMul(&result, &M.one, &n, n0inv); // back from Montgomery form

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

fn expectReferenceVectors(comptime R: type, comptime d: type) !void {
    const N = R.modulus_bits_ / 128;
    const M = bi.BigInt(2 * N);
    const K = R.signature_len;
    const msg = "hello rsa wasm benchmark message";
    const k = try R.Key.fromHex(d.p_hex, d.q_hex, d.dp_hex, d.dq_hex, d.qinv_hex);

    var sig = R.sign(&k, msg);
    var expected: [K]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, d.sig_hex);
    try std.testing.expectEqualSlices(u8, &expected, &sig);

    const n = M.toBytesBE(&bi.BigInt(N).mulFull(&k.p, &k.q));
    try std.testing.expect(R.verify(&n, 65537, msg, &sig));
    try std.testing.expect(!R.verify(&n, 65537, "hello rsa wasm benchmark messagf", &sig));

    // With e = 1, the padded message would pass as its own signature.
    try std.testing.expect(!R.verify(&n, 1, msg, &M.toBytesBE(&R.encodeMessage(msg))));

    sig[K - 1] ^= 1;
    try std.testing.expect(!R.verify(&n, 65537, msg, &sig));
}

test "RSA-2048 matches the OpenSSL signature and verifies it" {
    try expectReferenceVectors(Rsa2048, key.default2048);
}

test "RSA-3072 matches the OpenSSL signature and verifies it" {
    try expectReferenceVectors(Rsa3072, key.default3072);
}

test "RSA-4096 matches the OpenSSL signature and verifies it" {
    try expectReferenceVectors(Rsa4096, key.default4096);
}

test "key construction rejects components outside signer assumptions" {
    const R = Rsa2048;
    const d = key.default2048;
    var short_prime: [128]u8 = @splat(0xff);
    short_prime[0] = 0x7f;
    var even_prime: [128]u8 = @splat(0xff);
    even_prime[127] = 0xfe;

    try std.testing.expectError(error.InvalidKey, R.Key.fromBytes(&short_prime, &short_prime, &.{1}, &.{1}, &.{1}));
    try std.testing.expectError(error.InvalidKey, R.Key.fromBytes(&even_prime, &even_prime, &.{1}, &.{1}, &.{1}));
    try std.testing.expectError(error.InvalidKey, R.Key.fromHex(d.p_hex, d.q_hex, d.p_hex, d.dq_hex, d.qinv_hex));
}
