const std = @import("std");
pub const bi = @import("bigint.zig");
pub const bi28 = @import("bigint28.zig");
pub const key = @import("key.zig");

// PKCS#1 v1.5 DigestInfo prefix for SHA-256.
const sha256_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

// What signing does its exponentiations with.
const Arith = enum {
    limbs64, // BigInt: natively, and on wasm with wide arithmetic
    limbs28, // BigInt28: on wasm without wide arithmetic
    limbs28x2, // BigInt28x2: the same, with SIMD
};

const default_arith: Arith = if (bi28.preferred_x2) .limbs28x2 else if (bi28.preferred) .limbs28 else .limbs64;

// PKCS#1 v1.5 + SHA-256 signing and verification for one key size.
pub fn Rsa(comptime modulus_bits: usize) type {
    return RsaWith(modulus_bits, default_arith);
}

// The tests run all three natively.
fn RsaWith(comptime modulus_bits: usize, comptime arith: Arith) type {
    if (modulus_bits % 128 != 0) @compileError("modulus_bits must be a multiple of 128");
    const N = modulus_bits / 128; // limbs per CRT prime
    const K = modulus_bits / 8; // modulus bytes
    const B = bi.BigInt(N);
    const T = bi28.BigInt28(N);
    const X = bi28.BigInt28x2(N);
    const use28 = arith != .limbs64;
    const M = bi.PublicBigInt(2 * N); // full modulus size, for verify
    const Fe = B.Fe;
    // Window sizes, for the default and the constant-time exponentiation.
    // The larger ones are faster for 4096-bit keys, the smaller ones below that.
    const WINDOW = if (modulus_bits >= 4096) 7 else 6;
    const TABLE_SIZE = 1 << (WINDOW - 1); // the table only holds odd powers
    const CT_WINDOW = if (modulus_bits >= 4096) 6 else 5;
    const CT_WINDOWS = (64 * N + CT_WINDOW - 1) / CT_WINDOW;

    return struct {
        pub const Key = key.Key(N, use28);
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

        fn bitAt(exp: *const Fe, idx: usize) u1 {
            return @truncate(exp[idx >> 6] >> @intCast(idx & 63));
        }

        // Constant-time tables keep 28-bit values packed, so that lookups read less.
        fn Entry(comptime A: type) type {
            return if (A == T) T.Packed else A.Fe;
        }

        inline fn toEntry(comptime A: type, a: *const A.Fe) Entry(A) {
            return if (A == T) T.pack(a) else a.*;
        }

        inline fn fromEntry(comptime A: type, e: Entry(A)) A.Fe {
            return if (A == T) T.unpack(&e) else e;
        }

        // base^exp mod m, in Montgomery form, with B or T as the arithmetic.
        // Results are written in place: copying 28-bit values back is a slow runtime call in wasmer on aarch64.
        fn montExp(comptime A: type, base_mont: *const A.Fe, exp: *const Fe, m: *const A.Fe, n0inv: u64, mont_one: *const A.Fe) A.Fe {
            if (std.options.side_channels_mitigations != .none) return montExpConstantTime(A, base_mont, exp, m, n0inv, mont_one);
            var table: [TABLE_SIZE]A.Fe = undefined;
            table[0] = base_mont.*;
            const x2 = A.montSqr(base_mont, m, n0inv);
            for (1..TABLE_SIZE) |k| {
                A.mulTo(&table[k], &table[k - 1], &x2, m, n0inv);
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
                    A.sqrTo(&result, &result, m, n0inv);
                    i -= 1;
                    continue;
                }
                // End the window on a set bit, since the table only has odd powers.
                var l: isize = i - WINDOW + 1;
                if (l < 0) l = 0;
                while (bitAt(exp, @intCast(l)) == 0) l += 1;
                const wbits: usize = @intCast(i - l + 1);
                for (0..wbits) |_| A.sqrTo(&result, &result, m, n0inv);
                var val: usize = 0;
                var b: isize = i;
                while (b >= l) : (b -= 1) {
                    val = (val << 1) | bitAt(exp, @intCast(b));
                }
                A.mulTo(&result, &result, &table[(val - 1) >> 1], m, n0inv);
                i = l - 1;
            }
            return result;
        }

        // Does the same work for every exponent, and its table lookups read every entry.
        fn montExpConstantTime(comptime A: type, base_mont: *const A.Fe, exp: *const Fe, m: *const A.Fe, n0inv: u64, mont_one: *const A.Fe) A.Fe {
            var table: [1 << CT_WINDOW]Entry(A) = undefined;
            table[0] = toEntry(A, mont_one);
            table[1] = toEntry(A, base_mont);
            for (2..table.len) |k| {
                table[k] = if (A == T)
                    T.pack(&T.mul(&T.unpack(&table[k - 1]), base_mont, m, n0inv))
                else
                    A.montMul(&table[k - 1], base_mont, m, n0inv);
            }

            var result = fromEntry(A, bi.ct.lookup(&table, windowAt(exp, (CT_WINDOWS - 1) * CT_WINDOW)));
            var w: usize = CT_WINDOWS - 1;
            while (w > 0) {
                w -= 1;
                for (0..CT_WINDOW) |_| A.sqrTo(&result, &result, m, n0inv);
                const entry = fromEntry(A, bi.ct.lookup(&table, windowAt(exp, w * CT_WINDOW)));
                A.mulTo(&result, &result, &entry, m, n0inv);
            }
            return result;
        }

        // Takes and returns the same forms as the 64-bit code: Montgomery form in, plain value out.
        fn pow28(base: *const Fe, mont_one: *const Fe, exp: *const Fe, m64: *const Fe, n0inv64: u64, m: *const T.Fe, c: *const T.Fe) Fe {
            const n0 = T.n0inv(n0inv64);
            const b = T.toMont(base, c, m, n0);
            const one = T.toMont(mont_one, c, m, n0);
            const r = montExp(T, &b, exp, m, n0, &one);
            return T.fromMont(&r, m, m64, n0);
        }

        // pow28() for p and q at once.
        fn pow28x2(k: *const Key, base_p: *const Fe, base_q: *const Fe, one_p: *const Fe, one_q: *const Fe) [2]Fe {
            const m = X.join(&k.p28, &k.q28);
            const c = X.join(&k.p_c28, &k.q_c28);
            const n0 = X.n0pair(T.n0inv(k.p_n0inv), T.n0inv(k.q_n0inv));
            const base = X.mul(&X.join(&T.fromLimbs(base_p), &T.fromLimbs(base_q)), &c, &m, n0);
            const one = X.mul(&X.join(&T.fromLimbs(one_p), &T.fromLimbs(one_q)), &c, &m, n0);
            var r = montExp2(&base, &one, &k.p_exp, &k.q_exp, &m, n0);

            X.mulTo(&r, &r, &X.join(&T.one, &T.one), &m, n0);
            var sp = T.toLimbs(&X.lane(&r, 0));
            var sq = T.toLimbs(&X.lane(&r, 1));
            B.condSub(&sp, &k.p);
            B.condSub(&sq, &k.q);
            return .{ sp, sq };
        }

        // montExp() in both lanes, with a different exponent in each.
        // So the window is fixed, even without mitigations.
        fn montExp2(base: *const X.Fe, one: *const X.Fe, exp_p: *const Fe, exp_q: *const Fe, m: *const X.Fe, n0: X.N0) X.Fe {
            var table: [1 << CT_WINDOW]X.Fe = undefined;
            table[0] = one.*;
            table[1] = base.*;
            for (2..table.len) |i| {
                if (i % 2 == 0) X.sqrTo(&table[i], &table[i / 2], m, n0) else X.mulTo(&table[i], &table[i - 1], base, m, n0);
            }

            const top = (CT_WINDOWS - 1) * CT_WINDOW;
            var result = bi.ct.lookupHalves(&table, windowAt(exp_p, top), windowAt(exp_q, top));
            var w: usize = CT_WINDOWS - 1;
            while (w > 0) {
                w -= 1;
                for (0..CT_WINDOW) |_| X.sqrTo(&result, &result, m, n0);
                const entry = bi.ct.lookupHalves(&table, windowAt(exp_p, w * CT_WINDOW), windowAt(exp_q, w * CT_WINDOW));
                X.mulTo(&result, &result, &entry, m, n0);
            }
            return result;
        }

        fn windowAt(exp: *const Fe, pos: usize) usize {
            const lo = exp[pos / 64];
            const hi: u128 = if (pos / 64 + 1 < N) exp[pos / 64 + 1] else 0;
            const bits = ((hi << 64) | lo) >> @intCast(pos % 64);
            return @intCast(bits & ((1 << CT_WINDOW) - 1));
        }

        fn montOne(m: *const Fe, n0inv: u64, rr: *const Fe) Fe {
            return B.montMul(&B.one, rr, m, n0inv);
        }

        pub fn sign(k: *const Key, msg: []const u8) [K]u8 {
            const m_full = encodeMessage(msg);

            const base_p = reduceToMont(&m_full, &k.p, k.p_n0inv, &k.p_rr);
            const base_q = reduceToMont(&m_full, &k.q, k.q_n0inv, &k.q_rr);

            const mont_one_p = montOne(&k.p, k.p_n0inv, &k.p_rr);
            const mont_one_q = montOne(&k.q, k.q_n0inv, &k.q_rr);

            // Keep both exponentiations before both conversions.
            // Any other order changes the tuned 64-bit code.
            const sp_mont: Fe = if (use28) undefined else montExp(B, &base_p, &k.p_exp, &k.p, k.p_n0inv, &mont_one_p);
            const sq_mont: Fe = if (use28) undefined else montExp(B, &base_q, &k.q_exp, &k.q, k.q_n0inv, &mont_one_q);
            const pair: [2]Fe = if (arith == .limbs28x2) pow28x2(k, &base_p, &base_q, &mont_one_p, &mont_one_q) else undefined;

            const sp = switch (arith) {
                .limbs64 => B.montMul(&sp_mont, &B.one, &k.p, k.p_n0inv),
                .limbs28 => pow28(&base_p, &mont_one_p, &k.p_exp, &k.p, k.p_n0inv, &k.p28, &k.p_c28),
                .limbs28x2 => pair[0],
            };
            const sq = switch (arith) {
                .limbs64 => B.montMul(&sq_mont, &B.one, &k.q, k.q_n0inv),
                .limbs28 => pow28(&base_q, &mont_one_q, &k.q_exp, &k.q, k.q_n0inv, &k.q28, &k.q_c28),
                .limbs28x2 => pair[1],
            };

            // Combine both halves: s = sq + q * ((sp - sq) * qinv mod p)
            var sq_modp = sq;
            B.condSub(&sq_modp, &k.p); // sq can be larger than p
            const diff = B.subMod(&sp, &sq_modp, &k.p);
            const h = B.montMul(&diff, &k.qinv_mont, &k.p, k.p_n0inv);

            const qh = B.mulFull(&k.q, &h);
            var s: [2 * N]u64 = qh;
            var carry: u128 = 0;
            for (0..N) |i| {
                const t = carry + s[i] + sq[i];
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

        pub const PublicKey = struct {
            n: [2 * N]u64,
            e: u64,
            n0inv: u64,
            rr: [2 * N]u64,

            pub fn fromBytes(n_be: []const u8, e: u64) !PublicKey {
                if (n_be.len > K or e < 3 or e & 1 == 0) return error.InvalidKey;
                const n = M.fromBytesBE(n_be);
                if (n[0] & 1 == 0) return error.InvalidKey; // a real RSA modulus is always odd
                return .{ .n = n, .e = e, .n0inv = key.negInv64(n[0]), .rr = M.rSquared(&n) };
            }
        };

        pub fn verify(pk: *const PublicKey, msg: []const u8, sig: []const u8) bool {
            if (sig.len != K) return false;
            const n = &pk.n;
            const s = M.fromBytesBE(sig);
            if (M.geq(&s, n)) return false;

            const base_mont = M.montMul(&s, &pk.rr, n, pk.n0inv);
            var result = base_mont;
            var bit: isize = 62 - @as(isize, @clz(pk.e));
            while (bit >= 0) : (bit -= 1) {
                result = M.montSqr(&result, n, pk.n0inv);
                if ((pk.e >> @intCast(bit)) & 1 == 1) {
                    result = M.montMul(&result, &base_mont, n, pk.n0inv);
                }
            }
            const recovered = M.montMul(&result, &M.one, n, pk.n0inv); // back from Montgomery form

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
    const pk = try R.PublicKey.fromBytes(&n, 65537);
    try std.testing.expect(R.verify(&pk, msg, &sig));
    try std.testing.expect(!R.verify(&pk, "hello rsa wasm benchmark messagf", &sig));

    // With e = 1, the padded message would pass as its own signature.
    try std.testing.expectError(error.InvalidKey, R.PublicKey.fromBytes(&n, 1));

    sig[K - 1] ^= 1;
    try std.testing.expect(!R.verify(&pk, msg, &sig));
}

test "signatures match OpenSSL and verify" {
    inline for (.{ Arith.limbs64, Arith.limbs28, Arith.limbs28x2 }) |arith| {
        try expectReferenceVectors(RsaWith(2048, arith), key.default2048);
        try expectReferenceVectors(RsaWith(3072, arith), key.default3072);
        try expectReferenceVectors(RsaWith(4096, arith), key.default4096);
    }
}

test {
    _ = bi28;
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
