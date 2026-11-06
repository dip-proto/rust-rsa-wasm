// Montgomery arithmetic with 28-bit limbs, used for signing on wasm without wide arithmetic.
//
// There, a 64x64-bit product costs four multiplies and a lot of carry handling.
// With 28-bit limbs, it's a single multiply, and a whole column of products fits in 64 bits, so nothing carries until the column is done.
// It's the same idea as OpenSSL's RSAZ code.
//
// R is more than four times the modulus, so results stay below 2m and never need a final subtraction.
// That also makes everything here constant time.
const std = @import("std");
const builtin = @import("builtin");
const bi = @import("bigint.zig");
const key = @import("key.zig");

pub const preferred = bi.is_wasm and !bi.has_wide_arithmetic;

// With SIMD, p and q are done together, one in each lane (BigInt28x2).
pub const preferred_x2 = preferred and std.Target.wasm.featureSetHas(builtin.target.cpu.features, .simd128);

const bits = 28;
const mask: u64 = (1 << bits) - 1;
const load = bi.load;
const store = bi.store;

// For the same modulus sizes as BigInt(N).
pub fn BigInt28(comptime N: usize) type {
    const B64 = bi.BigInt(N);
    return struct {
        // Two bits more than the modulus, so that R > 4m.
        pub const L = (64 * N + 2 + bits - 1) / bits;
        pub const Fe = [L]u64;
        // Two limbs per word, so that constant-time lookups read half as much.
        pub const Packed = [(L + 1) / 2]u64;

        // A column sums up to 2L products below 2^56, plus a carry.
        comptime {
            std.debug.assert(2 * L <= 255);
        }

        pub const one: Fe = blk: {
            var r: Fe = @splat(0);
            r[0] = 1;
            break :blk r;
        };

        pub fn fromLimbs(x: *const [N]u64) Fe {
            var r: Fe = undefined;
            inline for (0..L) |i| {
                const bit = i * bits;
                const w = bit / 64;
                const s = bit % 64;
                var v: u64 = if (w < N) x[w] >> s else 0;
                if (s > 64 - bits and w + 1 < N) v |= x[w + 1] << (64 - s);
                r[i] = v & mask;
            }
            return r;
        }

        // x must be below 2^(64 * N).
        pub fn toLimbs(x: *const Fe) [N]u64 {
            var r: [N]u64 = @splat(0);
            inline for (0..L) |i| {
                const bit = i * bits;
                const w = bit / 64;
                const s = bit % 64;
                if (w < N) r[w] |= x[i] << s;
                if (s > 64 - bits and w + 1 < N) r[w + 1] |= x[i] >> (64 - s);
            }
            return r;
        }

        pub fn pack(x: *const Fe) Packed {
            var r: Packed = undefined;
            inline for (0..r.len) |i| {
                r[i] = x[2 * i] | if (2 * i + 1 < L) x[2 * i + 1] << 32 else 0;
            }
            return r;
        }

        pub fn unpack(x: *const Packed) Fe {
            var r: Fe = undefined;
            inline for (0..L) |i| r[i] = (x[i / 2] >> (32 * (i % 2))) & 0xffff_ffff;
            return r;
        }

        pub fn n0inv(n0inv64: u64) u64 {
            return n0inv64 & mask;
        }

        // The constant for toMont(): R^2 / 2^(64N) mod m.
        pub fn toMontConstant(m: *const [N]u64) Fe {
            var c = B64.one;
            for (0..2 * bits * L - 64 * N) |_| c = B64.addModNoMont(&c, &c, m);
            return fromLimbs(&c);
        }

        // Converts a value in BigInt's Montgomery form to this one.
        pub fn toMont(x64: *const [N]u64, c: *const Fe, m: *const Fe, n0: u64) Fe {
            return mul(&fromLimbs(x64), c, m, n0);
        }

        // Converts back to a plain value below m.
        pub fn fromMont(x: *const Fe, m: *const Fe, m64: *const [N]u64, n0: u64) [N]u64 {
            var r = toLimbs(&mul(x, &one, m, n0));
            B64.condSub(&r, m64);
            return r;
        }

        // The column sums of a product, before the reduction.
        const Wide = [2 * L - 1]u64;

        // Two sums per column, so that the CPU can work on both at once.
        // Every third product, the sum is stored to a word the column overwrites later.
        // Otherwise, Cranelift loads the whole column up front and spills it.
        const Column = struct {
            s: [2]u64,
            sink: *volatile u64,

            inline fn add(c: *Column, comptime n: usize, x: u64, y: u64) void {
                c.s[n % 2] += x * y;
                if (n % 3 == 2) c.sink.* = c.s[n % 2];
            }
        };

        // Multiplication and squaring share the reduction, so that the unrolled code fits in the M5's instruction cache.
        //
        // The kernels write through pointers.
        // With a local result array, LLVM zeroes most of it first.

        fn productInto(t: *Wide, a: *const Fe, b: *const Fe) void {
            @setEvalBranchQuota(1000000);
            inline for (0..2 * L - 1) |k| {
                comptime var n: usize = 0;
                var c: Column = .{ .s = .{ 0, 0 }, .sink = &t[k] };
                inline for (if (k < L) 0 else k - L + 1..@min(k + 1, L)) |i| {
                    c.add(n, load(a, i), load(b, k - i));
                    n += 1;
                }
                store(t, k, c.s[0] + c.s[1]);
            }
        }

        fn squareInto(t: *Wide, a: *const Fe) void {
            @setEvalBranchQuota(1000000);
            inline for (0..2 * L - 1) |k| {
                comptime var n: usize = 0;
                var c: Column = .{ .s = .{ 0, 0 }, .sink = &t[k] };
                inline for (if (k < L) 0 else k - L + 1..(k + 1) / 2) |i| {
                    c.add(n, load(a, i), load(a, k - i));
                    n += 1;
                }
                var v = (c.s[0] + c.s[1]) << 1;
                if (k % 2 == 0) {
                    const h = load(a, k / 2);
                    v += h * h;
                }
                store(t, k, v);
            }
        }

        // t / R mod m, column by column.
        // The low columns save the multipliers of m in r, and the high ones then overwrite them with the result.
        fn redcInto(r: *Fe, t: *const Wide, m: *const Fe, n0: u64) void {
            @setEvalBranchQuota(1000000);
            var carry: u64 = 0;
            inline for (0..2 * L - 1) |k| {
                comptime var n: usize = 0;
                var c: Column = .{ .s = .{ carry + load(t, k), 0 }, .sink = &r[if (k < L) L - 1 else k - L] };
                inline for (if (k < L) 0 else k - L + 1..@min(k, L)) |j| {
                    c.add(n, load(r, j), load(m, k - j));
                    n += 1;
                }
                var acc = c.s[0] + c.s[1];
                if (k < L) {
                    const q = ((acc & mask) * n0) & mask;
                    store(r, k, q);
                    acc += q * load(m, 0);
                } else {
                    store(r, k - L, acc & mask);
                }
                carry = acc >> bits;
            }
            store(r, L - 1, carry);
        }

        // r = a * b / R mod m, for a and b below 2m.
        // r can be a or b.
        pub fn mulTo(r: *Fe, a: *const Fe, b: *const Fe, m: *const Fe, n0: u64) void {
            var t: Wide = undefined;
            @call(.never_inline, productInto, .{ &t, a, b });
            @call(.never_inline, redcInto, .{ r, &t, m, n0 });
        }

        pub fn sqrTo(r: *Fe, a: *const Fe, m: *const Fe, n0: u64) void {
            var t: Wide = undefined;
            @call(.never_inline, squareInto, .{ &t, a });
            @call(.never_inline, redcInto, .{ r, &t, m, n0 });
        }

        pub fn mul(a: *const Fe, b: *const Fe, m: *const Fe, n0: u64) Fe {
            var r: Fe = undefined;
            mulTo(&r, a, b, m, n0);
            return r;
        }

        pub fn sqr(a: *const Fe, m: *const Fe, n0: u64) Fe {
            var r: Fe = undefined;
            sqrTo(&r, a, m, n0);
            return r;
        }

        // BigInt's name, for code that works with both.
        pub const montSqr = sqr;
    };
}

// BigInt28 for p and q at once, one in each SIMD lane, like OpenSSL's RSAZ x2 code.
// Each word holds a limb of the p value in its low half, and the same limb of the q value in its high half.
pub fn BigInt28x2(comptime N: usize) type {
    const T = BigInt28(N);
    const L = T.L;
    const V4 = @Vector(4, u32);
    const W2 = @Vector(2, u64);
    const wmask: W2 = @splat(mask);
    return struct {
        // One extra word, since limbs are read 16 bytes at a time.
        pub const Fe = [L + 1]u64;
        pub const N0 = V4;
        const Wide = [2 * L - 1]W2;
        const Q = [L]W2;

        pub fn join(p: *const T.Fe, q: *const T.Fe) Fe {
            var r: Fe = undefined;
            inline for (0..L) |i| r[i] = p[i] | (q[i] << 32);
            r[L] = 0;
            return r;
        }

        pub fn lane(x: *const Fe, comptime which: u1) T.Fe {
            var r: T.Fe = undefined;
            inline for (0..L) |i| r[i] = (x[i] >> (32 * @as(u6, which))) & 0xffff_ffff;
            return r;
        }

        pub fn n0pair(p: u64, q: u64) N0 {
            return .{ @intCast(p), @intCast(q), 0, 0 };
        }

        // 16 bytes, so that LLVM multiplies with extmul.
        // With 8-byte loads, it uses i64x2.mul, which is very slow on Cranelift.
        inline fn load16(p: anytype, comptime i: usize) V4 {
            const src: *align(8) const volatile V4 = @ptrCast(&p[i]);
            return src.*;
        }

        inline fn loadw(p: anytype, comptime i: usize) W2 {
            const src: *const volatile W2 = &p[i];
            return src.*;
        }

        inline fn storew(p: anytype, comptime i: usize, v: W2) void {
            const dst: *volatile W2 = &p[i];
            dst.* = v;
        }

        inline fn mulLow(x: V4, y: V4) W2 {
            const lo = [2]i32{ 0, 1 };
            return @as(W2, @shuffle(u32, x, undefined, lo)) * @as(W2, @shuffle(u32, y, undefined, lo));
        }

        inline fn pack(w: W2) u64 {
            const v: V4 = @bitCast(w);
            const p: @Vector(2, u32) = @shuffle(u32, v, undefined, [2]i32{ 0, 2 });
            return @bitCast(p);
        }

        inline fn narrow(w: W2) V4 {
            const v: V4 = @bitCast(w);
            return @shuffle(u32, v, undefined, [4]i32{ 0, 2, 0, 2 });
        }

        // Same as BigInt28's columns, but with four sums: with two, the M5 waits on its multiply-adds.
        const Column = struct {
            s: [4]W2,
            sink: *volatile W2,

            inline fn add(c: *Column, comptime n: usize, x: V4, y: V4) void {
                c.s[n % 4] += mulLow(x, y);
                if (n % 3 == 2) c.sink.* = c.s[n % 4];
            }

            inline fn total(c: *const Column) W2 {
                return (c.s[0] + c.s[1]) + (c.s[2] + c.s[3]);
            }
        };

        inline fn column(init: W2, sink: *volatile W2) Column {
            return .{ .s = .{ init, @splat(0), @splat(0), @splat(0) }, .sink = sink };
        }

        fn productInto(t: *Wide, a: *const Fe, b: *const Fe) void {
            @setEvalBranchQuota(1000000);
            inline for (0..2 * L - 1) |k| {
                comptime var n: usize = 0;
                var c = column(@splat(0), &t[k]);
                inline for (if (k < L) 0 else k - L + 1..@min(k + 1, L)) |i| {
                    c.add(n, load16(a, i), load16(b, k - i));
                    n += 1;
                }
                storew(t, k, c.total());
            }
        }

        fn squareInto(t: *Wide, a: *const Fe) void {
            @setEvalBranchQuota(1000000);
            inline for (0..2 * L - 1) |k| {
                comptime var n: usize = 0;
                var c = column(@splat(0), &t[k]);
                inline for (if (k < L) 0 else k - L + 1..(k + 1) / 2) |i| {
                    c.add(n, load16(a, i), load16(a, k - i));
                    n += 1;
                }
                var v = c.total() << @splat(1);
                if (k % 2 == 0) {
                    const h = load16(a, k / 2);
                    v += mulLow(h, h);
                }
                storew(t, k, v);
            }
        }

        // The multipliers get their own 16-byte slots in q.
        // Reading them back from r would stall, since each 16-byte load would span two recent 8-byte stores.
        fn redcInto(r: *Fe, t: *Wide, q: *Q, m: *const Fe, n0: V4) void {
            @setEvalBranchQuota(1000000);
            var carry: W2 = @splat(0);
            inline for (0..2 * L - 1) |k| {
                comptime var n: usize = 0;
                var c = column(carry + loadw(t, k), &t[k]);
                inline for (if (k < L) 0 else k - L + 1..@min(k, L)) |j| {
                    c.add(n, @bitCast(loadw(q, j)), load16(m, k - j));
                    n += 1;
                }
                var acc = c.total();
                if (k < L) {
                    const qk = narrow(mulLow(narrow(acc & wmask), n0) & wmask);
                    storew(q, k, @bitCast(qk));
                    acc += mulLow(qk, load16(m, 0));
                } else {
                    store(r, k - L, pack(acc & wmask));
                }
                carry = acc >> @splat(bits);
            }
            store(r, L - 1, pack(carry));
            store(r, L, 0);
        }

        // Same as BigInt28.mulTo(), in both lanes.
        pub fn mulTo(r: *Fe, a: *const Fe, b: *const Fe, m: *const Fe, n0: N0) void {
            var t: Wide = undefined;
            var q: Q = undefined;
            @call(.never_inline, productInto, .{ &t, a, b });
            @call(.never_inline, redcInto, .{ r, &t, &q, m, n0 });
        }

        pub fn sqrTo(r: *Fe, a: *const Fe, m: *const Fe, n0: N0) void {
            var t: Wide = undefined;
            var q: Q = undefined;
            @call(.never_inline, squareInto, .{ &t, a });
            @call(.never_inline, redcInto, .{ r, &t, &q, m, n0 });
        }

        pub fn mul(a: *const Fe, b: *const Fe, m: *const Fe, n0: N0) Fe {
            var r: Fe = undefined;
            mulTo(&r, a, b, m, n0);
            return r;
        }
    };
}

// The signature tests cover the rest.
// They never reach the largest inputs, 2m - 1, which leave the least room in the column sums.
fn expectLargestInputs(comptime N: usize, d: anytype) !void {
    const T = BigInt28(N);
    const X = BigInt28x2(N);
    const k = try key.Key(N, true).fromHex(d.p_hex, d.q_hex, d.dp_hex, d.dq_hex, d.qinv_hex);
    const np = T.n0inv(k.p_n0inv);
    const nq = T.n0inv(k.q_n0inv);

    var big: [2]T.Fe = .{ k.p28, k.q28 };
    for (&big) |*x| {
        var carry: u64 = 0;
        for (x) |*v| {
            const s = 2 * v.* + carry;
            v.* = s & mask;
            carry = s >> bits;
        }
        x[0] -= 1;
    }

    // 2p - 1 is -1 mod p, so its square is 1.
    const sp = T.sqr(&big[0], &k.p28, np);
    try std.testing.expectEqual(sp, T.mul(&big[0], &big[0], &k.p28, np));
    try std.testing.expectEqual(T.fromMont(&T.mul(&T.one, &T.one, &k.p28, np), &k.p28, &k.p, np), T.fromMont(&sp, &k.p28, &k.p, np));

    var x = X.join(&big[0], &big[1]);
    X.sqrTo(&x, &x, &X.join(&k.p28, &k.q28), X.n0pair(np, nq));
    try std.testing.expectEqual(sp, X.lane(&x, 0));
    try std.testing.expectEqual(T.sqr(&big[1], &k.q28, nq), X.lane(&x, 1));
}

test "largest inputs" {
    try expectLargestInputs(16, key.default2048);
    try expectLargestInputs(24, key.default3072);
    try expectLargestInputs(32, key.default4096);
}
