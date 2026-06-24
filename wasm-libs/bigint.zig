const std = @import("std");
const builtin = @import("builtin");

pub const Limb = u64;
pub const Wide = u128;

// 64x64 -> 128 widening multiply built from i64.mul only. The compiler otherwise
// lowers a u128*u128 product to a __multi3 runtime call, which is fatal in the
// Montgomery inner loop.
const is_wasm = builtin.target.cpu.arch.isWasm();
const has_wide_arithmetic = is_wasm and std.Target.wasm.featureSetHas(builtin.target.cpu.features, .wide_arithmetic);

pub inline fn mul64(a: Limb, b: Limb) [2]Limb {
    if (!is_wasm or has_wide_arithmetic) {
        // Native targets and wasm wide-arithmetic can lower this directly.
        const w = @as(Wide, a) * @as(Wide, b);
        return .{ @truncate(w), @intCast(w >> 64) };
    }
    // wasm has no 64x64->128 and lowers u128*u128 to a __multi3 runtime call,
    // so build the widening product from i64.mul only.
    const a0: Limb = a & 0xffff_ffff;
    const a1: Limb = a >> 32;
    const b0: Limb = b & 0xffff_ffff;
    const b1: Limb = b >> 32;
    const ll = a0 * b0;
    const lh = a0 * b1;
    const hl = a1 * b0;
    const hh = a1 * b1;
    const mid = (ll >> 32) + (lh & 0xffff_ffff) + (hl & 0xffff_ffff);
    const lo = (ll & 0xffff_ffff) | (mid << 32);
    const hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    return .{ lo, hi };
}
pub inline fn mulWide(a: Limb, b: Limb) Wide {
    const r = mul64(a, b);
    return (@as(Wide, r[1]) << 64) | r[0];
}

// Fixed-size limb arithmetic for an N-limb integer, instantiated at comptime for
// each modulus size. The arithmetic operates on a single CRT prime (half the
// modulus): N = 16 for RSA-2048, 24 for RSA-3072, 32 for RSA-4096. With N a
// compile-time constant every `inline for (0..N)` fully unrolls, so each
// instantiation is exactly the specialized code that a hand-written, size-fixed
// version would produce.
pub fn BigInt(comptime N: usize) type {
    return struct {
        pub const limbs = N;
        pub const Fe = [N]Limb; // a field element / N-limb integer
        pub const zero: Fe = @splat(0);
        pub const one: Fe = blk: {
            var o: Fe = @splat(0);
            o[0] = 1;
            break :blk o;
        };

        // Big-endian bytes (at most N limbs wide) into little-endian limbs. The
        // caller guarantees be.len <= 8*N; shorter inputs are right-aligned, so
        // leading-zero-trimmed values still land in the low limbs.
        pub fn fromBytesBE(be: []const u8) Fe {
            std.debug.assert(be.len <= 8 * N);
            var bytes: [8 * N]u8 = @splat(0);
            @memcpy(bytes[8 * N - be.len ..], be);
            var fe: Fe = undefined;
            for (0..N) |i| {
                fe[i] = std.mem.readInt(Limb, bytes[8 * N - 8 * (i + 1) ..][0..8], .big);
            }
            return fe;
        }

        // Little-endian limbs into big-endian bytes (I2OSP).
        pub fn toBytesBE(a: *const Fe) [8 * N]u8 {
            var bytes: [8 * N]u8 = undefined;
            for (0..N) |i| {
                std.mem.writeInt(Limb, bytes[8 * N - 8 * (i + 1) ..][0..8], a[i], .big);
            }
            return bytes;
        }

        // R^2 mod m with R = 2^(64*N): start at 1 and double mod m 2*64*N times.
        pub fn rSquared(m: *const Fe) Fe {
            var acc: Fe = zero;
            acc[0] = 1;
            for (0..2 * 64 * N) |_| {
                var carry: Limb = 0;
                for (0..N) |i| {
                    const nc = acc[i] >> 63;
                    acc[i] = (acc[i] << 1) | carry;
                    carry = nc;
                }
                if (carry != 0 or geq(&acc, m)) subInPlace(&acc, m);
            }
            return acc;
        }

        pub inline fn geq(a: *const Fe, b: *const Fe) bool {
            var i: usize = N;
            while (i > 0) {
                i -= 1;
                if (a[i] != b[i]) return a[i] > b[i];
            }
            return true;
        }

        inline fn subInPlace(a: *Fe, m: *const Fe) void {
            var borrow: Wide = 0;
            inline for (0..N) |i| {
                const d = @as(Wide, a[i]) -% @as(Wide, m[i]) -% borrow;
                a[i] = @truncate(d);
                borrow = (d >> 64) & 1;
            }
        }

        pub inline fn condSub(a: *Fe, m: *const Fe) void {
            if (geq(a, m)) subInPlace(a, m);
        }

        pub inline fn addModNoMont(a: *const Fe, b: *const Fe, m: *const Fe) Fe {
            var r: Fe = undefined;
            var carry: Limb = 0;
            inline for (0..N) |i| {
                const s = @as(Wide, a[i]) + @as(Wide, b[i]) + @as(Wide, carry);
                r[i] = @truncate(s);
                carry = @intCast(s >> 64);
            }
            // Sum may be N+1 limbs (carry out). value = carry*R + r < 2m, so subtract
            // m when there is a carry OR the low part already exceeds m.
            if (carry != 0 or geq(&r, m)) subInPlace(&r, m);
            return r;
        }

        pub inline fn subMod(a: *const Fe, b: *const Fe, m: *const Fe) Fe {
            var r: Fe = undefined;
            var borrow: Wide = 0;
            inline for (0..N) |i| {
                const d = @as(Wide, a[i]) -% @as(Wide, b[i]) -% borrow;
                r[i] = @truncate(d);
                borrow = (d >> 64) & 1;
            }
            if (borrow != 0) {
                var carry: Wide = 0;
                inline for (0..N) |i| {
                    const s = @as(Wide, r[i]) + @as(Wide, m[i]) + carry;
                    r[i] = @truncate(s);
                    carry = s >> 64;
                }
            }
            return r;
        }

        // CIOS Montgomery multiplication: returns a*b*R^{-1} mod m, with R = 2^(64*N).
        pub fn montMul(a: *const Fe, b: *const Fe, m: *const Fe, n0inv: Limb) Fe {
            @setEvalBranchQuota(20000);
            var t: [N + 1]Limb = @splat(0);
            var tn: Limb = 0; // t[N]
            for (0..N) |i| {
                const ai = a[i];
                // t += a[i] * b
                var c: Limb = 0;
                inline for (0..N) |j| {
                    const prod = mulWide(ai, b[j]) + @as(Wide, t[j]) + @as(Wide, c);
                    t[j] = @truncate(prod);
                    c = @intCast(prod >> 64);
                }
                const s0 = @as(Wide, tn) + @as(Wide, c);
                const tcarry: Limb = @intCast(s0 >> 64);

                // m_hat = t[0] * n0inv mod 2^64; t = (t + m_hat*m) / 2^64
                const mh: Limb = t[0] *% n0inv;
                var c2: Limb = @intCast((mulWide(mh, m[0]) + @as(Wide, t[0])) >> 64);
                inline for (1..N) |j| {
                    const prod = mulWide(mh, m[j]) + @as(Wide, t[j]) + @as(Wide, c2);
                    t[j - 1] = @truncate(prod);
                    c2 = @intCast(prod >> 64);
                }
                const s1 = @as(Wide, @as(Limb, @truncate(s0))) + @as(Wide, c2);
                t[N - 1] = @truncate(s1);
                tn = tcarry + @as(Limb, @intCast(s1 >> 64));
            }
            var r: Fe = t[0..N].*;
            // result < 2m; one conditional subtraction (tn is 0 or 1)
            if (tn != 0 or geq(&r, m)) subInPlace(&r, m);
            return r;
        }

        // Squaring with the i<j symmetry: ~N^2/2 limb products instead of N^2.
        pub fn sqrFull(a: *const Fe) [2 * N]Limb {
            @setEvalBranchQuota(20000);
            var r: [2 * N]Limb = @splat(0);
            // off-diagonal sum_{i<j} a[i]*a[j]
            inline for (0..N) |i| {
                var c: Limb = 0;
                const ai = a[i];
                inline for (i + 1..N) |j| {
                    const prod = mulWide(ai, a[j]) + @as(Wide, r[i + j]) + @as(Wide, c);
                    r[i + j] = @truncate(prod);
                    c = @intCast(prod >> 64);
                }
                r[i + N] = c;
            }
            // double the off-diagonal part
            var carry: Limb = 0;
            inline for (0..2 * N) |i| {
                const nc = r[i] >> 63;
                r[i] = (r[i] << 1) | carry;
                carry = nc;
            }
            // add the diagonal a[i]^2
            var c2: Wide = 0;
            inline for (0..N) |i| {
                const sq = mulWide(a[i], a[i]);
                var s = @as(Wide, r[2 * i]) + (sq & 0xffff_ffff_ffff_ffff) + c2;
                r[2 * i] = @truncate(s);
                s = @as(Wide, r[2 * i + 1]) + (sq >> 64) + (s >> 64);
                r[2 * i + 1] = @truncate(s);
                c2 = s >> 64;
            }
            return r;
        }

        // Montgomery reduction of a 2N-limb value: returns T * R^{-1} mod m in [0, m).
        pub fn redc(tin: *const [2 * N]Limb, m: *const Fe, n0inv: Limb) Fe {
            @setEvalBranchQuota(20000);
            var t: [2 * N + 1]Limb = undefined;
            @memcpy(t[0 .. 2 * N], tin);
            t[2 * N] = 0;
            for (0..N) |i| {
                const mh: Limb = t[i] *% n0inv;
                var c: Limb = 0;
                inline for (0..N) |j| {
                    const prod = mulWide(mh, m[j]) + @as(Wide, t[i + j]) + @as(Wide, c);
                    t[i + j] = @truncate(prod);
                    c = @intCast(prod >> 64);
                }
                // propagate carry c through the upper words
                var k: usize = i + N;
                while (c != 0) : (k += 1) {
                    const s = @as(Wide, t[k]) + @as(Wide, c);
                    t[k] = @truncate(s);
                    c = @intCast(s >> 64);
                }
            }
            var r: Fe = t[N .. 2 * N].*;
            if (t[2 * N] != 0 or geq(&r, m)) subInPlace(&r, m);
            return r;
        }

        pub inline fn montSqr(a: *const Fe, m: *const Fe, n0inv: Limb) Fe {
            const s = sqrFull(a);
            return redc(&s, m, n0inv);
        }

        // Full schoolbook multiply: (a[N]) * (b[N]) -> r[2N]
        pub fn mulFull(a: *const Fe, b: *const Fe) [2 * N]Limb {
            var r: [2 * N]Limb = @splat(0);
            for (0..N) |i| {
                var c: Limb = 0;
                const ai = a[i];
                for (0..N) |j| {
                    const prod = mulWide(ai, b[j]) + @as(Wide, r[i + j]) + @as(Wide, c);
                    r[i + j] = @truncate(prod);
                    c = @intCast(prod >> 64);
                }
                r[i + N] = c;
            }
            return r;
        }
    };
}
