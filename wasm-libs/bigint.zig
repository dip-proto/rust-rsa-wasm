const std = @import("std");
const builtin = @import("builtin");

pub const Limb = u64;
pub const Wide = u128;

const is_wasm = builtin.target.cpu.arch.isWasm();
const has_wide_arithmetic = is_wasm and std.Target.wasm.featureSetHas(builtin.target.cpu.features, .wide_arithmetic);

// 64x64 -> 128-bit product, as { low, high }.
// Without wide arithmetic, wasm would turn this into a slow __multi3 call, so it uses mul64Portable instead.
pub inline fn mul64(a: Limb, b: Limb) [2]Limb {
    if (is_wasm and !has_wide_arithmetic) return mul64Portable(a, b);
    const w = @as(Wide, a) * @as(Wide, b);
    return .{ @truncate(w), @intCast(w >> 64) };
}

// Same thing, using only regular 64-bit multiplies.
inline fn mul64Portable(a: Limb, b: Limb) [2]Limb {
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

// Operations on private key material.
// They run in constant time unless side-channel mitigations are turned off.
pub const ct = if (std.options.side_channels_mitigations == .none) ct_unprotected else ct_protected;

inline fn subWithBorrow(a: anytype, b: *const @TypeOf(a.*)) Limb {
    var borrow: Wide = 0;
    inline for (0..a.len) |i| {
        const d = @as(Wide, a[i]) -% @as(Wide, b[i]) -% borrow;
        a[i] = @truncate(d);
        borrow = (d >> 64) & 1;
    }
    return @intCast(borrow);
}

const ct_protected = struct {
    // Keeps the compiler from seeing that a mask is either all zeros or all ones.
    // If it can see that, it turns the selection back into a branch.
    fn barrier(x: Limb) Limb {
        var v = x;
        asm (""
            : [v] "+r" (v),
        );
        return v;
    }

    fn mask(on: bool) Limb {
        return barrier(@as(Limb, 0) -% @intFromBool(on));
    }

    pub fn geq(a: anytype, b: *const @TypeOf(a.*)) bool {
        var borrow: Wide = 0;
        inline for (0..a.len) |i| {
            borrow = ((@as(Wide, a[i]) -% @as(Wide, b[i]) -% borrow) >> 64) & 1;
        }
        return borrow == 0;
    }

    // Subtracts m from a if a, with `top` (0 or 1) as an extra high limb, is at least m.
    // It runs after every multiplication, and wasmer's LLVM backend is much slower when it isn't inlined.
    pub inline fn reduceOnce(a: anytype, top: Limb, m: *const @TypeOf(a.*)) void {
        var d = a.*;
        const borrow = subWithBorrow(&d, m);
        const take = mask((top | (borrow ^ 1)) != 0);
        inline for (0..a.len) |i| a[i] ^= (a[i] ^ d[i]) & take;
    }

    pub fn addIf(on: bool, a: anytype, m: *const @TypeOf(a.*)) void {
        const take = mask(on);
        var carry: Wide = 0;
        inline for (0..a.len) |i| {
            const s = @as(Wide, a[i]) + @as(Wide, m[i] & take) + carry;
            a[i] = @truncate(s);
            carry = s >> 64;
        }
    }

    // Returns table[index], reading every entry.
    pub fn lookup(table: anytype, index: usize) @TypeOf(table[0]) {
        const V = @Vector(table[0].len, Limb);
        var r: V = @splat(0);
        for (table, 0..) |*entry, i| {
            r |= @as(V, entry.*) & @as(V, @splat(mask(i == index)));
        }
        return r;
    }
};

const ct_unprotected = struct {
    pub inline fn geq(a: anytype, b: *const @TypeOf(a.*)) bool {
        var i: usize = a.len;
        while (i > 0) {
            i -= 1;
            if (a[i] != b[i]) return a[i] > b[i];
        }
        return true;
    }

    pub inline fn reduceOnce(a: anytype, top: Limb, m: *const @TypeOf(a.*)) void {
        if (top != 0 or geq(a, m)) _ = subWithBorrow(a, m);
    }

    pub inline fn addIf(on: bool, a: anytype, m: *const @TypeOf(a.*)) void {
        if (on) {
            var carry: Wide = 0;
            inline for (0..a.len) |i| {
                const s = @as(Wide, a[i]) + @as(Wide, m[i]) + carry;
                a[i] = @truncate(s);
                carry = s >> 64;
            }
        }
    }
};

// Fixed-size math on N 64-bit limbs, lowest limb first.
// Signing uses it at half the modulus size (one CRT prime).
pub fn BigInt(comptime N: usize) type {
    return BigIntWith(N, ct);
}

// Same as BigInt, but never constant time.
// Verification uses it at full size, since everything there is public.
pub fn PublicBigInt(comptime N: usize) type {
    return BigIntWith(N, ct_unprotected);
}

fn BigIntWith(comptime N: usize, comptime ct_: type) type {
    return struct {
        // On WebAssembly, constant-time squaring isn't inlined.
        // Otherwise, the exponentiation loop gets huge and slow.
        const square_call: std.builtin.CallModifier = if (is_wasm and ct_ == ct_protected) .never_inline else .auto;

        pub const limbs = N;
        pub const Fe = [N]Limb;
        pub const zero: Fe = @splat(0);
        pub const one: Fe = blk: {
            var o: Fe = @splat(0);
            o[0] = 1;
            break :blk o;
        };

        // Shorter inputs are treated as having leading zeros.
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

        pub fn toBytesBE(a: *const Fe) [8 * N]u8 {
            var bytes: [8 * N]u8 = undefined;
            for (0..N) |i| {
                std.mem.writeInt(Limb, bytes[8 * N - 8 * (i + 1) ..][0..8], a[i], .big);
            }
            return bytes;
        }

        // R^2 mod m (R = 2^(64*N)), used to put values in Montgomery form.
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
                ct_.reduceOnce(&acc, carry, m);
            }
            return acc;
        }

        pub inline fn geq(a: *const Fe, b: *const Fe) bool {
            return ct_.geq(a, b);
        }

        pub inline fn condSub(a: *Fe, m: *const Fe) void {
            ct_.reduceOnce(a, 0, m);
        }

        pub inline fn addModNoMont(a: *const Fe, b: *const Fe, m: *const Fe) Fe {
            var r: Fe = undefined;
            var carry: Limb = 0;
            inline for (0..N) |i| {
                const s = @as(Wide, a[i]) + @as(Wide, b[i]) + @as(Wide, carry);
                r[i] = @truncate(s);
                carry = @intCast(s >> 64);
            }
            // Don't ignore the carry: if the sum overflowed, it's already above m.
            ct_.reduceOnce(&r, carry, m);
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
            ct_.addIf(borrow != 0, &r, m);
            return r;
        }

        // a * b * R^-1 mod m, with a and b both below m.
        pub fn montMul(a: *const Fe, b: *const Fe, m: *const Fe, n0inv: Limb) Fe {
            @setEvalBranchQuota(20000);
            var t: [N + 1]Limb = @splat(0);
            var tn: Limb = 0; // top limb of t
            for (0..N) |i| {
                const ai = a[i];
                var c: Limb = 0;
                inline for (0..N) |j| {
                    const prod = mulWide(ai, b[j]) + @as(Wide, t[j]) + @as(Wide, c);
                    t[j] = @truncate(prod);
                    c = @intCast(prod >> 64);
                }
                const s0 = @as(Wide, tn) + @as(Wide, c);
                const tcarry: Limb = @intCast(s0 >> 64);

                // Add the multiple of m that zeroes the low limb, then drop that limb.
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
            // The result is below 2m, so one subtraction is enough.
            ct_.reduceOnce(&r, tn, m);
            return r;
        }

        // Same as mulFull(a, a), with about half the multiplies.
        // Each cross product a[i]*a[j] is computed once and doubled.
        pub fn sqrFull(a: *const Fe) [2 * N]Limb {
            @setEvalBranchQuota(20000);
            var r: [2 * N]Limb = @splat(0);
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
            var carry: Limb = 0;
            inline for (0..2 * N) |i| {
                const nc = r[i] >> 63;
                r[i] = (r[i] << 1) | carry;
                carry = nc;
            }
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

        // T * R^-1 mod m, for any T below m*R, like the square of a number below m.
        pub fn redc(tin: *const [2 * N]Limb, m: *const Fe, n0inv: Limb) Fe {
            @setEvalBranchQuota(20000);
            var t: [2 * N + 1]Limb = undefined;
            @memcpy(t[0 .. 2 * N], tin);
            t[2 * N] = 0;
            var top: Limb = 0;
            for (0..N) |i| {
                const mh: Limb = t[i] *% n0inv;
                var c: Limb = 0;
                inline for (0..N) |j| {
                    const prod = mulWide(mh, m[j]) + @as(Wide, t[i + j]) + @as(Wide, c);
                    t[i + j] = @truncate(prod);
                    c = @intCast(prod >> 64);
                }
                // Constant-time code keeps the carry for the next step, instead of a loop whose length depends on the data.
                // From 32 limbs (4096-bit keys), that's faster anyway, so it's used either way.
                if (ct_ == ct_unprotected and N < 32) {
                    var k: usize = i + N;
                    while (c != 0) : (k += 1) {
                        const s = @as(Wide, t[k]) + @as(Wide, c);
                        t[k] = @truncate(s);
                        c = @intCast(s >> 64);
                    }
                } else {
                    const s = @as(Wide, t[i + N]) + @as(Wide, c) + @as(Wide, top);
                    t[i + N] = @truncate(s);
                    top = @intCast(s >> 64);
                }
            }
            t[2 * N] += top;
            var r: Fe = t[N .. 2 * N].*;
            ct_.reduceOnce(&r, t[2 * N], m);
            return r;
        }

        pub inline fn montSqr(a: *const Fe, m: *const Fe, n0inv: Limb) Fe {
            const s = @call(square_call, sqrFull, .{a});
            return @call(square_call, redc, .{ &s, m, n0inv });
        }

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

fn testCt(ct_: anytype) !void {
    const m: [2]Limb = .{ 5, 1 };
    var a = m;
    try std.testing.expect(ct_.geq(&a, &m));
    ct_.reduceOnce(&a, 0, &m);
    try std.testing.expectEqual([2]Limb{ 0, 0 }, a);

    a = .{ 4, 1 };
    try std.testing.expect(!ct_.geq(&a, &m));
    ct_.reduceOnce(&a, 0, &m);
    try std.testing.expectEqual([2]Limb{ 4, 1 }, a);
    ct_.reduceOnce(&a, 1, &m);
    try std.testing.expectEqual([2]Limb{ std.math.maxInt(Limb), std.math.maxInt(Limb) }, a);

    ct_.addIf(false, &a, &m);
    try std.testing.expectEqual([2]Limb{ std.math.maxInt(Limb), std.math.maxInt(Limb) }, a);
    ct_.addIf(true, &a, &m);
    try std.testing.expectEqual([2]Limb{ 4, 1 }, a);
}

test ct {
    try testCt(ct_protected);
    try testCt(ct_unprotected);
}

// Native builds never use mul64Portable, so test it directly.
test "mul64Portable matches the 128-bit product" {
    var prng: std.Random.DefaultPrng = .init(0);
    var values: [64]Limb = undefined;
    for (&values) |*v| v.* = prng.random().int(Limb);
    values[0..4].* = .{ 0, 1, 0xffff_ffff, std.math.maxInt(Limb) };
    for (values) |a| {
        for (values) |b| {
            const w = @as(Wide, a) * @as(Wide, b);
            try std.testing.expectEqual([2]Limb{ @truncate(w), @intCast(w >> 64) }, mul64Portable(a, b));
        }
    }
}
