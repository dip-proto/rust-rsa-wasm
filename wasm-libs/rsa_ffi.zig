const std = @import("std");
const rsa = @import("rsa.zig");

pub const std_options: std.Options = .{ .side_channels_mitigations = .none };

const R2048 = rsa.Rsa(2048);
const R3072 = rsa.Rsa(3072);
const R4096 = rsa.Rsa(4096);

// The signing key keeps its precomputed Montgomery constants, so the Rust side
// owns the serialized key struct as an opaque, properly aligned byte buffer and
// hands a pointer to it back on every sign call. Only this code interprets the
// bytes, so the layout never crosses the FFI boundary as anything but a size.
fn keyBytes(comptime R: type) usize {
    return @sizeOf(R.Key);
}

fn keyInit(
    comptime R: type,
    out: [*c]u8,
    p: [*c]const u8,
    p_len: usize,
    q: [*c]const u8,
    q_len: usize,
    dp: [*c]const u8,
    dp_len: usize,
    dq: [*c]const u8,
    dq_len: usize,
    qinv: [*c]const u8,
    qinv_len: usize,
) i32 {
    const k = R.Key.fromBytes(
        p[0..p_len],
        q[0..q_len],
        dp[0..dp_len],
        dq[0..dq_len],
        qinv[0..qinv_len],
    ) catch return -1;
    const kp: *R.Key = @ptrCast(@alignCast(out));
    kp.* = k;
    return 0;
}

fn signWith(comptime R: type, sig: [*c]u8, k: [*c]const u8, msg: [*c]const u8, msg_len: usize) void {
    const kp: *const R.Key = @ptrCast(@alignCast(k));
    const s = R.sign(kp, msg[0..msg_len]);
    @memcpy(sig[0..R.signature_len], &s);
}

fn verifyWith(
    comptime R: type,
    n: [*c]const u8,
    n_len: usize,
    e: u64,
    msg: [*c]const u8,
    msg_len: usize,
    sig: [*c]const u8,
    sig_len: usize,
) i32 {
    return if (R.verify(n[0..n_len], e, msg[0..msg_len], sig[0..sig_len])) 1 else 0;
}

// RSA-2048

export fn rsa2048_key_bytes() callconv(.c) usize {
    return keyBytes(R2048);
}
export fn rsa2048_key_init(out: [*c]u8, p: [*c]const u8, p_len: usize, q: [*c]const u8, q_len: usize, dp: [*c]const u8, dp_len: usize, dq: [*c]const u8, dq_len: usize, qinv: [*c]const u8, qinv_len: usize) callconv(.c) i32 {
    return keyInit(R2048, out, p, p_len, q, q_len, dp, dp_len, dq, dq_len, qinv, qinv_len);
}
export fn rsa2048_sign(sig: [*c]u8, k: [*c]const u8, msg: [*c]const u8, msg_len: usize) callconv(.c) void {
    signWith(R2048, sig, k, msg, msg_len);
}
export fn rsa2048_verify(n: [*c]const u8, n_len: usize, e: u64, msg: [*c]const u8, msg_len: usize, sig: [*c]const u8, sig_len: usize) callconv(.c) i32 {
    return verifyWith(R2048, n, n_len, e, msg, msg_len, sig, sig_len);
}

// RSA-3072

export fn rsa3072_key_bytes() callconv(.c) usize {
    return keyBytes(R3072);
}
export fn rsa3072_key_init(out: [*c]u8, p: [*c]const u8, p_len: usize, q: [*c]const u8, q_len: usize, dp: [*c]const u8, dp_len: usize, dq: [*c]const u8, dq_len: usize, qinv: [*c]const u8, qinv_len: usize) callconv(.c) i32 {
    return keyInit(R3072, out, p, p_len, q, q_len, dp, dp_len, dq, dq_len, qinv, qinv_len);
}
export fn rsa3072_sign(sig: [*c]u8, k: [*c]const u8, msg: [*c]const u8, msg_len: usize) callconv(.c) void {
    signWith(R3072, sig, k, msg, msg_len);
}
export fn rsa3072_verify(n: [*c]const u8, n_len: usize, e: u64, msg: [*c]const u8, msg_len: usize, sig: [*c]const u8, sig_len: usize) callconv(.c) i32 {
    return verifyWith(R3072, n, n_len, e, msg, msg_len, sig, sig_len);
}

// RSA-4096

export fn rsa4096_key_bytes() callconv(.c) usize {
    return keyBytes(R4096);
}
export fn rsa4096_key_init(out: [*c]u8, p: [*c]const u8, p_len: usize, q: [*c]const u8, q_len: usize, dp: [*c]const u8, dp_len: usize, dq: [*c]const u8, dq_len: usize, qinv: [*c]const u8, qinv_len: usize) callconv(.c) i32 {
    return keyInit(R4096, out, p, p_len, q, q_len, dp, dp_len, dq, dq_len, qinv, qinv_len);
}
export fn rsa4096_sign(sig: [*c]u8, k: [*c]const u8, msg: [*c]const u8, msg_len: usize) callconv(.c) void {
    signWith(R4096, sig, k, msg, msg_len);
}
export fn rsa4096_verify(n: [*c]const u8, n_len: usize, e: u64, msg: [*c]const u8, msg_len: usize, sig: [*c]const u8, sig_len: usize) callconv(.c) i32 {
    return verifyWith(R4096, n, n_len, e, msg, msg_len, sig, sig_len);
}
