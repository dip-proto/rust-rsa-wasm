const std = @import("std");

pub fn build(b: *std.Build) void {
    // Match rsa-wasm exactly: wasm32-wasi, lime1+simd128+wide_arithmetic, .fast.
    // wide_arithmetic is what lets the Montgomery inner loop lower to i64.mul_wide_u
    // instead of a __multi3 helper, and it is worth ~2.4x on the signing benchmark.
    //
    // Older wasm runtimes do not implement the wide-arithmetic proposal and will
    // refuse to validate a module that uses it. Build with -Dwide-arithmetic=false
    // to drop the feature: bigint.zig then synthesizes the 64x64->128 product from
    // plain i64.mul, so the archive runs anywhere at the cost of the ~2.4x. The two
    // configs ship as separate archives, librsa.a and librsa_nowide.a.
    const wide = b.option(bool, "wide-arithmetic", "Use the wasm wide-arithmetic feature (default true; set false for old runtimes)") orelse true;
    const cpu_features = if (wide) "lime1+simd128+wide_arithmetic" else "lime1+simd128";
    const default_query = std.Target.Query.parse(.{
        .arch_os_abi = "wasm32-wasi",
        .cpu_features = cpu_features,
    }) catch unreachable;
    const target = b.standardTargetOptions(.{ .default_target = default_query });
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Optimization mode (default fast)") orelse .fast;

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("rsa_ffi.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    const lib = b.addLibrary(.{
        .name = if (wide) "rsa" else "rsa_nowide",
        .linkage = .static,
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // Native correctness tests for the signing and verification code.
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("rsa.zig"),
            .target = b.resolveTargetQuery(.{}),
            .optimize = optimize,
        }),
    });
    const test_step = b.step("test", "Run native correctness tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
