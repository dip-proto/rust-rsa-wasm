const std = @import("std");

pub fn build(b: *std.Build) void {
    // Wide arithmetic makes signing about 2.4-2.8x faster, but some wasm runtimes don't support it yet.
    // For those, -Dwide-arithmetic=false builds librsa_nowide.a, which the Rust crate links with its no-wide-arithmetic feature.
    //
    // The archive is named after the CPU features the build really ends up with, so -Dcpu can't produce a mislabeled one.
    // If -Dwide-arithmetic and -Dcpu disagree, the build fails.
    const wide_option = b.option(bool, "wide-arithmetic", "Use the wasm wide-arithmetic feature (default true; set false for old runtimes)");
    const default_query = std.Target.Query.parse(.{
        .arch_os_abi = "wasm32-freestanding",
        .cpu_features = if (wide_option orelse true) "lime1+simd128+wide_arithmetic" else "lime1+simd128",
    }) catch unreachable;
    const target = b.standardTargetOptions(.{ .default_target = default_query });
    const is_wasm = target.result.cpu.arch.isWasm();
    const wide = is_wasm and std.Target.wasm.featureSetHas(target.result.cpu.features, .wide_arithmetic);
    const optimize = b.option(std.lang.Optimize, "optimize", "Optimization mode (default fast)") orelse .fast;

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("rsa_ffi.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    const lib = b.addLibrary(.{
        .name = if (is_wasm and !wide) "rsa_nowide" else "rsa",
        .linkage = .static,
        .root_module = lib_mod,
    });
    if (wide_option) |requested| {
        if (is_wasm and requested != wide) {
            lib.step.dependOn(&b.addFail("-Dwide-arithmetic doesn't match the CPU features from -Dtarget/-Dcpu").step);
        }
    }
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("rsa.zig"),
            .target = b.resolveTargetQuery(.{}), // native
            .optimize = optimize,
        }),
    });
    const test_step = b.step("test", "Run native correctness tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
