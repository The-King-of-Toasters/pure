const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // pure Zig library
    _ = b.addModule("pure", .{ .root_source_file = .{ .path = "src/root.zig" } });

    // pure Zig CLI
    const exe = b.addExecutable(.{
        .name = "pure",
        .target = target,
        .optimize = optimize,
        .root_source_file = .{ .path = "src/main.zig" },
    });
    b.installArtifact(exe);
    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_exe.addArgs(args);
    }
    const run_step = b.step("run", "Run pure CLI");
    run_step.dependOn(&run_exe.step);

    // C library depends on zlib
    const zlib = b.dependency("zlib", .{ .target = target, .optimize = optimize });

    // original pure C library
    const pure_c = b.addStaticLibrary(.{
        .name = "purec",
        .target = target,
        .optimize = optimize,
        .pic = true,
    });
    pure_c.addCSourceFile(.{
        .file = .{ .path = "c-impl/pure.c" },
        .flags = &.{"-std=c89"},
    });
    pure_c.linkLibrary(zlib.artifact("z"));

    // regression tests use libzip's regression testing data
    var libzip = b.dependency("libzip", .{});
    var regress_opts = b.addOptions();
    regress_opts.addOptionPath("regression_zip_dir", libzip.path("regress"));

    // test suite
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });
    tests.linkLibrary(zlib.artifact("z"));
    tests.linkLibrary(pure_c);
    tests.root_module.addOptions("regress", regress_opts);

    const run_unit_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
