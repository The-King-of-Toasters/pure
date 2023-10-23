const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pure = b.addStaticLibrary(.{
        .name = "pure",
        .root_source_file = .{ .path = "src/pure.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(pure);

    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/test.zig" },
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const zlib = b.dependency("zlib", .{ .target = target, .optimize = optimize });
    const libz = zlib.artifact("z");

    const pure_c = b.addStaticLibrary(.{
        .name = "purec",
        .target = target,
        .optimize = optimize,
    });
    pure_c.force_pic = true;
    pure_c.addCSourceFile(.{ .file = .{ .path = "c-impl/pure.c" }, .flags = &[_][]const u8{"-std=c89"} });
    pure_c.linkLibrary(libz);
    b.installArtifact(pure_c);

    const regress_exe = b.addExecutable(.{
        .name = "pure",
        .root_source_file = .{ .path = "src/regress.zig" },
        .target = target,
        .optimize = optimize,
    });
    var libzip = b.dependency("libzip", .{});
    var regress_opts = b.addOptions();
    regress_opts.addOptionPath("regression_zip_dir", libzip.path("regress"));
    regress_exe.linkLibrary(libz);
    regress_exe.linkLibrary(pure_c);
    regress_exe.addOptions("regress", regress_opts);
    b.installArtifact(regress_exe);

    const run_cmd = b.addRunArtifact(regress_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args|
        run_cmd.addArgs(args);

    const regress_step = b.step("regress", "Run the regression test against C version");
    regress_step.dependOn(&run_cmd.step);
}
