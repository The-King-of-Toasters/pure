const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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

    const exe = b.addExecutable(.{
        .name = "pure",
        .root_source_file = .{ .path = "src/cli.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libz);
    exe.linkLibrary(pure_c);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args|
        run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the purity test");
    run_step.dependOn(&run_cmd.step);
}
