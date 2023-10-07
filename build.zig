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
    pure_c.addCSourceFiles(&.{"c-impl/pure.c"}, &.{"-std=c89"});
    //pure_c.addIncludePath(.{ .path = "zlib" });
    pure_c.linkLibrary(libz);
    b.installArtifact(pure_c);

    const pure = b.addStaticLibrary(.{
        .name = "pure",
        .root_source_file = .{ .path = "src/pure.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(pure);

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
