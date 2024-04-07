/// CLI utility for testing ZIP files
const std = @import("std");
const pure = @import("root.zig");

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = gpa.deinit();
    }
    const a = gpa.allocator();
    var args = std.process.args();
    std.debug.assert(args.skip()); // program name
    const fname = args.next() orelse {
        try printHelp();
        return 1;
    };
    if (std.mem.eql(u8, fname, "--help") or std.mem.eql(u8, fname, "-h")) {
        try printHelp();
        return 0;
    }
    var diags: pure.Diagnostics = .{};
    const f = try std.fs.cwd().openFile(fname, .{});
    defer f.close();
    const stat = try f.stat();
    const buffer = try std.posix.mmap(null, stat.size, std.posix.PROT.READ, std.posix.MAP{ .TYPE = .PRIVATE }, f.handle, 0);
    errdefer {
        std.posix.munmap(buffer);
    }
    if (pure.zip(buffer, a, .{ .diagnostics = &diags })) {
        try std.io.getStdOut().writeAll("ok\n");
        return 0;
    } else |_| {
        const st = diags.subtype.?;
        try std.fmt.format(std.io.getStdErr().writer(), "{s}: {s}\n", .{ @tagName(st), st.message() });
        return 1;
    }
}

fn printHelp() !void {
    try std.fmt.format(std.io.getStdOut(),
        \\Usage: pure [zipfile]
        \\
    , .{});
}
