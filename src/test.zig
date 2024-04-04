const std = @import("std");
const mem = std.mem;
const io = std.io;
const fmt = std.fmt;
const testing = std.testing;

const pure = @import("pure.zig");

const TestOptions = struct {
    signature: [4]u8 = .{ 0x50, 0x4b, 0x05, 0x06 },
    disk: u16 = 0,
    disk_records: u16 = 0,
    records: u16 = 0,
    size: u32 = 0,
    offset: u32 = 0,
    comment: []const u8 = "",
    reset_buffer: bool = true,
};

const FbsType = io.FixedBufferStream([]u8);

fn writeEocdr(fbs: *FbsType, opts: TestOptions) void {
    if (opts.reset_buffer)
        fbs.reset();
    const writer = fbs.writer();

    writer.writeAll(&opts.signature) catch unreachable;
    writer.writeInt(u16, 0, .little) catch unreachable; // disk
    writer.writeInt(u16, opts.disk, .little) catch unreachable; // cd_disk
    writer.writeInt(u16, opts.disk_records, .little) catch unreachable; // cd_disk_records
    writer.writeInt(u16, opts.records, .little) catch unreachable; // cd_records
    writer.writeInt(u32, opts.size, .little) catch unreachable; // cd_size
    writer.writeInt(u32, opts.offset, .little) catch unreachable; // cd_offset
    writer.writeInt(u16, @intCast(opts.comment.len), .little) catch unreachable;
    writer.writeAll(opts.comment) catch unreachable;
}

fn testFailure(buf: []const u8, err: pure.errors) !void {
    try testing.expectError(err, pure.zip(buf, testing.allocator));
}

test "foo" {
    var buf = mem.zeroes([4096]u8);
    var fbs = io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    {
        writeEocdr(&fbs, .{});
        try pure.zip(fbs.getWritten(), testing.allocator);
    }
    {
        writeEocdr(&fbs, .{});
        try testFailure(fbs.getWritten()[0..21], error.TooSmall);
    }
    {
        const bytes = fmt.hexToBytes(
            &buf,
            "526172211a0700000000000000000000000000000000",
        ) catch unreachable;
        try testFailure(bytes, error.Rar);
    }
    {
        const bytes = fmt.hexToBytes(
            &buf,
            "75737461720000000000000000000000000000000000",
        ) catch unreachable;
        try testFailure(bytes, error.Tar);
    }
    {
        const bytes = fmt.hexToBytes(
            &buf,
            "78617221000000000000000000000000000000000000",
        ) catch unreachable;
        try testFailure(bytes, error.Xar);
    }
    {
        writeEocdr(&fbs, .{ .signature = .{ 0x50, 0x4b, 0x05, 0x05 } });
        try testFailure(fbs.getWritten(), error.EocdrNotFound);
    }
    {
        writeEocdr(&fbs, .{ .records = 2, .size = 46 * 2 - 1 });
        try testFailure(fbs.getWritten(), error.EocdrSizeOverflow);
    }
    {
        writeEocdr(&fbs, .{ .records = 2, .size = 46 * 2 - 1 });
        try testFailure(fbs.getWritten(), error.EocdrSizeOverflow);
    }
    {
        writeEocdr(&fbs, .{ .records = 0, .size = 46 });
        try testFailure(fbs.getWritten(), error.EocdrSizeUnderflow);
    }
    {
        writeEocdr(&fbs, .{ .records = 1, .size = 46, .offset = 0 });
        try testFailure(fbs.getWritten(), error.CdEocdrOverflow);
    }
    {
        writeEocdr(&fbs, .{ .disk_records = 1, .records = 0 });
        try testFailure(fbs.getWritten(), error.EocdrRecords);
    }
    {
        writeEocdr(&fbs, .{ .disk = 1 });
        try testFailure(fbs.getWritten(), error.MultipleDisks);
    }
    {
        writeEocdr(&fbs, .{});
        writer.writeByteNTimes(0, 13) catch unreachable;
        try testFailure(fbs.getWritten(), error.AppendedDataZeroed);
        fbs.reset();
    }
    {
        writeEocdr(&fbs, .{ .reset_buffer = false });
        writer.writeByteNTimes(1, 97) catch unreachable;
        try testFailure(fbs.getWritten(), error.AppendedDataBufferBleed);
        fbs.reset();
    }
    {
        writeEocdr(&fbs, .{ .reset_buffer = false });
        writer.writeByteNTimes(1, 97) catch unreachable;
        try testFailure(fbs.getWritten(), error.AppendedDataBufferBleed);
        fbs.reset();
    }
    {
        writer.writeByteNTimes(1, 2048) catch unreachable;
        writeEocdr(&fbs, .{ .reset_buffer = false });
        try testFailure(fbs.getWritten(), error.PrependedData);
        fbs.reset();
    }
    {
        writer.writeByteNTimes(1, 1) catch unreachable;
        writeEocdr(&fbs, .{ .reset_buffer = false });
        try testFailure(fbs.getWritten(), error.PrependedDataBufferBleed);
        fbs.reset();
    }
    {
        writer.writeByteNTimes(0, 1) catch unreachable;
        writeEocdr(&fbs, .{ .reset_buffer = false });
        try testFailure(fbs.getWritten(), error.PrependedDataZeroed);
        fbs.reset();
    }
}
