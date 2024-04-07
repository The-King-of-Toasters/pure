# Pure, the Zig port

This is a WIP port of Joran Dirk Greef's `pure`, a static-analysis tool for Zip
files. The goal of this fork is to progressively refactor the code to be a
generic Zip reader, while still maintaining the quality of the original source.

## Why `pure`?

`pure` was written to protect against a slew of vulnerabilities that many Zip
implementations fall victim to. For example, a pre-release version was able was
able to [detect a hand-crafted
zip-bomb](https://news.ycombinator.com/item?id=20352439) on its release, without
any specific logic.

As a greenfield project, Zig aims to be [as good or
better](https://github.com/ziglang/zig/issues/15916) than other programming
languages in terms of safety and performance. I believe that `pure` establishes
a bar of quality that few Zip implementations have reached, and its acceptance
into the Zig standard library would put the language above most "better C"
projects.

## Using this Port

This source code produces an executable `pure` which is a port of the original 
CLI tool to zig. To build the tool run `zig build`, the executable it output to
`zig-out/bin/pure`. Run `zig-out/bin/pure --help` for usage.

The CLI tool is regression tested against the original C implementation, using 
the libzip regression testing suite. Run `zig build test` to run tests including
regression tests.

This source code can also be used as a zig library. Add this to your build.zig.zon:
```zig
        .pure = .{
            .url = "https://github.com/The-King-of-Toasters/pure/archive/refs/heads/zig-port.tar.gz",
            //.hash = "122040785c06695cbeab60f27343e85b18fad60719cb49f89f2730038e6a7ad8bf76",
        },
```
And this to your `build.zig`
```zig
    const pure = b.dependency("pure", .{});
    exe.root_module.addImport("pure", pure.module("pure"));
```
`zig build` will download the source code on first use. The `.hash` value may need
to be updated. You can change the download URL to a specific git commit hash to
pin the dependency at that commit.

The code contains a generic ZIP module which can be used like this:
```zig
const std = @import("std");
const pure = @import("pure");

// Naïve example of extracting a ZIP file
pub fn main() !void {
    const a = std.heap.page_allocator;
    var args = std.process.args();
    std.debug.assert(args.skip()); // program name
    const zipfilename = args.next() orelse return error.NoZipFile;
    const outdir: std.fs.Dir = if (args.next()) |arg| try std.fs.cwd().openDir(arg, .{}) else std.fs.cwd();
    const zipfile = try std.fs.cwd().openFile(zipfilename, .{});
    defer zipfile.close();
    var zip = try pure.Zip.init(a, zipfile, .{});
    defer zip.deinit();
    var i = zip.iterator();
    while (try i.next()) |e| {
        std.log.info("extracting {s} size: {}", .{ e.name, e.size });
        if (std.fs.path.dirname(e.name)) |dirname| {
            try outdir.makePath(dirname);
        }
        // Note this is not handling symlinks
        var outfile = try outdir.createFile(e.name, .{});
        defer outfile.close();
        var wtr = outfile.writer();
        var rdr = try e.reader();
        var buf: [std.mem.page_size]u8 = .{0} ** std.mem.page_size;
        while (true) {
            const sz = try rdr.read(&buf);
            if (sz == 0) break;
            try wtr.writeAll(buf[0..sz]);
        }
    }
}

```

The code also contains the `pure` CLI error checking function, see 
`src/main.zip` for how this is used.

## TODOs

- The original code would read the Zip structures by manually reading
  little-endian integers and incrementing an offset into the file. I was
  part-way through a refactor that would read packed structs, so that I could
  eventually use a `SeekableStream`.
- The large error-set should be refactored to use return some (optional?) error
  context with the error type and the offset where it was encountered.
- Anything else marked `TODO` in the code.
