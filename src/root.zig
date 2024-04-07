const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const assert = std.debug.assert;
const fs = std.fs;
const os = std.os;
const mem = std.mem;
const crc = std.hash.Crc32;
const math = std.math;
const ascii = std.ascii;
const flate = std.compress.flate;

pub const Error = error{
    ZipError,
};

pub const Diagnostics = struct {
    subtype: ?ErrorSubtype = null,
};

pub const ErrorSubtype = enum {
    SizeMax,
    OutOfMemory,
    Overflow,
    BombArchives,
    BombDepth,
    BombFifield,
    BombFiles,
    BombRatio,
    BombInflateCompressedOverflow,
    BombInflateUncompressedOverflow,
    TooSmall,
    Size4Gb,
    Rar,
    Tar,
    Xar,
    Signature,
    EocdrNotFound,
    EocdrOverflow,
    EocdrCommentOverflow,
    EocdrSignature,
    EocdrRecords,
    EocdrSizeOverflow,
    EocdrSizeUnderflow,
    MultipleDisks,
    AppendedDataZeroed,
    AppendedDataBufferBleed,
    PrependedData,
    PrependedDataZeroed,
    PrependedDataBufferBleed,
    CdhOverflow,
    CdhSignature,
    CdhRelativeOffsetOverflow,
    CdhRelativeOffsetOverlap,
    CdhFileNameOverflow,
    CdhExtraFieldOverflow,
    CdhFileCommentOverflow,
    LfhOverflow,
    LfhSignature,
    LfhFileNameOverflow,
    LfhExtraFieldOverflow,
    LfhUnderflowZeroed,
    LfhUnderflowBufferBleed,
    LfhDataOverflow,
    DdrOverflow,
    LfOverflow,
    LfUnderflowZeroed,
    LfUnderflowBufferBleed,
    CdOverflow,
    CdUnderflowZeroed,
    CdUnderflowBufferBleed,
    CdEocdrOverflow,
    CdEocdrUnderflowZeroed,
    CdEocdrUnderflowBufferBleed,
    DiffLfhGeneralPurposeBitFlag,
    DiffLfhCompressionMethod,
    DiffLfhLastModFileTime,
    DiffLfhLastModFileDate,
    DiffLfhCrc32,
    DiffLfhCompressedSize,
    DiffLfhUncompressedSize,
    DiffLfhFileNameLength,
    DiffLfhFileName,
    DiffLfhDdrCrc32,
    DiffLfhDdrCompressedSize,
    DiffLfhDdrUncompressedSize,
    DiffDdrCrc32,
    DiffDdrCompressedSize,
    DiffDdrUncompressedSize,
    FlagOverflow,
    FlagTraditionalEncryption,
    FlagEnhancedDeflate,
    FlagCompressedPatchedData,
    FlagStrongEncryption,
    FlagUnusedBit7,
    FlagUnusedBit8,
    FlagUnusedBit9,
    FlagUnusedBit10,
    FlagEnhancedCompression,
    FlagMaskedLocalHeaders,
    FlagReservedBit14,
    FlagReservedBit15,
    CompressionMethodDangerous,
    CompressionMethodEncrypted,
    CompressionMethodUnsupported,
    StoredCompressionSizeMismatch,
    DangerousNegativeCompressionRatio,
    TimeOverflow,
    TimeHourOverflow,
    TimeMinuteOverflow,
    TimeSecondOverflow,
    DateOverflow,
    DateYearOverflow,
    DateMonthOverflow,
    DateDayOverflow,
    FileNameLength,
    FileNameControlCharacters,
    FileNameTraversalDrivePath,
    FileNameTraversalRelativePath,
    FileNameTraversalDoubleDots,
    FileNameComponentOverflow,
    FileNameBackslash,
    ExtraFieldMax,
    ExtraFieldMin,
    ExtraFieldAttributeOverflow,
    ExtraFieldOverflow,
    ExtraFieldUnderflowZeroed,
    ExtraFieldUnderflowBufferBleed,
    ExtraFieldUnicodePathOverflow,
    ExtraFieldUnicodePathVersion,
    ExtraFieldUnicodePathDiff,
    UnixModeOverflow,
    UnixModeBlockDevice,
    UnixModeCharacterDevice,
    UnixModeFifo,
    UnixModeSocket,
    UnixModePermissionsSticky,
    UnixModePermissionsSetgid,
    UnixModePermissionsSetuid,
    DirectoryCompressed,
    DirectoryUncompressed,
    SymlinkCompressed,
    SymlinkLength,
    SymlinkControlCharacters,
    SymlinkTraversalDrivePath,
    SymlinkTraversalRelativePath,
    SymlinkTraversalDoubleDots,
    SymlinkComponentOverflow,
    StringInvalidUnicode,
    StringMax,
    StringNullByte,
    Inflate,
    InflateDictionary,
    InflateStream,
    InflateData,
    InflateMemory,
    InflateCompressedUnderflow,
    InflateUncompressedUnderflow,
    AdNihilo,
    ExNihilo,
    Crc32,
    Eocdl64Overflow,
    Eocdl64Signature,
    Eocdl64NegativeOffset,
    Eocdl64Disk,
    Eocdl64Disks,
    Eocdr64Overflow,
    Eocdr64Signature,
    EocdrEocdl64Overflow,
    EocdrEocdl64UnderflowZeroed,
    EocdrEocdl64UnderflowBufferBleed,
    DiffEocdrDisk,
    DiffEocdrCdDisk,
    DiffEocdrCdDiskRecords,
    DiffEocdrCdRecords,
    DiffEocdrCdSize,
    DiffEocdrCdOffset,
    Eief64CompressedSize,
    Eief64Disk,
    Eief64RelativeOffset,
    Eief64UncompressedSize,
    Eief64UnderflowZeroed,
    Eief64UnderflowBufferBleed,
    Eief64Lfh,
    DirectoryHasNoLfh,

    pub fn message(self: ErrorSubtype) []const u8 {
        return switch (self) {
            .SizeMax => "exceeded 64 GB limit",
            .OutOfMemory => "insufficient memory",
            .Overflow => "string not found",
            .BombArchives => "uint64_t overflow",
            .BombDepth => "zip bomb: too many archives",
            .BombFifield => "zip bomb: too much recursion",
            .BombFiles => "zip bomb: local file header overlap (see research by David Fifield)",
            .BombRatio => "zip bomb: too many files",
            .BombInflateCompressedOverflow => "zip bomb: dangerous compression ratio and uncompressed size",
            .BombInflateUncompressedOverflow => "zip bomb: compressed data is larger than compressed size (overflow)",
            .TooSmall => "zip bomb: uncompressed data is larger than uncompressed size (overflow)",
            .Size4Gb => "zip file too small (minimum size is 22 bytes)",
            .Rar => "unsupported: zip file exceeds 4 GB limit (ZIP64)",
            .Tar => "not a zip file (malicious rar)",
            .Xar => "not a zip file (malicious tar)",
            .Signature => "not a zip file (malicious xar)",
            .EocdrNotFound => "not a zip file (bad signature)",
            .EocdrOverflow => "end of central directory record: not found",
            .EocdrCommentOverflow => "end of central directory record: overflow",
            .EocdrSignature => "end of central directory record: comment overflow",
            .EocdrRecords => "end of central directory record: bad signature",
            .EocdrSizeOverflow => "end of central directory record: cd_disk_records != cd_records",
            .EocdrSizeUnderflow => "end of central directory record: cd_size too small for number of cd_records",
            .MultipleDisks => "end of central directory record: cd_size > 0 but cd_records == 0",
            .AppendedDataZeroed => "unsupported: multiple disks",
            .AppendedDataBufferBleed => "zip file has appended data (zeroed)",
            .PrependedData => "zip file has appended data (buffer bleed)",
            .PrependedDataZeroed => "zip file has prepended data",
            .PrependedDataBufferBleed => "zip file has prepended data (zeroed)",
            .CdhOverflow => "zip file has prepended data (buffer bleed)",
            .CdhSignature => "central directory header: overflow",
            .CdhRelativeOffsetOverflow => "central directory header: bad signature",
            .CdhRelativeOffsetOverlap => "central directory header: relative offset overflow",
            .CdhFileNameOverflow => "central directory header: relative offset overlaps central directory",
            .CdhExtraFieldOverflow => "central directory header: file name overflow",
            .CdhFileCommentOverflow => "central directory header: extra field overflow",
            .LfhOverflow => "central directory header: file comment overflow",
            .LfhSignature => "local file header: overflow",
            .LfhFileNameOverflow => "local file header: bad signature",
            .LfhExtraFieldOverflow => "local file header: file name overflow",
            .LfhUnderflowZeroed => "local file header: extra field overflow",
            .LfhUnderflowBufferBleed => "local file header: gap (zeroed)",
            .LfhDataOverflow => "local file header: gap (buffer bleed)",
            .DdrOverflow => "local file header: data overflow",
            .LfOverflow => "data descriptor record: overflow",
            .LfUnderflowZeroed => "zip file has overlap between last local file and central directory",
            .LfUnderflowBufferBleed => "zip file has gap between last local file and central directory (zeroed)",
            .CdOverflow => "zip file has gap between last local file and central directory (buffer bleed)",
            .CdUnderflowZeroed => "central directory: overflow",
            .CdUnderflowBufferBleed => "central directory: underflow (zeroed)",
            .CdEocdrOverflow => "central directory: underflow (buffer bleed)",
            .CdEocdrUnderflowZeroed => "central directory overlaps end of central directory record",
            .CdEocdrUnderflowBufferBleed => "zip file has gap between central directory and end of central directory record (zeroed)",
            .DiffLfhGeneralPurposeBitFlag => "zip file has gap between central directory and end of central directory record (buffer bleed)",
            .DiffLfhCompressionMethod => "local file header diverges from central directory header: general purpose bit flag",
            .DiffLfhLastModFileTime => "local file header diverges from central directory header: compression method",
            .DiffLfhLastModFileDate => "local file header diverges from central directory header: last mod file time",
            .DiffLfhCrc32 => "local file header diverges from central directory header: last mod file date",
            .DiffLfhCompressedSize => "local file header diverges from central directory header: crc32",
            .DiffLfhUncompressedSize => "local file header diverges from central directory header: compressed size",
            .DiffLfhFileNameLength => "local file header diverges from central directory header: uncompressed size",
            .DiffLfhFileName => "local file header diverges from central directory header: file name length",
            .DiffLfhDdrCrc32 => "local file header diverges from central directory header: file name",
            .DiffLfhDdrCompressedSize => "local file header diverges from data descriptor record: crc32",
            .DiffLfhDdrUncompressedSize => "local file header diverges from data descriptor record: compressed size",
            .DiffDdrCrc32 => "local file header diverges from data descriptor record: uncompressed size",
            .DiffDdrCompressedSize => "data descriptor record diverges from central directory header: crc32",
            .DiffDdrUncompressedSize => "data descriptor record diverges from central directory header: compressed size",
            .FlagOverflow => "data descriptor record diverges from central directory header: uncompressed size",
            .FlagTraditionalEncryption => "general purpose bit flag: 16-bit overflow",
            .FlagEnhancedDeflate => "unsupported: traditional encryption",
            .FlagCompressedPatchedData => "unsupported: enhanced deflate",
            .FlagStrongEncryption => "unsupported: compressed patched data",
            .FlagUnusedBit7 => "unsupported: strong encryption",
            .FlagUnusedBit8 => "unsupported: unused flag (bit 7)",
            .FlagUnusedBit9 => "unsupported: unused flag (bit 8)",
            .FlagUnusedBit10 => "unsupported: unused flag (bit 9)",
            .FlagEnhancedCompression => "unsupported: unused flag (bit 10)",
            .FlagMaskedLocalHeaders => "unsupported: enhanced compression",
            .FlagReservedBit14 => "unsupported: masked local headers",
            .FlagReservedBit15 => "unsupported: reserved flag (bit 14)",
            .CompressionMethodDangerous => "unsupported: reserved flag (bit 15)",
            .CompressionMethodEncrypted => "compression method: exceeds 999 (CVE-2016-9844)",
            .CompressionMethodUnsupported => "compression method: encrypted",
            .StoredCompressionSizeMismatch => "compression method: must be 0 or 8",
            .DangerousNegativeCompressionRatio => "file stored with no compression has mismatching compressed and uncompressed sizes",
            .TimeOverflow => "dangerous negative compression ratio (CVE-2018-18384)",
            .TimeHourOverflow => "time: 16-bit overflow",
            .TimeMinuteOverflow => "time: ms-dos hour: overflow",
            .TimeSecondOverflow => "time: ms-dos minute: overflow",
            .DateOverflow => "time: ms-dos second: overflow",
            .DateYearOverflow => "date: 16-bit overflow",
            .DateMonthOverflow => "date: ms-dos year: overflow",
            .DateDayOverflow => "date: ms-dos month: overflow",
            .FileNameLength => "date: ms-dos day: overflow",
            .FileNameControlCharacters => "file name exceeds 4096 bytes (CVE-2018-1000035)",
            .FileNameTraversalDrivePath => "file name contains control characters (CVE-2003-0282)",
            .FileNameTraversalRelativePath => "directory traversal (via file name drive path)",
            .FileNameTraversalDoubleDots => "directory traversal (via file name relative path)",
            .FileNameComponentOverflow => "directory traversal (via file name double dots)",
            .FileNameBackslash => "file name path component exceeds 255 bytes",
            .ExtraFieldMax => "file name contains backslash",
            .ExtraFieldMin => "extra field length exceeds maximum",
            .ExtraFieldAttributeOverflow => "extra field length must be 0 or at least 4 bytes",
            .ExtraFieldOverflow => "extra field: attribute overflow",
            .ExtraFieldUnderflowZeroed => "extra field: overflow",
            .ExtraFieldUnderflowBufferBleed => "extra field: underflow (zeroed)",
            .ExtraFieldUnicodePathOverflow => "extra field: underflow (buffer bleed)",
            .ExtraFieldUnicodePathVersion => "extra field: unicode path overflow",
            .ExtraFieldUnicodePathDiff => "extra field: unicode path has an invalid version",
            .UnixModeOverflow => "extra field: unicode path diverges from file name",
            .UnixModeBlockDevice => "unix mode: overflow",
            .UnixModeCharacterDevice => "unix mode: dangerous type (block device)",
            .UnixModeFifo => "unix mode: dangerous type (character device)",
            .UnixModeSocket => "unix mode: dangerous type (fifo)",
            .UnixModePermissionsSticky => "unix mode: dangerous type (socket)",
            .UnixModePermissionsSetgid => "unix mode: dangerous permissions (sticky)",
            .UnixModePermissionsSetuid => "unix mode: dangerous permissions (setgid)",
            .DirectoryCompressed => "unix mode: dangerous permissions (setuid)",
            .DirectoryUncompressed => "directory: non-zero compressed size",
            .SymlinkCompressed => "directory: non-zero uncompressed size",
            .SymlinkLength => "unsupported: compressed symlink",
            .SymlinkControlCharacters => "symlink exceeds 4096 bytes (CVE-2018-1000035)",
            .SymlinkTraversalDrivePath => "symlink contains control characters (CVE-2003-0282)",
            .SymlinkTraversalRelativePath => "directory traversal (via symlink drive path)",
            .SymlinkTraversalDoubleDots => "directory traversal (via symlink relative path)",
            .SymlinkComponentOverflow => "directory traversal (via symlink double dots)",
            .StringInvalidUnicode => "symlink path component exceeds 255 bytes",
            .StringMax => "string exceeds reasonable limit (PURE_ZIP_STRING_MAX)",
            .StringNullByte => "string contains a dangerous null byte",
            .Inflate => "zip file could not be uncompressed",
            .InflateDictionary => "zip file could not be uncompressed (dictionary error)",
            .InflateStream => "zip file could not be uncompressed (stream error)",
            .InflateData => "zip file could not be uncompressed (data error)",
            .InflateMemory => "zip file could not be uncompressed (memory error)",
            .InflateCompressedUnderflow => "compressed data is smaller than compressed size",
            .InflateUncompressedUnderflow => "uncompressed data is smaller than uncompressed size",
            .AdNihilo => "file has a zero uncompressed size but a non-zero compressed size or invalid compressed data (ad nihilo)",
            .ExNihilo => "file has a zero compressed size but a non-zero uncompressed size (ex nihilo)",
            .Crc32 => "file is corrupt or has an invalid crc32 checksum",
            .Eocdl64Overflow => "zip64 end of central directory locator: overflow",
            .Eocdl64Signature => "zip64 end of central directory locator: bad signature",
            .Eocdl64NegativeOffset => "zip64 end of central directory locator: negative offset",
            .Eocdl64Disk => "zip64 end of central directory locator: disk != 0",
            .Eocdl64Disks => "zip64 end of central directory locator: disks > 1",
            .Eocdr64Overflow => "zip64 end of central directory record: overflow",
            .Eocdr64Signature => "zip64 end of central directory record: bad signature",
            .EocdrEocdl64Overflow => "zip64 eocdr overlaps zip64 eocdl",
            .EocdrEocdl64UnderflowZeroed => "gap between zip64 eocdr and zip64 eocdl (zeroed)",
            .EocdrEocdl64UnderflowBufferBleed => "gap between zip64 eocdr and zip64 eocdl (buffer bleed)",
            .DiffEocdrDisk => "eocdr diverges from zip64 eocdr: disk",
            .DiffEocdrCdDisk => "eocdr diverges from zip64 eocdr: cd_disk",
            .DiffEocdrCdDiskRecords => "eocdr diverges from zip64 eocdr: cd_disk_records",
            .DiffEocdrCdRecords => "eocdr diverges from zip64 eocdr: cd_records",
            .DiffEocdrCdSize => "eocdr diverges from zip64 eocdr: cd_size",
            .DiffEocdrCdOffset => "eocdr diverges from zip64 eocdr: cd_offset",
            .Eief64CompressedSize => "zip64 extended information extra field: missing compressed_size",
            .Eief64Disk => "zip64 extended information extra field: missing disk",
            .Eief64RelativeOffset => "zip64 extended information extra field: missing relative_offset",
            .Eief64UncompressedSize => "zip64 extended information extra field: missing uncompressed_size",
            .Eief64UnderflowZeroed => "zip64 extended information extra field: appended data (zeroed)",
            .Eief64UnderflowBufferBleed => "zip64 extended information extra field: appended data (buffer bleed)",
            .Eief64Lfh => "zip64 extended information extra field: local file header must include both uncompressed_size and compressed_size",
            .DirectoryHasNoLfh => "a directory has no local file header",
        };
    }
};

// General purpose Zip API
pub const Zip = struct {
    pub const FileKind = enum {
        directory,
        sym_link,
        file,
    };

    pub const File = struct {
        name: []const u8, // name of file, symlink or directory
        link_name: []const u8, // target name of symlink
        size: u64, // size of the file in bytes
        mode: u32,
        kind: FileKind,

        _zip: *Zip,
        _cdh: Cdh,
        _fbs: std.io.FixedBufferStream([]const u8),
        _fbsr: std.io.FixedBufferStream([]const u8).Reader,
        _decomp: ?flate.inflate.Decompressor(.raw, std.io.FixedBufferStream([]const u8).Reader) = null,
        _decompr: ?flate.inflate.Decompressor(.raw, std.io.FixedBufferStream([]const u8).Reader).Reader = null,

        pub fn reader(self: File) !std.io.AnyReader {
            if (self._cdh.compression_method == .deflate) {
                return self._decompr.?.any();
            } else {
                return self._fbsr.any();
            }
        }

        fn getContentUncompressed(self: File) ![]const u8 {
            var ctx: Ctx = .{ .allocator = self._zip.allocator };
            const lfh = try decodeLfh(&ctx, self._zip.buffer, self._cdh.relative_offset);
            return self._zip.buffer[self._cdh.relative_offset + lfh.length ..][0..self._cdh.compressed_size];
        }

        fn from(z: *Zip, cdh: Cdh) !File {
            const k: FileKind = if (cdh.directory)
                .directory
            else if ((cdh.unix_mode & S.IFMT) == S.IFLNK)
                .sym_link
            else
                .file;
            var file: File = .{
                .name = cdh.file_name,
                .link_name = "",
                .size = cdh.uncompressed_size,
                .mode = @intCast(cdh.unix_mode), // TODO (MFA) is cast right? Seems to be, we validate it's < max(u16) so it should be safe
                .kind = k,
                ._zip = z,
                ._cdh = cdh,
                ._fbs = undefined,
                ._fbsr = undefined,
            };
            if (k == .sym_link) {
                file.link_name = try file.getContentUncompressed();
            }
            file._fbs = std.io.fixedBufferStream(try file.getContentUncompressed());
            file._fbsr = file._fbs.reader();
            if (cdh.compression_method == .deflate) {
                file._decomp = flate.decompressor(file._fbsr);
                file._decompr = file._decomp.?.reader();
            }
            return file;
        }
    };
    pub const Iterator = struct {
        zip: *Zip,
        index: usize = 0,
        pub fn next(self: *Iterator) !?File {
            const values = self.zip.directory.values();
            if (self.index >= values.len) return null;
            const cdh = values[self.index];
            const f = try File.from(self.zip, cdh);
            self.index += 1;
            return f;
        }
    };
    const InitOptions = struct { diagnostics: ?*Diagnostics = null };

    allocator: std.mem.Allocator,
    buffer: []align(mem.page_size) const u8,
    directory: std.StringArrayHashMap(Cdh),

    pub fn init(a: std.mem.Allocator, file: std.fs.File, opts: InitOptions) !Zip {
        const stat = try file.stat();
        const buffer = try std.posix.mmap(null, stat.size, std.posix.PROT.READ, std.posix.MAP{ .TYPE = .PRIVATE }, file.handle, 0);
        errdefer {
            std.posix.munmap(buffer);
        }
        // Read the central directory
        var directory = std.StringArrayHashMap(Cdh).init(a);
        errdefer {
            directory.deinit();
        }
        var ctx: Ctx = .{
            .allocator = a,
            .directory = &directory,
            .do_decompress = false,
            .diagnostics = opts.diagnostics,
        };
        try zipMeta(&ctx, buffer);
        return .{
            .allocator = a,
            .buffer = buffer,
            .directory = directory,
        };
    }

    pub fn deinit(self: *Zip) void {
        self.directory.deinit();
        std.posix.munmap(self.buffer);
    }

    pub fn get(self: *Zip, subpath: []const u8) !?File {
        const cdh = self.directory.get(subpath) orelse return null;
        return try File.from(self, cdh);
    }

    pub fn iterator(self: *Zip) Iterator {
        return .{ .zip = self };
    }
};

test "open ZIP read file name" {
    const a = std.testing.allocator;
    const f = try std.fs.cwd().openFile("src/testdata/twofiles.zip", .{});
    var z = try Zip.init(a, f, .{});
    defer z.deinit();
    const zf = try z.get("README.md") orelse return error.FileNotFound;
    try std.testing.expectEqual(2064, zf.size);
}

test "open a ZIP with symlink" {
    const a = std.testing.allocator;
    const f = try std.fs.cwd().openFile("src/testdata/symlink.zip", .{});
    var z = try Zip.init(a, f, .{});
    defer z.deinit();
    const symlink = try z.get("README-link.md") orelse return error.FileNotFound;
    try std.testing.expectEqual(.sym_link, symlink.kind);
    try std.testing.expectEqualStrings("README.md", symlink.link_name);
}

test "open a ZIP with a directory" {
    const a = std.testing.allocator;
    const f = try std.fs.cwd().openFile("src/testdata/directory.zip", .{});
    var z = try Zip.init(a, f, .{});
    defer z.deinit();
    const dir = try z.get("src/") orelse return error.FileNotFound;
    try std.testing.expectEqual(.directory, dir.kind);
}

test "iterate ZIP entries" {
    const a = std.testing.allocator;
    const f = try std.fs.cwd().openFile("src/testdata/twofiles.zip", .{});
    var z = try Zip.init(a, f, .{});
    defer z.deinit();
    var it = z.iterator();
    const f1 = try it.next() orelse return error.FileNotFound;
    const f2 = try it.next() orelse return error.FileNotFound;
    const f3 = try it.next();
    try std.testing.expectEqualStrings("README.md", f1.name);
    try std.testing.expectEqualStrings("README-original.md", f2.name);
    try std.testing.expectEqual(null, f3);
}

test "read a ZIP entry contents" {
    const a = std.testing.allocator;
    const f = try std.fs.cwd().openFile("src/testdata/twofiles.zip", .{});
    var z = try Zip.init(a, f, .{});
    defer z.deinit();
    const f1 = try z.get("README.md") orelse return error.FileNotFound;
    var rdr1 = try f1.reader();
    const f1c = try rdr1.readAllAlloc(a, 1_000_000);
    defer a.free(f1c);
    try std.testing.expect(std.mem.startsWith(u8, f1c, "# Pure, the Zig port"));
    try std.testing.expect(std.mem.endsWith(u8, f1c, "- Anything else marked `TODO` in the code.\n"));
}

const path_component_max = 255;
const path_max = 4096;
const malloc_min = 65536;

const archives_max = 1000;
const depth_max = 4;
const files_max = 10000;
const size_max = 34359738368;

const zip_cdh_min = 46;
const zip_ddr_64_min = 20;
const zip_ddr_min = 12;
const zip_eocdl_64 = 20;
const zip_eocdr_64_min = 56;
const zip_eocdr_min = 22;
const zip_extra_field_max = 4096;
const zip_flag_utf8 = 1 << 11;
const zip_lfh_min = 30;
const zip_string_max = 16384;
const zip_version_made_unix = 3;

fn byteSwapAllFields(comptime T: type, ptr: *T) void {
    assert(@typeInfo(T) == .Struct);
    inline for (std.meta.fields(T)) |f| {
        const field_type = @TypeOf(@field(ptr, f.name));

        switch (@typeInfo(field_type)) {
            .Int => @field(ptr, f.name) = @byteSwap(@field(ptr, f.name)),
            .Struct => |s| {
                assert(s.layout == .Packed);
                @field(ptr, f.name) = @as(field_type, @bitCast(@byteSwap(
                    @as(s.backing_integer.?, @bitCast(@field(ptr, f.name))),
                )));
            },
            .Enum => @field(ptr, f.name) = @as(field_type, @enumFromInt(@byteSwap(
                @intFromEnum(@field(ptr, f.name)),
            ))),
            else => {},
        }
    }
}

inline fn pkCode(b1: u8, b2: u8) []const u8 {
    return "PK" ++ [2]u8{ b1, b2 };
}

inline fn pkCode2(b1: u8, b2: u8) u32 {
    return mem.readInt(u32, &[4]u8{ 'P', 'K', b1, b2 }, .little);
}

const s_iconr = "Icon\r".*;
const span_signature = pkCode(7, 8);
const s_zip_temp = pkCode(48, 48);

const Ctx = struct {
    allocator: mem.Allocator,
    depth: u64 = 0,
    files: u64 = 0,
    archives: u64 = 0,
    size: u64 = 0,
    compressed_size: u64 = 0,
    uncompressed_size: u64 = 0,

    // Set to false if you want to skip decompressing the contents to verify content lengths
    // NOTE also disables checking nested ZIP meta
    do_decompress: bool = true,
    // Populate this this if you want more detailed errors
    diagnostics: ?*Diagnostics = null,
    // Populate this if you want to collect the central directory entries for further processing
    directory: ?*std.StringArrayHashMap(Cdh) = null,
};

const LocalFileHeader = struct {
    const signature = pkCode2(3, 4);

    const Complete = packed struct {
        sig: u32,
        version_made: u16,
        gp_bits: GeneralPurposeBits,
        compression_method: CompressionMethod,
        last_mod_file_time: u16,
        last_mod_file_date: u16,
        crc32: u32,
        compressed_size: u32,
        uncompressed_size: u32,
        file_name_length: u16,
        extra_field_length: u16,
    };
};

/// Local File Header
const Lfh = struct {
    const signature = pkCode(3, 4);

    offset: u64,
    length: u64,
    version_minimum: u64,
    gp_bits: GeneralPurposeBits,
    compression_method: CompressionMethod,
    last_mod_file_time: u64,
    last_mod_file_date: u64,
    crc32: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    file_name: []const u8,
    extra_field: []const u8,
    zip64: bool,
};

/// Data Descriptor
const Ddr = struct {
    const signature = pkCode(7, 8);

    offset: u64,
    length: u64,
    crc32: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    zip64: bool,
};

const CentralDirectory = struct {
    const signature = pkCode2(1, 2);

    version_made: u16,
    gp_bits: GeneralPurposeBits,
    compression_method: CompressionMethod,
    last_mod_file_time: u16,
    last_mod_file_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name: []const u8,
    extra_field: []const u8,
    file_comment: []const u8,
    disk: u16,
    unix_mode: u16,
    directory: bool,
    zip64: bool,

    const Complete = packed struct {
        sig: u32,
        version_made: u16,
        version_needed: u16,
        gp_bits: u16, //GeneralPurposeBits,
        compression_method: u16, //CompressionMethod,
        last_mod_file_time: u16,
        last_mod_file_date: u16,
        crc32: u32,
        compressed_size: u32,
        uncompressed_size: u32,
        file_name_length: u16,
        extra_field_length: u16,
        file_comment_length: u16,
        disk_number_start: u16,
        internal_file_attributes: u16,
        external_file_attributes: u32,
        relative_offset: u32,
    };
};

const Cdh = struct {
    offset: u64,
    length: u64,
    gp_bits: GeneralPurposeBits,
    compression_method: CompressionMethod,
    last_mod_file_time: u64,
    last_mod_file_date: u64,
    crc32: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    file_name: []const u8,
    extra_field: []const u8,
    file_comment: []const u8,
    disk: u64,
    relative_offset: u64,
    unix_mode: u64,
    directory: bool,
    zip64: bool,
};

const Eocdr64 = struct {
    const Complete = packed struct {
        sig: u32,
        size: u64,
        version_made: u16,
        version_needed: u16,
        disk: u32,
        cd_disk: u32,
        cd_disk_records: u64,
        cd_records: u64,
        cd_size: u64,
        cd_offset: u64,
    };

    offset: u64,
    length: u64,
    version_made: u64,
    version_minimum: u64,
    disk: u64,
    cd_disk: u64,
    cd_disk_records: u64,
    cd_records: u64,
    cd_size: u64,
    cd_offset: u64,
    extensible_data_sector: []const u8,
};

const Eocdl64 = struct {
    pub const signature = pkCode(6, 7);

    offset: u64,
    length: u64,
    disk: u64,
    eocdr_64_offset: u64,
    disks: u64,
};

const Eocdr = struct {
    pub const signature = pkCode(5, 6);

    offset: u64,
    length: u64,
    disk: u64,
    cd_disk: u64,
    cd_disk_records: u64,
    cd_records: u64,
    cd_size: u64,
    cd_offset: u64,
    comment: []const u8,
    comment_length: u64,
    zip64: bool,
};

const DosTimestamp = packed struct(u32) {
    // Multiplied by two.
    second: u5,
    minute: u6,
    hour: u5,
    day: u5,
    month: u4,
    // Relative to 1980.
    year: u7,
};

const GeneralPurposeBits = packed struct(u16) {
    traditional_encryption: bool = false,
    bit1: bool = false,
    bit2: bool = false,
    lfh_fields_zeroed: bool = false,
    enhanced_deflate: bool = false,
    compressed_patched: bool = false,
    strong_encryption: bool = false,
    bit7_unused: bool = false,
    bit8_unused: bool = false,
    bit9_unused: bool = false,
    bit10_unused: bool = false,
    utf8_fields: bool = false,
    enhanced_compression: bool = false,
    masked_local_headers: bool = false,
    bit14_reserved: bool = false,
    bit15_reserved: bool = false,
};

const CompressionMethod = enum(u16) {
    uncompressed = 0,
    shrink = 1,
    reduce_factor_1 = 2,
    reduce_factor_2 = 3,
    reduce_factor_3 = 4,
    reduce_factor_4 = 5,
    implode = 6,
    reserved_tokenize = 7,
    deflate = 8,
    deflate64 = 9,
    terse_implode = 10,
    reserved2 = 11,
    bzip2 = 12,
    reserved3 = 13,
    lzma = 14,
    reserved4 = 15,
    cmpsc = 16,
    reserved5 = 17,
    terse = 18,
    ibm_lz77 = 19,
    zstd_deprecated = 20,
    zstd = 93,
    mp3 = 94,
    xz = 95,
    jpeg = 96,
    wavpack = 97,
    ppmd1_1 = 98,
    AEx = 99,

    _,
};

const Signature = enum(u32) {
    cdh = gen(1, 2),
    lfh = gen(3, 4),
    digital_signature = gen(5, 5),
    eocdr = gen(5, 6),
    eocdr64 = gen(6, 6),
    eocdl64 = gen(6, 7),
    extra_data = gen(6, 8),
    ddr = gen(7, 8),
    temp = gen(48, 48),

    inline fn gen(b1: u8, b2: u8) u32 {
        return mem.readInt(u32, &[4]u8{ 'P', 'K', b1, b2 }, .little);
    }
};

fn overflow(offset: u64, length: u64, available: u64) bool {
    if (available < length) return true;
    if (offset > available - length) return true;
    return false;
}

fn zeroes(buf: []const u8) bool {
    for (buf) |c|
        if (c != 0) return false;
    return true;
}

inline fn pathRelative(path: []const u8) bool {
    if (path.len == 0) return false;
    return path[0] == '\\' or path[0] == '/';
}

fn pathComponentOverflow(path: []const u8) bool {
    var start: u64 = 0;
    while (start < path.len) {
        const end = mem.indexOfAny(u8, path[start..], "/\\") orelse path.len;
        if (end - start > path_component_max) return true;
        start = end + 1;
    }

    return false;
}

fn pathControlCharactersIconr(path: []const u8) bool {
    if (path.len < s_iconr.len) return false;
    const offset = path.len - s_iconr.len;
    if (mem.startsWith(u8, path[offset..], &s_iconr))
        return false;

    // Do not fail for partial component matches:
    return offset == 0 or pathRelative(path[offset - 1 ..]);
}

fn pathControlCharacters(path: []const u8) bool {
    // We want to check for control characters, except the "\r" in "Icon\r" files:
    var excluding_iconr_length = path.len;
    if (pathControlCharactersIconr(path)) {
        assert(excluding_iconr_length >= s_iconr.len);
        excluding_iconr_length -= s_iconr.len;
    }

    for (path[0..excluding_iconr_length]) |c|
        if (ascii.isControl(c)) return true;

    return false;
}

fn pathDoubleDots(path: []const u8) bool {
    var start: u64 = 0;
    while (start < path.len) {
        const end = mem.indexOfAny(u8, path[start..], "/\\") orelse path.len;
        // Check two-character components for double dots (".."):
        if (end - start == 2 and mem.startsWith(u8, path[start..], ".."))
            return true;
        start = end + 1;
    }

    return false;
}

inline fn pathDrive(path: []const u8) bool {
    return path.len >= 2 and
        path[1] == ':' and
        path[0] >= 'A' and
        path[0] <= 'Z';
}

const ratio_size_min = 1 << 27;
const ratio_score_max = 1 << 34;

fn verifyCompressionRatio(ctx: *Ctx, compressed_size: u64, uncompressed_size: u64) Error!void {
    // Here, compressed size and uncompressed size could relate to the respective
    // sizes of an individual file or the sum of the sizes across an archive.
    //
    // We do not use only a ratio limit to detect dangerous compression ratios,
    // since an extreme ratio can be mitigated by a negligible uncompressed size.
    //
    // Instead, we calculate a score that combines the ratio and uncompressed size
    // and then compare this score against a limit. The higher the ratio and the
    // larger the uncompressed size, the more dangerous the file or archive.
    //
    // Conversely, a file or archive with high ratio but negligible uncompressed
    // size is less likely to be dangerous, since while it may have high power,
    // this power is multiplied by less weight.
    if (compressed_size == 0) return; // Prevent divide-by-zero.
    if (uncompressed_size < ratio_size_min) return;
    const ratio = @divTrunc(uncompressed_size, compressed_size);
    const score = ratio * uncompressed_size;
    if (score > ratio_score_max) {
        if (ctx.diagnostics) |diags| {
            diags.subtype = .BombRatio;
        }
        return error.ZipError;
    }
}

fn err(ctx: *Ctx, subtype: ErrorSubtype) Error {
    if (ctx.diagnostics) |diags| {
        diags.subtype = subtype;
    }
    return error.ZipError;
}

fn verifyCompressionMethod(
    ctx: *Ctx,
    method: CompressionMethod,
    compressed_size: u64,
    uncompressed_size: u64,
) Error!void {
    switch (method) {
        .uncompressed => if (compressed_size != uncompressed_size)
            return err(ctx, .StoredCompressionSizeMismatch),
        .deflate => {},
        .AEx => return err(ctx, .CompressionMethodEncrypted),
        // CVE-2016-9844:
        // Defend vulnerable implementations against overflow when the two-byte
        // compression method in the central directory file header exceeds 999.
        // https://bugs.launchpad.net/ubuntu/+source/unzip/+bug/1643750
        else => if (@intFromEnum(method) > 999)
            return err(ctx, .CompressionMethodDangerous)
        else
            return err(ctx, .CompressionMethodUnsupported),
    }

    // CVE-2018-18384:
    // Defend vulnerable implementations against buffer overflow.
    // https://bugzilla.suse.com/show_bug.cgi?id=1110194
    if (uncompressed_size > 0 and
        compressed_size > uncompressed_size and
        compressed_size / uncompressed_size >= 2)
        return err(ctx, .DangerousNegativeCompressionRatio);
}

fn verifyModTime(ctx: *Ctx, date: u64, time: u64) Error!void {
    if (date > math.maxInt(u16)) return err(ctx, .DateOverflow);
    if (time > math.maxInt(u16)) return err(ctx, .TimeOverflow);
    // An MS-DOS date is a packed 16-bit (2 bytes) value in which bits in the
    // value represent the day, month, and year:
    //
    //  Bits:  0-4   5-8    9-15
    //  Unit:  Day   Month  Year
    //  Range: 1-31  1-12   Relative to 1980
    //
    // Similarly, an MS-DOS time is a packed 16-bit value in which bits in the
    // value represent the hour, minute, and second:
    //
    //  Bits:  0-4     5-10    11-15
    //  Unit:  Second  Minute  Hour
    //  Range: 0-59    0-59    0-23
    const year = (date >> 9) + 1980;
    const month = (date >> 5) & 15;
    const day = date & 31;
    const hour = (time >> 11);
    const minute = (time >> 5) & 63;
    const second = (time & 31) * 2;

    if (year > 2099) return err(ctx, .DateYearOverflow);
    if (month > 12) return err(ctx, .DateMonthOverflow);
    if (day > 31) return err(ctx, .DateDayOverflow);
    if (hour > 23) return err(ctx, .TimeHourOverflow);
    if (minute > 59) return err(ctx, .TimeMinuteOverflow);
    if (second > 59) return err(ctx, .TimeSecondOverflow);
}

fn verifyExtraField(ctx: *Ctx, extra_field: []const u8, file_name: []const u8) Error!void {
    if (extra_field.len > zip_extra_field_max)
        return err(ctx, .ExtraFieldMax);
    // The extra field contains a variety of optional data such as OS-specific
    // attributes. It is divided into chunks, each with a 16-bit ID code and a
    // 16-bit length.
    if (extra_field.len != 0 and extra_field.len < 4)
        return err(ctx, .ExtraFieldMin);

    // Check extra field attribute sizes, and specifically the unicode path:
    var offset: u64 = 0;
    while (offset + 2 + 2 <= extra_field.len) {
        const buf = extra_field[offset..];
        const id = mem.readInt(u16, buf[0..2], .little);
        const size = mem.readInt(u16, buf[2..4], .little);
        if (offset + 2 + 2 + size > extra_field.len)
            return err(ctx, .ExtraFieldAttributeOverflow);

        if (id == 0x7075) {
            // We expect at least a 1-byte version followed by a 4-byte crc32:
            if (size < 1 + 4)
                return err(ctx, .ExtraFieldUnicodePathOverflow);
            assert(offset + 2 + 2 + 1 <= extra_field.len);
            const version = buf[2 + 2];
            if (version != 1)
                return err(ctx, .ExtraFieldUnicodePathVersion);
            // We require the unicode path to match the central directory file even if
            // the crc32 of the non-unicode path is different. Otherwise, an attacker
            // could present an alternative extension to bypass content inspection.
            //const base = offset + 2 + 2 + 1 + 4;
            //const unicode_path = extra_field[base .. base + size - 1 - 4];
            const unicode_path = buf[2 + 2 + 1 + 4 ..][0 .. size - 1 - 4];
            if (!mem.eql(u8, unicode_path, file_name))
                return err(ctx, .ExtraFieldUnicodePathDiff);
        }

        offset += 4;
        offset += size;
    }

    if (offset > extra_field.len)
        return err(ctx, .ExtraFieldOverflow);
    if (offset < extra_field.len) {
        if (zeroes(extra_field[offset..extra_field.len]))
            return err(ctx, .ExtraFieldUnderflowZeroed)
        else
            return err(ctx, .ExtraFieldUnderflowBufferBleed);
    }
}

const mode_t = u16;
const S = struct {
    pub const IFMT = 0o170000;

    pub const IFDIR = 0o040000;
    pub const IFCHR = 0o020000;
    pub const IFBLK = 0o060000;
    pub const IFIFO = 0o010000;
    pub const IFLNK = 0o120000;
    pub const IFSOCK = 0o140000;

    pub const ISUID = 0o4000;
    pub const ISGID = 0o2000;
    pub const ISVTX = 0o1000;
};

fn verifyUnixMode(ctx: *Ctx, value: u64) Error!void {
    if (value > math.maxInt(u16)) return err(ctx, .UnixModeOverflow);
    // Detect dangerous file types:
    switch (value & S.IFMT) {
        S.IFBLK => return err(ctx, .UnixModeBlockDevice),
        S.IFCHR => return err(ctx, .UnixModeCharacterDevice),
        S.IFIFO => return err(ctx, .UnixModeFifo),
        S.IFSOCK => return err(ctx, .UnixModeSocket),
        else => {},
    }
    // Detect dangerous permissions:
    // CVE-2005-0602
    // https://marc.info/?l=bugtraq&m=110960796331943&w=2
    if (value & S.ISVTX > 0) return err(ctx, .UnixModePermissionsSticky);
    if (value & S.ISGID > 0) return err(ctx, .UnixModePermissionsSetgid);
    if (value & S.ISUID > 0) return err(ctx, .UnixModePermissionsSetuid);
}

fn verifyFilename(ctx: *Ctx, name: []const u8) Error!void {
    // A "file name" in this context is a path name with multiple components.
    // The file name length may be 0 if the archiver input came from stdin.

    // CVE-2018-1000035:
    // Heap-based buffer overflow in password protected ZIP archives.
    // https://sec-consult.com/en/blog/advisories/
    //   multiple-vulnerabilities-in-infozip-unzip/index.html
    // We want to defend vulnerable implementations against PATH_MAX allocation
    // bugs, e.g. malloc(N * PATH_MAX) where the assumption is that user data
    // cannot exceed PATH_MAX.
    if (name.len > path_max)
        return err(ctx, .FileNameLength);
    // CVE-2003-0282 (aka "JELMER"):
    // Some zip implementations filter control characters amongst others.
    // This behavior can be exploited to mask ".." in a directory traversal.
    // https://www.securityfocus.com/archive/1/321090
    if (pathControlCharacters(name))
        return err(ctx, .FileNameControlCharacters);
    if (pathDrive(name))
        return err(ctx, .FileNameTraversalDrivePath);
    if (pathRelative(name))
        return err(ctx, .FileNameTraversalRelativePath);
    if (pathDoubleDots(name))
        return err(ctx, .FileNameTraversalDoubleDots);
    if (pathComponentOverflow(name))
        return err(ctx, .FileNameComponentOverflow);
    // All slashes must be forward according to the APPNOTE.TXT specification:
    for (name) |c|
        if (c == '\\') return err(ctx, .FileNameBackslash);
}

fn verifyFlags(ctx: *Ctx, bits: GeneralPurposeBits) Error!void {
    if (bits.traditional_encryption) return err(ctx, .FlagTraditionalEncryption);
    if (bits.enhanced_deflate) return err(ctx, .FlagEnhancedDeflate);
    if (bits.compressed_patched) return err(ctx, .FlagCompressedPatchedData);
    if (bits.strong_encryption) return err(ctx, .FlagStrongEncryption);
    if (bits.bit7_unused) return err(ctx, .FlagUnusedBit7);
    if (bits.bit8_unused) return err(ctx, .FlagUnusedBit8);
    if (bits.bit9_unused) return err(ctx, .FlagUnusedBit9);
    if (bits.bit10_unused) return err(ctx, .FlagUnusedBit10);
    if (bits.enhanced_compression) return err(ctx, .FlagEnhancedCompression);
    if (bits.masked_local_headers) return err(ctx, .FlagMaskedLocalHeaders);
    if (bits.bit14_reserved) return err(ctx, .FlagReservedBit14);
    if (bits.bit15_reserved) return err(ctx, .FlagReservedBit15);
}

fn verifyString(ctx: *Ctx, string: []const u8, utf8: bool) Error!void {
    if (string.len > zip_string_max) return err(ctx, .StringMax);
    for (string) |c|
        if (c == 0) return err(ctx, .StringNullByte);

    if (utf8) {
        // TODO(joran): Verify that UTF-8 encoding is valid:
        //  Some systems such as macOS never bother to set bit 11 to indicate UTF-8.
        //  We therefore always attempt UTF-8 and fallback to CP437 only on error.
        //  If the string must be UTF-8 then reject the string as invalid.
        if (!std.unicode.utf8ValidateSlice(string)) {
            return err(ctx, .StringInvalidUnicode);
        }
    }
}

fn verifySymlink(ctx: *Ctx, cdh: Cdh, lfh: Lfh, buffer: []const u8) Error!void {
    if ((cdh.unix_mode & S.IFMT) != S.IFLNK)
        return;
    if (cdh.compression_method != .uncompressed)
        return err(ctx, .SymlinkCompressed);

    assert(cdh.relative_offset == lfh.offset);
    assert(!overflow(cdh.relative_offset, lfh.length, cdh.offset));
    const offset = cdh.relative_offset + lfh.length;
    const symlink = buffer[offset..][0..cdh.compressed_size];
    // Check for PATH_MAX overflow:
    if (symlink.len > path_max) return err(ctx, .SymlinkLength);
    // Check for control characters used to mask a directory traversal:
    if (pathControlCharacters(symlink))
        return err(ctx, .SymlinkControlCharacters);
    // Check for a directory traversal:
    if (pathDrive(symlink))
        return err(ctx, .SymlinkTraversalDrivePath);
    if (pathRelative(symlink))
        return err(ctx, .SymlinkTraversalRelativePath);
    if (pathDoubleDots(symlink))
        return err(ctx, .SymlinkTraversalDoubleDots);
    // Check for path component overflow:
    if (pathComponentOverflow(symlink))
        return err(ctx, .SymlinkComponentOverflow);
}

fn decodeEief64(
    ctx: *Ctx,
    extra_field: []const u8,
    compressed_size: *u64,
    uncompressed_size: *u64,
    relative_offset: *u64,
    disk: *u64,
    zip64: *bool,
    lfh: bool,
) Error!void {
    assert(compressed_size.* == math.maxInt(u32) or
        uncompressed_size.* == math.maxInt(u32) or
        relative_offset.* == math.maxInt(u32) or
        disk.* == math.maxInt(u16));
    assert(zip64.* == false);

    if (extra_field.len > zip_extra_field_max)
        return err(ctx, .ExtraFieldMax);
    if (extra_field.len != 0 and extra_field.len < 4)
        return err(ctx, .ExtraFieldMin);

    var offset: u64 = 0;
    while (offset + 4 <= extra_field.len) {
        const id = mem.readInt(u16, extra_field[offset + 0 ..][0..2], .little);
        const size = mem.readInt(u16, extra_field[offset + 2 ..][0..2], .little);
        offset += 4;
        if (offset + size > extra_field.len)
            return err(ctx, .ExtraFieldAttributeOverflow);

        if (id == 0x0001) {
            zip64.* = true;

            var index: u64 = 0;
            if (uncompressed_size.* == math.maxInt(u32)) {
                if (index + 8 > size) return err(ctx, .Eief64UncompressedSize);
                uncompressed_size.* = mem.readInt(u64, extra_field[offset + index ..][0..8], .little);
                index += 8;
            }
            if (compressed_size.* == math.maxInt(u32)) {
                if (index + 8 > size) return err(ctx, .Eief64CompressedSize);
                compressed_size.* = mem.readInt(u64, extra_field[offset + index ..][0..8], .little);
                index += 8;
            }
            if (relative_offset.* == math.maxInt(u32)) {
                if (index + 8 > size) return err(ctx, .Eief64RelativeOffset);
                relative_offset.* = mem.readInt(u64, extra_field[offset + index ..][0..8], .little);
                index += 8;
            }
            if (disk.* == math.maxInt(u16)) {
                if (index + 4 > size) return err(ctx, .Eief64Disk);
                disk.* = mem.readInt(u32, extra_field[offset + index ..][0..4], .little);
                index += 4;
            }

            assert(offset + size <= extra_field.len);
            if (index < size) {
                if (zeroes(extra_field[offset + index .. offset + size]))
                    return err(ctx, .Eief64UnderflowZeroed)
                else
                    return err(ctx, .Eief64UnderflowBufferBleed);
            }

            // The EIEF in an LFH must include both uncompressed and compressed size:
            if (lfh and index != 16) return err(ctx, .Eief64Lfh);
            assert(index == size);
        }

        offset += size;
    }

    assert(offset <= extra_field.len);
}

// Compare LFH against CDH taking Data Descriptor Record into account:
fn diffCld(cdh_value: u64, lfh_value: u64, lfh: Lfh) bool {
    // LFH matches CDH:
    if (lfh_value == cdh_value)
        return false;
    // LFH delegates value to Data Descriptor:
    if (lfh.gp_bits.lfh_fields_zeroed and lfh_value == 0)
        return false;
    // LFH diverges from CDH:
    return true;
}

// Compare DDR against CDH:
fn diffCdhAndDdr(ctx: *Ctx, cdh: Cdh, ddr: Ddr) Error!void {
    if (ddr.crc32 != cdh.crc32)
        return err(ctx, .DiffDdrCrc32);
    if (ddr.compressed_size != cdh.compressed_size)
        return err(ctx, .DiffDdrCompressedSize);
    if (ddr.uncompressed_size != cdh.uncompressed_size)
        return err(ctx, .DiffDdrUncompressedSize);
}

// Compare LFH against CDH:
fn diffCdhAndLfh(ctx: *Ctx, cdh: Cdh, lfh: Lfh) Error!void {
    if (@as(u16, @bitCast(lfh.gp_bits)) != @as(u16, @bitCast(cdh.gp_bits)))
        return err(ctx, .DiffLfhGeneralPurposeBitFlag);
    if (lfh.compression_method != cdh.compression_method)
        return err(ctx, .DiffLfhCompressionMethod);
    if (lfh.last_mod_file_time != cdh.last_mod_file_time)
        return err(ctx, .DiffLfhLastModFileTime);
    if (lfh.last_mod_file_date != cdh.last_mod_file_date)
        return err(ctx, .DiffLfhLastModFileDate);
    if (diffCld(cdh.crc32, lfh.crc32, lfh))
        return err(ctx, .DiffLfhCrc32);
    if (diffCld(cdh.compressed_size, lfh.compressed_size, lfh))
        return err(ctx, .DiffLfhCompressedSize);
    if (diffCld(cdh.uncompressed_size, lfh.uncompressed_size, lfh))
        return err(ctx, .DiffLfhUncompressedSize);
    if (lfh.file_name.len != cdh.file_name.len)
        return err(ctx, .DiffLfhFileNameLength);
    // We assume decode_lfh() and decode_cdh() have already checked for overflow:
    if (!mem.eql(u8, lfh.file_name, cdh.file_name))
        return err(ctx, .DiffLfhFileName);
}

fn decodeLfh(ctx: *Ctx, buffer: []const u8, offset: u64) Error!Lfh {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    var fbs = std.io.fixedBufferStream(buf);
    const reader = fbs.reader();

    const lfh = reader.readStruct(LocalFileHeader.Complete) catch
        return err(ctx, .LfhOverflow);
    if (native_endian != .little)
        byteSwapAllFields(LocalFileHeader, &lfh);
    if (lfh.sig != LocalFileHeader.signature)
        return err(ctx, .LfhSignature);

    var header = Lfh{
        .offset = offset,
        .version_minimum = lfh.version_made,
        .gp_bits = lfh.gp_bits,
        .compression_method = lfh.compression_method,
        .last_mod_file_time = lfh.last_mod_file_time,
        .last_mod_file_date = lfh.last_mod_file_date,
        .crc32 = lfh.crc32,
        .compressed_size = lfh.compressed_size,
        .uncompressed_size = lfh.uncompressed_size,
        .length = zip_lfh_min,

        .file_name = "",
        .extra_field = "",
        .zip64 = false,
    };

    if (overflow(header.offset + header.length, lfh.file_name_length, buffer.len))
        return err(ctx, .LfhFileNameOverflow);
    header.file_name = buffer[header.offset + header.length ..][0..lfh.file_name_length];
    header.length += lfh.file_name_length;

    if (overflow(header.offset + header.length, lfh.extra_field_length, buffer.len))
        return err(ctx, .LfhExtraFieldOverflow);
    header.extra_field = buffer[header.offset + header.length ..][0..lfh.extra_field_length];
    header.length += lfh.extra_field_length;

    // ZIP64:
    header.zip64 = false;
    if (header.compressed_size == math.maxInt(u32) or
        header.uncompressed_size == math.maxInt(u32))
    {
        var relative_offset: u64 = 0;
        var disk: u64 = 0;
        try decodeEief64(
            ctx,
            header.extra_field,
            &header.compressed_size,
            &header.uncompressed_size,
            &relative_offset,
            &disk,
            &header.zip64,
            true,
        );
    }

    try verifyFlags(ctx, header.gp_bits);
    try verifyCompressionMethod(
        ctx,
        header.compression_method,
        header.compressed_size,
        header.uncompressed_size,
    );
    try verifyModTime(
        ctx,
        header.last_mod_file_date,
        header.last_mod_file_time,
    );
    try verifyFilename(ctx, header.file_name);
    try verifyString(ctx, header.file_name, header.gp_bits.utf8_fields);
    try verifyExtraField(
        ctx,
        header.extra_field,
        header.file_name,
    );
    return header;
}

fn decodeDdr(ctx: *Ctx, buffer: []const u8, offset: u64, zip64: bool) Error!Ddr {
    assert(offset < buffer.len);
    var min: u64 = zip_ddr_min;
    if (zip64) min = zip_ddr_64_min;

    // The DDR signature is optional but we expect at least 4 bytes regardless:
    if (overflow(offset, Ddr.signature.len, buffer.len))
        return err(ctx, .DdrOverflow);

    var header: Ddr = undefined;
    var off = offset;
    if (mem.startsWith(u8, buffer[offset..], Ddr.signature)) {
        header.offset = off;
        header.length = Ddr.signature.len + min;
        off += Ddr.signature.len;
    } else {
        header.offset = off;
        header.length = min;
    }

    if (overflow(off, min, buffer.len))
        return err(ctx, .DdrOverflow);
    const buf = buffer[off..];

    if (header.zip64) {
        assert(min == 4 + 8 + 8);
        header.crc32 = mem.readInt(u32, buf[0..4], .little);
        header.compressed_size = mem.readInt(u64, buf[4..12], .little);
        header.uncompressed_size = mem.readInt(u64, buf[12..20], .little);
    } else {
        assert(min == 4 + 4 + 4);
        header.crc32 = mem.readInt(u32, buf[0..4], .little);
        header.compressed_size = mem.readInt(u32, buf[4..8], .little);
        header.uncompressed_size = mem.readInt(u32, buf[8..12], .little);
    }
    return header;
}

fn decodeCdh(
    ctx: *Ctx,
    buffer: []const u8,
    offset: u64,
) Error!Cdh {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    var fbs = std.io.fixedBufferStream(buf);
    const reader = fbs.reader();

    var cdh2 = reader.readStruct(CentralDirectory.Complete) catch
        return err(ctx, .CdhOverflow);
    if (native_endian != .little)
        mem.byteSwapAllFields(CentralDirectory, &cdh2);
    if (cdh2.sig != CentralDirectory.signature)
        return err(ctx, .CdhSignature);

    // Used fields
    // - version_made: only used here for unix_mode
    // - gp_bits: used for zip_verify_flags.
    // - compression_method:
    // - last_mode_file_time/date
    // - crc32
    // - (un)compressed size
    // - *_length: Should be converted to a slice
    // - *_file_attributes: only used here for unix/dir check.
    var header = Cdh{
        .offset = offset,
        .gp_bits = @as(GeneralPurposeBits, @bitCast(cdh2.gp_bits)),
        .compression_method = @as(CompressionMethod, @enumFromInt(cdh2.compression_method)),
        .last_mod_file_time = cdh2.last_mod_file_time,
        .last_mod_file_date = cdh2.last_mod_file_date,
        .crc32 = cdh2.crc32,
        .compressed_size = cdh2.compressed_size,
        .uncompressed_size = cdh2.uncompressed_size,
        .disk = cdh2.disk_number_start,
        .relative_offset = cdh2.relative_offset,
        .length = zip_cdh_min,
        .file_name = buffer[offset + zip_cdh_min ..][0..cdh2.file_name_length],

        .extra_field = "",
        .file_comment = "",
        .zip64 = false,
        .unix_mode = 0,
        .directory = false,
    };
    header.length += header.file_name.len;
    if (overflow(header.offset, header.length, buffer.len))
        return err(ctx, .CdhFileNameOverflow);
    header.extra_field = buffer[header.offset + header.length ..][0..cdh2.extra_field_length];
    header.length += header.extra_field.len;
    if (overflow(header.offset, header.length, buffer.len))
        return err(ctx, .CdhExtraFieldOverflow);
    header.file_comment = buffer[header.offset + header.length ..][0..cdh2.file_comment_length];
    header.length += header.file_comment.len;
    if (overflow(header.offset, header.length, buffer.len))
        return err(ctx, .CdhFileCommentOverflow);
    header.unix_mode = 0;
    if ((cdh2.version_made >> 8) == zip_version_made_unix)
        header.unix_mode = cdh2.external_file_attributes >> 16;

    header.directory =
        (header.unix_mode & S.IFMT) == S.IFDIR or
        cdh2.external_file_attributes & 0x10 > 0 or
        (header.file_name.len > 0 and
        header.file_name[header.file_name.len - 1] == '/');

    // ZIP64:
    if (header.compressed_size == math.maxInt(u32) or
        header.uncompressed_size == math.maxInt(u32) or
        header.relative_offset == math.maxInt(u32) or
        header.disk == math.maxInt(u16))
    {
        try decodeEief64(
            ctx,
            header.extra_field,
            &header.compressed_size,
            &header.uncompressed_size,
            &header.relative_offset,
            &header.disk,
            &header.zip64,
            false,
        );
    }

    if (header.relative_offset > buffer.len)
        return err(ctx, .CdhRelativeOffsetOverflow);
    if (header.relative_offset > offset)
        return err(ctx, .CdhRelativeOffsetOverlap);

    try verifyFlags(ctx, header.gp_bits);
    try verifyCompressionMethod(
        ctx,
        header.compression_method,
        header.compressed_size,
        header.uncompressed_size,
    );
    // An LFH may have a zero compressed size with a non-zero uncompressed size
    // because the actual sizes may be in the DDR, but a CDH cannot be ex nihilo.
    // We cross-check the DDR against the CDH, so this check applies to the DDR:
    if (header.compressed_size == 0 and header.uncompressed_size != 0)
        return err(ctx, .ExNihilo);

    try verifyModTime(ctx, header.last_mod_file_date, header.last_mod_file_time);
    try verifyFilename(ctx, header.file_name);
    try verifyString(ctx, header.file_name, header.gp_bits.utf8_fields);
    try verifyExtraField(ctx, header.extra_field, header.file_name);
    try verifyString(ctx, header.file_comment, header.gp_bits.utf8_fields);
    if (header.disk != 0)
        return err(ctx, .MultipleDisks);
    try verifyUnixMode(ctx, header.unix_mode);
    if (header.directory) {
        if (header.compressed_size > 0) return err(ctx, .DirectoryCompressed);
        if (header.uncompressed_size > 0) return err(ctx, .DirectoryUncompressed);
    }
    return header;
}

fn decodeEocdl64(
    ctx: *Ctx,
    buffer: []const u8,
    offset: u64,
) Error!?Eocdl64 {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    if (overflow(offset, zip_eocdl_64, buffer.len))
        return err(ctx, .Eocdl64Overflow);
    if (!mem.startsWith(u8, buf, Eocdl64.signature))
        // A header field may actually be FFFF or FFFFFFFF without any Zip64 format:
        return null;

    const header = Eocdl64{
        .offset = offset,
        .disk = mem.readInt(u32, buf[4..8], .little),
        .eocdr_64_offset = mem.readInt(u64, buf[8..16], .little),
        .disks = mem.readInt(u32, buf[16..20], .little),
        .length = zip_eocdl_64,
    };
    if (header.disk != 0) return err(ctx, .Eocdl64Disk);
    if (overflow(header.eocdr_64_offset, zip_eocdr_64_min, header.offset))
        return err(ctx, .EocdrEocdl64Overflow);
    if (header.disks != 0 and header.disks != 1)
        return err(ctx, .Eocdl64Disks);
    return header;
}

fn decodeEocdr64(ctx: *Ctx, buffer: []const u8, offset: u64) Error!Eocdr64 {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    var fbs = std.io.fixedBufferStream(buf);
    const reader = fbs.reader();

    var eocdr = reader.readStruct(Eocdr64.Complete) catch
        return err(ctx, .LfhOverflow);
    if (native_endian != .little)
        mem.byteSwapAllFields(Eocdr64.Complete, &eocdr);
    if (eocdr.sig != @intFromEnum(Signature.eocdr64))
        return err(ctx, .Eocdr64Signature);

    var header = Eocdr64{
        .offset = offset,
        .version_made = eocdr.version_made,
        .version_minimum = eocdr.version_needed,
        .disk = eocdr.disk,
        .cd_disk = eocdr.cd_disk,
        .cd_disk_records = eocdr.cd_disk_records,
        .cd_records = eocdr.cd_records,
        .cd_size = eocdr.cd_size,
        .cd_offset = eocdr.cd_offset,
        .length = zip_eocdr_64_min,

        .extensible_data_sector = "",
    };

    // The value stored in "size of zip64 end of central directory record" is the
    // size of the remaining record and excludes the leading 12 bytes:
    // size_remaining = PURE_ZIP_EOCDR_64_MIN + extensible_data_sector_length - 12
    // extensible_data_sector_length = size_remaining - PURE_ZIP_EOCDR_64_MIN + 12
    const extensible_length = eocdr.size - (zip_eocdr_64_min - 12);
    header.extensible_data_sector = buf[0..extensible_length];
    header.length += header.extensible_data_sector.len;
    return header;
}

fn decodeEocdr64Upgrade(ctx: *Ctx, buffer: []const u8, header: *Eocdr) Error!void {
    header.zip64 = false;
    if (header.disk != math.maxInt(u16) and
        header.cd_disk != math.maxInt(u16) and
        header.cd_disk_records != math.maxInt(u16) and
        header.cd_records != math.maxInt(u16) and
        header.cd_size != math.maxInt(u32) and
        header.cd_offset != math.maxInt(u32))
    {
        return;
    }

    if (header.offset < zip_eocdl_64)
        return err(ctx, .Eocdl64NegativeOffset);

    assert(header.offset >= zip_eocdl_64);
    const eocdl_64 = if (try decodeEocdl64(ctx, buffer, header.offset - zip_eocdl_64)) |x| x else {
        return;
    };
    assert(!overflow(eocdl_64.offset, eocdl_64.length, header.offset));
    assert(eocdl_64.offset + eocdl_64.length == header.offset);
    assert(!overflow(eocdl_64.eocdr_64_offset, zip_eocdr_64_min, eocdl_64.offset));

    const eocdr_64 = try decodeEocdr64(ctx, buffer, eocdl_64.eocdr_64_offset);
    const eocdl_offset = eocdr_64.offset + eocdr_64.length;
    assert(eocdl_offset > eocdr_64.offset);
    if (eocdl_offset > eocdl_64.offset)
        return err(ctx, .EocdrEocdl64Overflow);
    if (eocdl_offset < eocdl_64.offset) {
        assert(eocdl_64.offset <= buffer.len);
        return if (zeroes(buffer[eocdl_offset..eocdl_64.offset]))
            err(ctx, .EocdrEocdl64UnderflowZeroed)
        else
            err(ctx, .EocdrEocdl64UnderflowBufferBleed);
    }

    assert(!overflow(eocdr_64.offset, eocdr_64.length, eocdl_64.offset));
    assert(eocdr_64.offset + eocdr_64.length == eocdl_64.offset);

    // Inherit only those values that are maxed out in the EOCDR:
    if (header.disk == math.maxInt(u16))
        header.disk = eocdr_64.disk;
    if (header.cd_disk == math.maxInt(u16))
        header.cd_disk = eocdr_64.cd_disk;
    if (header.cd_disk_records == math.maxInt(u16))
        header.cd_disk_records = eocdr_64.cd_disk_records;
    if (header.cd_records == math.maxInt(u16))
        header.cd_records = eocdr_64.cd_records;
    if (header.cd_size == math.maxInt(u32))
        header.cd_size = eocdr_64.cd_size;
    if (header.cd_offset == math.maxInt(u32))
        header.cd_offset = eocdr_64.cd_offset;
    // Verify that all values are now in agreement between the EOCDR and EOCDR_64:
    if (header.disk != eocdr_64.disk)
        return err(ctx, .DiffEocdrDisk);
    if (header.cd_disk != eocdr_64.cd_disk)
        return err(ctx, .DiffEocdrCdDisk);
    if (header.cd_disk_records != eocdr_64.cd_disk_records)
        return err(ctx, .DiffEocdrCdDiskRecords);
    if (header.cd_records != eocdr_64.cd_records)
        return err(ctx, .DiffEocdrCdRecords);
    if (header.cd_size != eocdr_64.cd_size)
        return err(ctx, .DiffEocdrCdSize);
    if (header.cd_offset != eocdr_64.cd_offset)
        return err(ctx, .DiffEocdrCdOffset);

    header.zip64 = true;
    header.offset = eocdr_64.offset;
    header.length = eocdr_64.length + eocdl_64.length + header.length;
}

fn decodeEocdr(ctx: *Ctx, buffer: []const u8, offset: u64) Error!Eocdr {
    if (overflow(offset, zip_eocdr_min, buffer.len))
        return err(ctx, .EocdrOverflow);
    const buf = buffer[offset..];
    if (!mem.startsWith(u8, buf, Eocdr.signature))
        return err(ctx, .EocdrSignature);

    // We consider header.offset to start at EOCDR_64 or EOCDR.
    // We consider header.length to include EOCDR_64, EOCDL_64 and EOCDR.
    var header = Eocdr{
        .offset = offset,
        .disk = mem.readInt(u16, buf[4..6], .little),
        .cd_disk = mem.readInt(u16, buf[6..8], .little),
        .cd_disk_records = mem.readInt(u16, buf[8..10], .little),
        .cd_records = mem.readInt(u16, buf[10..12], .little),
        .cd_size = mem.readInt(u32, buf[12..16], .little),
        .cd_offset = mem.readInt(u32, buf[16..20], .little),
        .comment_length = mem.readInt(u16, buf[20..22], .little),
        .length = zip_eocdr_min,

        .comment = "",
        .zip64 = false,
    };
    header.length += header.comment_length;
    if (overflow(header.offset, header.length, buffer.len))
        return err(ctx, .EocdrCommentOverflow);
    header.comment = buf[zip_eocdr_min..(zip_eocdr_min + header.comment_length)];

    // If we find an EOCDR_64 and EOCDL_64, we modify header.(offset, length):
    const length = zip_eocdr_min + header.comment_length;
    assert(header.length == length);
    try decodeEocdr64Upgrade(ctx, buffer, &header);
    if (header.zip64) {
        const length_64 = zip_eocdr_64_min + zip_eocdl_64;
        assert(header.length >= length + length_64);
    } else {
        assert(header.length == length);
    }

    if (header.cd_size < header.cd_records * zip_cdh_min)
        return err(ctx, .EocdrSizeOverflow);
    if (header.cd_size > 0 and header.cd_records == 0)
        return err(ctx, .EocdrSizeUnderflow);
    if (overflow(header.cd_offset, header.cd_size, header.offset))
        return err(ctx, .CdEocdrOverflow);
    if (header.disk != 0 or header.cd_disk != 0)
        return err(ctx, .MultipleDisks);
    if (header.cd_disk_records != header.cd_records)
        return err(ctx, .EocdrRecords);
    // The EOCDR has no General Purpose Bit Flag with which to indicate UTF-8.
    // Therefore, the comment encoding must always be CP437:
    try verifyString(ctx, header.comment[0..header.comment_length], false);
    const suffix_offset = header.offset + header.length;
    if (suffix_offset < buffer.len) {
        if (zeroes(buffer[suffix_offset..]))
            return err(ctx, .AppendedDataZeroed)
        else
            return err(ctx, .AppendedDataBufferBleed);
    }
    return header;
}

// Returns the crc32 hash of the uncompressed data
fn inflateRaw(ctx: *Ctx, compressed: []const u8, expected_len: usize, writer: anytype) Error!u32 {
    var hash = crc.init();
    if (expected_len == 0) return hash.final();

    var fbs = std.io.fixedBufferStream(compressed);
    var inflate = flate.decompressor(fbs.reader());
    // TODO(stephen): Migrate across the rest of the zlib errors?
    var reader = inflate.reader();
    var ct: usize = 0;

    const bufsz = std.mem.page_size;
    var buf: [bufsz]u8 = .{0} ** bufsz;
    while (ct < expected_len) {
        const sz = reader.read(&buf) catch return err(ctx, .InflateUncompressedUnderflow);
        writer.writeAll(buf[0..sz]) catch return err(ctx, .OutOfMemory); // TODO (MFA) new error code?
        hash.update(buf[0..sz]);
        ct += sz;
    }
    return hash.final();
}

fn locateEocdr(ctx: *Ctx, buffer: []const u8) Error!u64 {
    if (buffer.len < zip_eocdr_min) return err(ctx, .TooSmall);
    var index = @as(i64, @bitCast(buffer.len)) - zip_eocdr_min;
    // The EOCDR can be at most EOCDR_MIN plus a variable length comment.
    // The variable length of the comment can be at most a 16-bit integer.
    // Assuming no garbage after the EOCDR, our maximum search distance is:
    const floor = @max(0, index - math.maxInt(u16));

    assert(!overflow(@as(u64, @bitCast(index)), Eocdr.signature.len, buffer.len));
    while (index >= floor) : (index -= 1) {
        if (mem.eql(u8, buffer[@as(u64, @bitCast(index))..][0..4], Eocdr.signature)) {
            assert(!overflow(@as(u64, @bitCast(index)), 4, buffer.len));
            return @as(u64, @bitCast(index));
        }
    }

    return err(ctx, .EocdrNotFound);
}

fn locateFirstLfh(ctx: *Ctx, buffer: []const u8, eocdr: *const Eocdr) Error!u64 {
    assert(buffer.len >= 8);
    // We expect a Local File Header or End Of Central Directory Record signature:
    // TODO(joran):
    //  - Test empty file OK.
    //  - Test non-empty file OK.
    const string = if (eocdr.cd_records > 0)
        Lfh.signature
    else
        Eocdr.signature;
    if (mem.startsWith(u8, buffer, string))
        return 0;

    // A spanned/split archive may be preceded by a special spanning signature:
    // See APPNOTE 8.5.3 and 8.5.4.
    // TODO(joran):
    //  - Test spanned file OK (empty, non-empty).
    //  - Test split file OK (empty, non-empty).
    if (mem.startsWith(u8, buffer, span_signature) or
        mem.startsWith(u8, buffer, s_zip_temp))
        if (mem.startsWith(u8, buffer[span_signature.len..], string))
            return span_signature.len;

    const search_limit = @min(buffer.len, 1024);
    if (mem.indexOf(u8, buffer[0..search_limit], string)) |prepended_data| {
        return if (zeroes(buffer[0..prepended_data]))
            err(ctx, .PrependedDataZeroed)
        else
            err(ctx, .PrependedDataBufferBleed);
    }

    // We could not find any end to the prepended data:
    return err(ctx, .PrependedData);
}

// Compare LFH against DDR:
fn diffDdrLfh(ctx: *Ctx, ddr: *const Ddr, lfh: *const Lfh) Error!void {
    if (lfh.crc32 != 0 and lfh.crc32 != ddr.crc32)
        return err(ctx, .DiffLfhDdrCrc32);
    if (lfh.compressed_size != 0 and
        lfh.compressed_size != ddr.compressed_size)
        return err(ctx, .DiffLfhDdrCompressedSize);
    if (lfh.uncompressed_size != 0 and
        lfh.uncompressed_size != ddr.uncompressed_size)
        return err(ctx, .DiffLfhDdrUncompressedSize);
}

// Data which is optionally freed in deinit. Useful when a piece of data may be _either_ part of a larger buffer or not.
// and you only know which at runtime
const MaybeOwned = struct {
    owned: bool = false,
    data: []const u8,

    pub fn deinit(self: *MaybeOwned, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.data);
    }
};

fn verifyData(
    ctx: *Ctx,
    buffer: []const u8,
    cdh: *Cdh,
    lfh: *Lfh,
) Error!void {
    if (cdh.directory) {
        assert(cdh.compressed_size == 0);
        assert(cdh.uncompressed_size == 0);
        return;
    }

    if (cdh.uncompressed_size == 0) {
        if (cdh.compressed_size == 0) return;
        if (cdh.compressed_size == 2 and
            cdh.compression_method == .deflate and
            buffer[cdh.relative_offset + lfh.length + 0] == 3 and
            buffer[cdh.relative_offset + lfh.length + 1] == 0)
            return;
        return err(ctx, .AdNihilo);
    }

    assert(cdh.compressed_size > 0);
    assert(cdh.compressed_size <= math.maxInt(usize));
    assert(cdh.uncompressed_size > 0);
    assert(cdh.uncompressed_size <= math.maxInt(usize));

    // We verify the compression ratio here, after first checking for LFH overlap:
    // We do this to return zipBombFifield before zipBombRatio.
    ctx.compressed_size = math.add(u64, ctx.compressed_size, cdh.compressed_size) catch return err(ctx, .Overflow);
    ctx.uncompressed_size = math.add(u64, ctx.uncompressed_size, cdh.uncompressed_size) catch return err(ctx, .Overflow);
    try verifyCompressionRatio(
        ctx,
        ctx.compressed_size,
        ctx.uncompressed_size,
    );

    // This next part is expensive (inflating the whole zip contents) so we might skip it
    if (!ctx.do_decompress) return;

    const entry_bytes = buffer[cdh.relative_offset + lfh.length ..][0..cdh.compressed_size];

    // peek just the first two bytes to check if the entry is a zip
    var peek: [2]u8 = .{ 0, 0 };
    var hash: u64 = undefined;
    if (cdh.compression_method == .deflate) {
        var fbs = std.io.fixedBufferStream(&peek);
        var cw = ChainWriter{ .writers = &.{ fbs.writer().any(), std.io.null_writer.any() } };
        hash = try inflateRaw(
            ctx,
            entry_bytes,
            cdh.uncompressed_size,
            cw.writer(),
        );
    } else {
        assert(cdh.compression_method == .uncompressed);
        if (entry_bytes.len >= 2) {
            peek = .{ entry_bytes[0], entry_bytes[1] };
        }
        hash = crc.hash(entry_bytes);
    }

    if (hash != cdh.crc32)
        return err(ctx, .Crc32);

    // TODO(joran):
    //  Check for common ZIP extensions in addition to PK signature.
    if (mem.startsWith(u8, &peek, "PK")) {
        var bytes = ctx.allocator.alloc(u8, cdh.uncompressed_size) catch return err(ctx, .OutOfMemory);
        defer ctx.allocator.free(bytes);
        var fbs = std.io.fixedBufferStream(bytes);
        _ = try inflateRaw(ctx, entry_bytes, cdh.uncompressed_size, fbs.writer());
        try zipMeta(ctx, bytes[0..cdh.uncompressed_size]);
    } else {
        ctx.files += 1;
        if (ctx.files > files_max) return err(ctx, .BombFiles);
    }
}

fn zipMeta(ctx: *Ctx, buffer: []const u8) Error!void {
    // Update and check context against limits:
    ctx.depth += 1;
    if (ctx.depth > depth_max) return err(ctx, .BombDepth);
    ctx.files += 1;
    if (ctx.files > files_max) return err(ctx, .BombFiles);
    ctx.archives += 1;
    if (ctx.archives > archives_max) return err(ctx, .BombArchives);
    ctx.size = math.add(u64, ctx.size, buffer.len) catch return err(ctx, .Overflow);
    if (ctx.size > size_max) return err(ctx, .SizeMax);

    // A zip file must contain at least an end of central directory record:
    if (buffer.len < zip_eocdr_min) return err(ctx, .TooSmall);
    // ZIP64:
    if (buffer.len > math.maxInt(u32) - 1) return err(ctx, .Size4Gb);
    // Malicious archive signatures (almost certainly when masquerading as a ZIP):
    if (mem.startsWith(u8, buffer, "Rar!\x1a\x07")) return err(ctx, .Rar);
    if (mem.startsWith(u8, buffer, "ustar")) return err(ctx, .Tar);
    if (mem.startsWith(u8, buffer, "xar!")) return err(ctx, .Xar);

    // Locate and decode end of central directory record:
    const offset = try locateEocdr(ctx, buffer);
    var eocdr = try decodeEocdr(ctx, buffer, offset);

    // Locate the offset of the first local file header:
    var lfh_offset = try locateFirstLfh(ctx, buffer, &eocdr);
    assert(lfh_offset == 0 or lfh_offset == span_signature.len);

    // Compare central directory headers with local file headers:
    var cdh: Cdh = undefined;
    var lfh: Lfh = undefined;
    var cdh_offset = eocdr.cd_offset;
    var cdh_record: u64 = 0;
    while (cdh_record < eocdr.cd_records) {
        // Central Directory Header:
        cdh = try decodeCdh(ctx, buffer, cdh_offset);

        if (lfh_offset > cdh.relative_offset) {
            if (cdh.directory and cdh.relative_offset == 0 and
                cdh.crc32 == 0 and cdh.compressed_size == 0 and cdh.uncompressed_size == 0)
                return err(ctx, .DirectoryHasNoLfh);
            return err(ctx, .BombFifield);
        }

        if (lfh_offset < cdh.relative_offset) {
            assert(cdh.relative_offset <= buffer.len);
            if (zeroes(buffer[lfh_offset..cdh.relative_offset]))
                return err(ctx, .LfhUnderflowZeroed)
            else
                return err(ctx, .LfhUnderflowBufferBleed);
        }

        // Local File Header:
        assert(cdh.relative_offset == lfh_offset);
        lfh = try decodeLfh(ctx, buffer, cdh.relative_offset);
        try diffCdhAndLfh(ctx, cdh, lfh);
        try verifySymlink(ctx, cdh, lfh, buffer);
        assert(lfh.length >= zip_lfh_min);
        lfh_offset += lfh.length;

        // File Data (compressed or uncompressed):
        lfh_offset = math.add(u64, lfh_offset, cdh.compressed_size) catch return err(ctx, .Overflow);
        if (lfh_offset > buffer.len) return err(ctx, .LfhDataOverflow);

        // Data Descriptor Record (optional):
        if (lfh.gp_bits.lfh_fields_zeroed) {
            const ddr = try decodeDdr(ctx, buffer, lfh_offset, lfh.zip64);
            try diffCdhAndDdr(ctx, cdh, ddr);
            try diffDdrLfh(ctx, &ddr, &lfh);
            lfh_offset += ddr.length;
        }
        if (lfh_offset > eocdr.cd_offset) return err(ctx, .LfOverflow);

        // We descend into the data only after checking for LFH overlap above:
        // We can therefore descend only after decoding at least two entries.
        if (cdh_record > 0)
            try verifyData(ctx, buffer, &cdh, &lfh);

        assert(cdh.length >= zip_cdh_min);
        cdh_offset += cdh.length;
        cdh_record += 1;

        if (ctx.directory) |dir| {
            // TODO (MFA) should I clone the cdh? It's pointer fields are pointers into
            // the buffer, which might be a memory mapped region. IDK how efficient this will be when
            // entries could be quite far apart (although typically I expect the central directory
            // will all end up in the file system cache on sane file system implementations)
            dir.put(cdh.file_name, cdh) catch return err(ctx, .OutOfMemory);
        }
    }

    // Descend into the previous CDH and LFH:
    if (cdh_record > 0)
        try verifyData(ctx, buffer, &cdh, &lfh);
    if (lfh_offset > eocdr.cd_offset) return err(ctx, .LfOverflow);
    if (lfh_offset < eocdr.cd_offset) {
        assert(eocdr.cd_offset <= buffer.len);
        if (zeroes(buffer[lfh_offset..eocdr.cd_offset]))
            return err(ctx, .LfUnderflowZeroed)
        else
            return err(ctx, .LfUnderflowBufferBleed);
    }

    const cdh_offset_expected = eocdr.cd_offset + eocdr.cd_size;
    if (cdh_offset > cdh_offset_expected) return err(ctx, .CdOverflow);
    if (cdh_offset < cdh_offset_expected) {
        assert(cdh_offset_expected <= buffer.len);
        if (zeroes(buffer[cdh_offset..cdh_offset_expected]))
            return err(ctx, .CdUnderflowZeroed)
        else
            return err(ctx, .CdUnderflowBufferBleed);
    }

    if (cdh_offset < eocdr.offset) {
        assert(eocdr.offset <= buffer.len);
        if (zeroes(buffer[cdh_offset..eocdr.offset]))
            return err(ctx, .CdEocdrUnderflowZeroed)
        else
            return err(ctx, .CdEocdrUnderflowBufferBleed);
    }

    assert(cdh_offset == eocdr.offset);
    assert(cdh_offset + eocdr.length == buffer.len);
    assert(ctx.depth > 0);
    ctx.depth -= 1;
}

pub const Options = struct {
    diagnostics: ?*Diagnostics = null,
};
pub fn zip(buffer: []const u8, allocator: mem.Allocator, options: Options) Error!void {
    // SPEC: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

    // Further, as per ISO/IEC 21320-1:2015, we disable support for:
    // * multiple disks
    // * encryption and archive headers
    // * encryption mechanisms
    // * compression methods other than 0 or 8
    // * ZIP64 version 2 (and we also disable ZIP64 version 1)
    // * unused and reserved flags

    // Contrary to ISO/IEC 21320-1:2015, we do not require:
    // * `version needed to extract` to be at most 45 (too many false positives)
    // * bit 11 (UTF-8) when a string byte exceeds 0x7F (this could also be CP437)
    var ctx = Ctx{ .allocator = allocator, .diagnostics = options.diagnostics };
    return zipMeta(&ctx, buffer);
}

// Write to one stream until NoSpaceLeft, then move onto the next and so on.

const ChainWriter = struct {
    const WriteError = std.io.AnyWriter.Error;
    const Writer = std.io.Writer(*ChainWriter, anyerror, ChainWriter.write);
    writers: []const std.io.AnyWriter,
    ix: usize = 0,

    pub fn writer(self: *ChainWriter) Writer {
        return .{
            .context = self,
        };
    }
    fn write(self: *ChainWriter, bytes: []const u8) WriteError!usize {
        if (self.ix >= self.writers.len) return error.NoSpaceLeft;
        var wtr = self.writers[self.ix];
        const written = wtr.write(bytes) catch |e| switch (e) {
            error.NoSpaceLeft => {
                self.ix += 1;
                return 0;
            },
            else => return e,
        };
        return written;
    }
};

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

const FbsType = std.io.FixedBufferStream([]u8);

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

fn testFailure(buf: []const u8, e: ErrorSubtype) !void {
    var diags: Diagnostics = .{};
    try std.testing.expectError(error.ZipError, zip(buf, std.testing.allocator, .{ .diagnostics = &diags }));
    try std.testing.expectEqual(e, diags.subtype);
}

test "foo" {
    var buf = mem.zeroes([4096]u8);
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    {
        writeEocdr(&fbs, .{});
        try zip(fbs.getWritten(), std.testing.allocator, .{});
    }
    {
        writeEocdr(&fbs, .{});
        try testFailure(fbs.getWritten()[0..21], .TooSmall);
    }
    {
        const bytes = std.fmt.hexToBytes(
            &buf,
            "526172211a0700000000000000000000000000000000",
        ) catch unreachable;
        try testFailure(bytes, .Rar);
    }
    {
        const bytes = std.fmt.hexToBytes(
            &buf,
            "75737461720000000000000000000000000000000000",
        ) catch unreachable;
        try testFailure(bytes, .Tar);
    }
    {
        const bytes = std.fmt.hexToBytes(
            &buf,
            "78617221000000000000000000000000000000000000",
        ) catch unreachable;
        try testFailure(bytes, .Xar);
    }
    {
        writeEocdr(&fbs, .{ .signature = .{ 0x50, 0x4b, 0x05, 0x05 } });
        try testFailure(fbs.getWritten(), .EocdrNotFound);
    }
    {
        writeEocdr(&fbs, .{ .records = 2, .size = 46 * 2 - 1 });
        try testFailure(fbs.getWritten(), .EocdrSizeOverflow);
    }
    {
        writeEocdr(&fbs, .{ .records = 2, .size = 46 * 2 - 1 });
        try testFailure(fbs.getWritten(), .EocdrSizeOverflow);
    }
    {
        writeEocdr(&fbs, .{ .records = 0, .size = 46 });
        try testFailure(fbs.getWritten(), .EocdrSizeUnderflow);
    }
    {
        writeEocdr(&fbs, .{ .records = 1, .size = 46, .offset = 0 });
        try testFailure(fbs.getWritten(), .CdEocdrOverflow);
    }
    {
        writeEocdr(&fbs, .{ .disk_records = 1, .records = 0 });
        try testFailure(fbs.getWritten(), .EocdrRecords);
    }
    {
        writeEocdr(&fbs, .{ .disk = 1 });
        try testFailure(fbs.getWritten(), .MultipleDisks);
    }
    {
        writeEocdr(&fbs, .{});
        writer.writeByteNTimes(0, 13) catch unreachable;
        try testFailure(fbs.getWritten(), .AppendedDataZeroed);
        fbs.reset();
    }
    {
        writeEocdr(&fbs, .{ .reset_buffer = false });
        writer.writeByteNTimes(1, 97) catch unreachable;
        try testFailure(fbs.getWritten(), .AppendedDataBufferBleed);
        fbs.reset();
    }
    {
        writeEocdr(&fbs, .{ .reset_buffer = false });
        writer.writeByteNTimes(1, 97) catch unreachable;
        try testFailure(fbs.getWritten(), .AppendedDataBufferBleed);
        fbs.reset();
    }
    {
        writer.writeByteNTimes(1, 2048) catch unreachable;
        writeEocdr(&fbs, .{ .reset_buffer = false });
        try testFailure(fbs.getWritten(), .PrependedData);
        fbs.reset();
    }
    {
        writer.writeByteNTimes(1, 1) catch unreachable;
        writeEocdr(&fbs, .{ .reset_buffer = false });
        try testFailure(fbs.getWritten(), .PrependedDataBufferBleed);
        fbs.reset();
    }
    {
        writer.writeByteNTimes(0, 1) catch unreachable;
        writeEocdr(&fbs, .{ .reset_buffer = false });
        try testFailure(fbs.getWritten(), .PrependedDataZeroed);
        fbs.reset();
    }
}

test {
    _ = @import("regress.zig");
}
