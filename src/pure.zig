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
const deflate = std.compress.deflate;

pub const errors = error{
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
};

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
    return mem.readIntLittle(u32, &[4]u8{ 'P', 'K', b1, b2 });
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
        return mem.readIntLittle(u32, &[4]u8{ 'P', 'K', b1, b2 });
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

fn verifyCompressionRatio(compressed_size: u64, uncompressed_size: u64) errors!void {
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
    if (score > ratio_score_max)
        return error.BombRatio;
}

fn verifyCompressionMethod(
    method: CompressionMethod,
    compressed_size: u64,
    uncompressed_size: u64,
) errors!void {
    switch (method) {
        .uncompressed => if (compressed_size != uncompressed_size)
            return error.StoredCompressionSizeMismatch,
        .deflate => {},
        .AEx => return error.CompressionMethodEncrypted,
        // CVE-2016-9844:
        // Defend vulnerable implementations against overflow when the two-byte
        // compression method in the central directory file header exceeds 999.
        // https://bugs.launchpad.net/ubuntu/+source/unzip/+bug/1643750
        else => if (@intFromEnum(method) > 999)
            return error.CompressionMethodDangerous
        else
            return error.CompressionMethodUnsupported,
    }

    // CVE-2018-18384:
    // Defend vulnerable implementations against buffer overflow.
    // https://bugzilla.suse.com/show_bug.cgi?id=1110194
    if (uncompressed_size > 0 and
        compressed_size > uncompressed_size and
        compressed_size / uncompressed_size >= 2)
        return error.DangerousNegativeCompressionRatio;
}

fn verifyModTime(date: u64, time: u64) errors!void {
    if (date > math.maxInt(u16)) return error.DateOverflow;
    if (time > math.maxInt(u16)) return error.TimeOverflow;
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

    if (year > 2099) return error.DateYearOverflow;
    if (month > 12) return error.DateMonthOverflow;
    if (day > 31) return error.DateDayOverflow;
    if (hour > 23) return error.TimeHourOverflow;
    if (minute > 59) return error.TimeMinuteOverflow;
    if (second > 59) return error.TimeSecondOverflow;
}

fn verifyExtraField(extra_field: []const u8, file_name: []const u8) errors!void {
    if (extra_field.len > zip_extra_field_max)
        return error.ExtraFieldMax;
    // The extra field contains a variety of optional data such as OS-specific
    // attributes. It is divided into chunks, each with a 16-bit ID code and a
    // 16-bit length.
    if (extra_field.len != 0 and extra_field.len < 4)
        return error.ExtraFieldMin;

    // Check extra field attribute sizes, and specifically the unicode path:
    var offset: u64 = 0;
    while (offset + 2 + 2 <= extra_field.len) {
        const buf = extra_field[offset..];
        const id = mem.readIntLittle(u16, buf[0..2]);
        const size = mem.readIntLittle(u16, buf[2..4]);
        if (offset + 2 + 2 + size > extra_field.len)
            return error.ExtraFieldAttributeOverflow;

        if (id == 0x7075) {
            // We expect at least a 1-byte version followed by a 4-byte crc32:
            if (size < 1 + 4)
                return error.ExtraFieldUnicodePathOverflow;
            assert(offset + 2 + 2 + 1 <= extra_field.len);
            const version = buf[2 + 2];
            if (version != 1)
                return error.ExtraFieldUnicodePathVersion;
            // We require the unicode path to match the central directory file even if
            // the crc32 of the non-unicode path is different. Otherwise, an attacker
            // could present an alternative extension to bypass content inspection.
            //const base = offset + 2 + 2 + 1 + 4;
            //const unicode_path = extra_field[base .. base + size - 1 - 4];
            const unicode_path = buf[2 + 2 + 1 + 4 ..][0 .. size - 1 - 4];
            if (!mem.eql(u8, unicode_path, file_name))
                return error.ExtraFieldUnicodePathDiff;
        }

        offset += 4;
        offset += size;
    }

    if (offset > extra_field.len)
        return error.ExtraFieldOverflow;
    if (offset < extra_field.len) {
        if (zeroes(extra_field[offset..extra_field.len]))
            return error.ExtraFieldUnderflowZeroed
        else
            return error.ExtraFieldUnderflowBufferBleed;
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

fn verifyUnixMode(value: u64) errors!void {
    if (value > math.maxInt(u16)) return error.UnixModeOverflow;
    // Detect dangerous file types:
    switch (value & S.IFMT) {
        S.IFBLK => return error.UnixModeBlockDevice,
        S.IFCHR => return error.UnixModeCharacterDevice,
        S.IFIFO => return error.UnixModeFifo,
        S.IFSOCK => return error.UnixModeSocket,
        else => {},
    }
    // Detect dangerous permissions:
    // CVE-2005-0602
    // https://marc.info/?l=bugtraq&m=110960796331943&w=2
    if (value & S.ISVTX > 0) return error.UnixModePermissionsSticky;
    if (value & S.ISGID > 0) return error.UnixModePermissionsSetgid;
    if (value & S.ISUID > 0) return error.UnixModePermissionsSetuid;
}

fn verifyFilename(name: []const u8) errors!void {
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
        return error.FileNameLength;
    // CVE-2003-0282 (aka "JELMER"):
    // Some zip implementations filter control characters amongst others.
    // This behavior can be exploited to mask ".." in a directory traversal.
    // https://www.securityfocus.com/archive/1/321090
    if (pathControlCharacters(name))
        return error.FileNameControlCharacters;
    if (pathDrive(name))
        return error.FileNameTraversalDrivePath;
    if (pathRelative(name))
        return error.FileNameTraversalRelativePath;
    if (pathDoubleDots(name))
        return error.FileNameTraversalDoubleDots;
    if (pathComponentOverflow(name))
        return error.FileNameComponentOverflow;
    // All slashes must be forward according to the APPNOTE.TXT specification:
    for (name) |c|
        if (c == '\\') return error.FileNameBackslash;
}

fn verifyFlags(bits: GeneralPurposeBits) errors!void {
    if (bits.traditional_encryption) return error.FlagTraditionalEncryption;
    if (bits.enhanced_deflate) return error.FlagEnhancedDeflate;
    if (bits.compressed_patched) return error.FlagCompressedPatchedData;
    if (bits.strong_encryption) return error.FlagStrongEncryption;
    if (bits.bit7_unused) return error.FlagUnusedBit7;
    if (bits.bit8_unused) return error.FlagUnusedBit8;
    if (bits.bit9_unused) return error.FlagUnusedBit9;
    if (bits.bit10_unused) return error.FlagUnusedBit10;
    if (bits.enhanced_compression) return error.FlagEnhancedCompression;
    if (bits.masked_local_headers) return error.FlagMaskedLocalHeaders;
    if (bits.bit14_reserved) return error.FlagReservedBit14;
    if (bits.bit15_reserved) return error.FlagReservedBit15;
}

fn verifyString(string: []const u8, utf8: bool) errors!void {
    if (string.len > zip_string_max) return error.StringMax;
    for (string) |c|
        if (c == 0) return error.StringNullByte;

    if (utf8) {
        // TODO(joran): Verify that UTF-8 encoding is valid:
        //  Some systems such as macOS never bother to set bit 11 to indicate UTF-8.
        //  We therefore always attempt UTF-8 and fallback to CP437 only on error.
        //  If the string must be UTF-8 then reject the string as invalid.
    }
}

fn verifySymlink(cdh: Cdh, lfh: Lfh, buffer: []const u8) errors!void {
    if ((cdh.unix_mode & S.IFMT) != S.IFLNK)
        return;
    if (cdh.compression_method != .uncompressed)
        return error.SymlinkCompressed;

    assert(cdh.relative_offset == lfh.offset);
    assert(!overflow(cdh.relative_offset, lfh.length, cdh.offset));
    const offset = cdh.relative_offset + lfh.length;
    const symlink = buffer[offset..][0..cdh.compressed_size];
    // Check for PATH_MAX overflow:
    if (symlink.len > path_max) return error.SymlinkLength;
    // Check for control characters used to mask a directory traversal:
    if (pathControlCharacters(symlink))
        return error.SymlinkControlCharacters;
    // Check for a directory traversal:
    if (pathDrive(symlink))
        return error.SymlinkTraversalDrivePath;
    if (pathRelative(symlink))
        return error.SymlinkTraversalRelativePath;
    if (pathDoubleDots(symlink))
        return error.SymlinkTraversalDoubleDots;
    // Check for path component overflow:
    if (pathComponentOverflow(symlink))
        return error.SymlinkComponentOverflow;
}

fn decodeEief64(
    extra_field: []const u8,
    compressed_size: *u64,
    uncompressed_size: *u64,
    relative_offset: *u64,
    disk: *u64,
    zip64: *bool,
    lfh: bool,
) errors!void {
    assert(compressed_size.* == math.maxInt(u32) or
        uncompressed_size.* == math.maxInt(u32) or
        relative_offset.* == math.maxInt(u32) or
        disk.* == math.maxInt(u16));
    assert(zip64.* == false);

    if (extra_field.len > zip_extra_field_max)
        return error.ExtraFieldMax;
    if (extra_field.len != 0 and extra_field.len < 4)
        return error.ExtraFieldMin;

    var offset: u64 = 0;
    while (offset + 4 <= extra_field.len) {
        const id = mem.readIntLittle(u16, extra_field[offset + 0 ..][0..2]);
        const size = mem.readIntLittle(u16, extra_field[offset + 2 ..][0..2]);
        offset += 4;
        if (offset + size > extra_field.len)
            return error.ExtraFieldAttributeOverflow;

        if (id == 0x0001) {
            zip64.* = true;

            var index: u64 = 0;
            if (uncompressed_size.* == math.maxInt(u32)) {
                if (index + 8 > size) return error.Eief64UncompressedSize;
                uncompressed_size.* = mem.readIntLittle(u64, extra_field[offset + index ..][0..8]);
                index += 8;
            }
            if (compressed_size.* == math.maxInt(u32)) {
                if (index + 8 > size) return error.Eief64CompressedSize;
                compressed_size.* = mem.readIntLittle(u64, extra_field[offset + index ..][0..8]);
                index += 8;
            }
            if (relative_offset.* == math.maxInt(u32)) {
                if (index + 8 > size) return error.Eief64RelativeOffset;
                relative_offset.* = mem.readIntLittle(u64, extra_field[offset + index ..][0..8]);
                index += 8;
            }
            if (disk.* == math.maxInt(u16)) {
                if (index + 4 > size) return error.Eief64Disk;
                disk.* = mem.readIntLittle(u32, extra_field[offset + index ..][0..4]);
                index += 4;
            }

            assert(offset + size <= extra_field.len);
            if (index < size) {
                if (zeroes(extra_field[offset + index .. offset + size]))
                    return error.Eief64UnderflowZeroed
                else
                    return error.Eief64UnderflowBufferBleed;
            }

            // The EIEF in an LFH must include both uncompressed and compressed size:
            if (lfh and index != 16) return error.Eief64Lfh;
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
fn diffCdhAndDdr(cdh: Cdh, ddr: Ddr) errors!void {
    if (ddr.crc32 != cdh.crc32)
        return error.DiffDdrCrc32;
    if (ddr.compressed_size != cdh.compressed_size)
        return error.DiffDdrCompressedSize;
    if (ddr.uncompressed_size != cdh.uncompressed_size)
        return error.DiffDdrUncompressedSize;
}

// Compare LFH against CDH:
fn diffCdhAndLfh(cdh: Cdh, lfh: Lfh) errors!void {
    if (@as(u16, @bitCast(lfh.gp_bits)) != @as(u16, @bitCast(cdh.gp_bits)))
        return error.DiffLfhGeneralPurposeBitFlag;
    if (lfh.compression_method != cdh.compression_method)
        return error.DiffLfhCompressionMethod;
    if (lfh.last_mod_file_time != cdh.last_mod_file_time)
        return error.DiffLfhLastModFileTime;
    if (lfh.last_mod_file_date != cdh.last_mod_file_date)
        return error.DiffLfhLastModFileDate;
    if (diffCld(cdh.crc32, lfh.crc32, lfh))
        return error.DiffLfhCrc32;
    if (diffCld(cdh.compressed_size, lfh.compressed_size, lfh))
        return error.DiffLfhCompressedSize;
    if (diffCld(cdh.uncompressed_size, lfh.uncompressed_size, lfh))
        return error.DiffLfhUncompressedSize;
    if (lfh.file_name.len != cdh.file_name.len)
        return error.DiffLfhFileNameLength;
    // We assume decode_lfh() and decode_cdh() have already checked for overflow:
    if (!mem.eql(u8, lfh.file_name, cdh.file_name))
        return error.DiffLfhFileName;
}

fn decodeLfh(buffer: []const u8, offset: u64) errors!Lfh {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    var fbs = std.io.fixedBufferStream(buf);
    const reader = fbs.reader();

    const lfh = reader.readStruct(LocalFileHeader.Complete) catch
        return error.LfhOverflow;
    if (native_endian != .Little)
        byteSwapAllFields(LocalFileHeader, &lfh);
    if (lfh.sig != LocalFileHeader.signature)
        return error.LfhSignature;

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
        return error.LfhFileNameOverflow;
    header.file_name = buffer[header.offset + header.length ..][0..lfh.file_name_length];
    header.length += lfh.file_name_length;

    if (overflow(header.offset + header.length, lfh.extra_field_length, buffer.len))
        return error.LfhExtraFieldOverflow;
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
            header.extra_field,
            &header.compressed_size,
            &header.uncompressed_size,
            &relative_offset,
            &disk,
            &header.zip64,
            true,
        );
    }

    try verifyFlags(header.gp_bits);
    try verifyCompressionMethod(
        header.compression_method,
        header.compressed_size,
        header.uncompressed_size,
    );
    try verifyModTime(
        header.last_mod_file_date,
        header.last_mod_file_time,
    );
    try verifyFilename(header.file_name);
    try verifyString(header.file_name, header.gp_bits.utf8_fields);
    try verifyExtraField(
        header.extra_field,
        header.file_name,
    );
    return header;
}

fn decodeDdr(buffer: []const u8, offset: u64, zip64: bool) errors!Ddr {
    assert(offset < buffer.len);
    var min: u64 = zip_ddr_min;
    if (zip64) min = zip_ddr_64_min;

    // The DDR signature is optional but we expect at least 4 bytes regardless:
    if (overflow(offset, Ddr.signature.len, buffer.len))
        return error.DdrOverflow;

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
        return error.DdrOverflow;
    const buf = buffer[off..];

    if (header.zip64) {
        assert(min == 4 + 8 + 8);
        header.crc32 = mem.readIntLittle(u32, buf[0..4]);
        header.compressed_size = mem.readIntLittle(u64, buf[4..12]);
        header.uncompressed_size = mem.readIntLittle(u64, buf[12..20]);
    } else {
        assert(min == 4 + 4 + 4);
        header.crc32 = mem.readIntLittle(u32, buf[0..4]);
        header.compressed_size = mem.readIntLittle(u32, buf[4..8]);
        header.uncompressed_size = mem.readIntLittle(u32, buf[8..12]);
    }
    return header;
}

fn decodeCdh(
    buffer: []const u8,
    offset: u64,
) errors!Cdh {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    var fbs = std.io.fixedBufferStream(buf);
    const reader = fbs.reader();

    var cdh2 = reader.readStruct(CentralDirectory.Complete) catch
        return error.CdhOverflow;
    if (native_endian != .Little)
        mem.byteSwapAllFields(CentralDirectory, &cdh2);
    if (cdh2.sig != CentralDirectory.signature)
        return error.CdhSignature;

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
        return error.CdhFileNameOverflow;
    header.extra_field = buffer[header.offset + header.length ..][0..cdh2.extra_field_length];
    header.length += header.extra_field.len;
    if (overflow(header.offset, header.length, buffer.len))
        return error.CdhExtraFieldOverflow;
    header.file_comment = buffer[header.offset + header.length ..][0..cdh2.file_comment_length];
    header.length += header.file_comment.len;
    if (overflow(header.offset, header.length, buffer.len))
        return error.CdhFileCommentOverflow;
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
        return error.CdhRelativeOffsetOverflow;
    if (header.relative_offset > offset)
        return error.CdhRelativeOffsetOverlap;

    try verifyFlags(header.gp_bits);
    try verifyCompressionMethod(
        header.compression_method,
        header.compressed_size,
        header.uncompressed_size,
    );
    // An LFH may have a zero compressed size with a non-zero uncompressed size
    // because the actual sizes may be in the DDR, but a CDH cannot be ex nihilo.
    // We cross-check the DDR against the CDH, so this check applies to the DDR:
    if (header.compressed_size == 0 and header.uncompressed_size != 0)
        return error.ExNihilo;

    try verifyModTime(header.last_mod_file_date, header.last_mod_file_time);
    try verifyFilename(header.file_name);
    try verifyString(header.file_name, header.gp_bits.utf8_fields);
    try verifyExtraField(header.extra_field, header.file_name);
    try verifyString(header.file_comment, header.gp_bits.utf8_fields);
    if (header.disk != 0)
        return error.MultipleDisks;
    try verifyUnixMode(header.unix_mode);
    if (header.directory) {
        if (header.compressed_size > 0) return error.DirectoryCompressed;
        if (header.uncompressed_size > 0) return error.DirectoryUncompressed;
    }
    return header;
}

fn decodeEocdl64(
    buffer: []const u8,
    offset: u64,
) errors!Eocdl64 {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    if (overflow(offset, zip_eocdl_64, buffer.len))
        return error.Eocdl64Overflow;
    if (!mem.startsWith(u8, buf, Eocdl64.signature))
        return error.Eocdl64Signature;

    var header = Eocdl64{
        .offset = offset,
        .disk = mem.readIntLittle(u32, buf[4..8]),
        .eocdr_64_offset = mem.readIntLittle(u64, buf[8..16]),
        .disks = mem.readIntLittle(u32, buf[16..20]),
        .length = zip_eocdl_64,
    };
    if (header.disk != 0) return error.Eocdl64Disk;
    if (overflow(header.eocdr_64_offset, zip_eocdr_64_min, header.offset))
        return error.EocdrEocdl64Overflow;
    if (header.disks != 0 and header.disks != 1)
        return error.Eocdl64Disks;
    return header;
}

fn decodeEocdr64(buffer: []const u8, offset: u64) errors!Eocdr64 {
    assert(offset < buffer.len);
    const buf = buffer[offset..];
    var fbs = std.io.fixedBufferStream(buf);
    const reader = fbs.reader();

    var eocdr = reader.readStruct(Eocdr64.Complete) catch
        return error.LfhOverflow;
    if (native_endian != .Little)
        mem.byteSwapAllFields(Eocdr64.Complete, &eocdr);
    if (eocdr.sig != @intFromEnum(Signature.eocdr64))
        return error.Eocdr64Signature;

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

fn decodeEocdr64Upgrade(buffer: []const u8, header: *Eocdr) errors!void {
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
        return error.Eocdl64NegativeOffset;

    assert(header.offset >= zip_eocdl_64);
    var eocdl_64 = decodeEocdl64(buffer, header.offset - zip_eocdl_64) catch |err| {
        // A header field may actually be FFFF or FFFFFFFF without any Zip64 format:
        if (err == error.Eocdl64Signature) return;
        return err;
    };
    assert(!overflow(eocdl_64.offset, eocdl_64.length, header.offset));
    assert(eocdl_64.offset + eocdl_64.length == header.offset);
    assert(!overflow(eocdl_64.eocdr_64_offset, zip_eocdr_64_min, eocdl_64.offset));

    var eocdr_64 = try decodeEocdr64(buffer, eocdl_64.eocdr_64_offset);
    const eocdl_offset = eocdr_64.offset + eocdr_64.length;
    assert(eocdl_offset > eocdr_64.offset);
    if (eocdl_offset > eocdl_64.offset)
        return error.EocdrEocdl64Overflow;
    if (eocdl_offset < eocdl_64.offset) {
        assert(eocdl_64.offset <= buffer.len);
        return if (zeroes(buffer[eocdl_offset..eocdl_64.offset]))
            error.EocdrEocdl64UnderflowZeroed
        else
            error.EocdrEocdl64UnderflowBufferBleed;
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
        return error.DiffEocdrDisk;
    if (header.cd_disk != eocdr_64.cd_disk)
        return error.DiffEocdrCdDisk;
    if (header.cd_disk_records != eocdr_64.cd_disk_records)
        return error.DiffEocdrCdDiskRecords;
    if (header.cd_records != eocdr_64.cd_records)
        return error.DiffEocdrCdRecords;
    if (header.cd_size != eocdr_64.cd_size)
        return error.DiffEocdrCdSize;
    if (header.cd_offset != eocdr_64.cd_offset)
        return error.DiffEocdrCdOffset;

    header.zip64 = true;
    header.offset = eocdr_64.offset;
    header.length = eocdr_64.length + eocdl_64.length + header.length;
}

fn decodeEocdr(buffer: []const u8, offset: u64) errors!Eocdr {
    if (overflow(offset, zip_eocdr_min, buffer.len))
        return error.EocdrOverflow;
    const buf = buffer[offset..];
    if (!mem.startsWith(u8, buf, Eocdr.signature))
        return error.EocdrSignature;

    // We consider header.offset to start at EOCDR_64 or EOCDR.
    // We consider header.length to include EOCDR_64, EOCDL_64 and EOCDR.
    var header = Eocdr{
        .offset = offset,
        .disk = mem.readIntLittle(u16, buf[4..6]),
        .cd_disk = mem.readIntLittle(u16, buf[6..8]),
        .cd_disk_records = mem.readIntLittle(u16, buf[8..10]),
        .cd_records = mem.readIntLittle(u16, buf[10..12]),
        .cd_size = mem.readIntLittle(u32, buf[12..16]),
        .cd_offset = mem.readIntLittle(u32, buf[16..20]),
        .comment_length = mem.readIntLittle(u16, buf[20..22]),
        .length = zip_eocdr_min,

        .comment = "",
        .zip64 = false,
    };
    header.length += header.comment_length;
    if (overflow(header.offset, header.length, buffer.len))
        return error.EocdrCommentOverflow;
    header.comment = buf[zip_eocdr_min..(zip_eocdr_min + header.comment_length)];

    // If we find an EOCDR_64 and EOCDL_64, we modify header.(offset, length):
    const length = zip_eocdr_min + header.comment_length;
    assert(header.length == length);
    try decodeEocdr64Upgrade(buffer, &header);
    if (header.zip64) {
        const length_64 = zip_eocdr_64_min + zip_eocdl_64;
        assert(header.length >= length + length_64);
    } else {
        assert(header.length == length);
    }

    if (header.cd_size < header.cd_records * zip_cdh_min)
        return error.EocdrSizeOverflow;
    if (header.cd_size > 0 and header.cd_records == 0)
        return error.EocdrSizeUnderflow;
    if (overflow(header.cd_offset, header.cd_size, header.offset))
        return error.CdEocdrOverflow;
    if (header.disk != 0 or header.cd_disk != 0)
        return error.MultipleDisks;
    if (header.cd_disk_records != header.cd_records)
        return error.EocdrRecords;
    // The EOCDR has no General Purpose Bit Flag with which to indicate UTF-8.
    // Therefore, the comment encoding must always be CP437:
    try verifyString(header.comment[0..header.comment_length], false);
    const suffix_offset = header.offset + header.length;
    if (suffix_offset < buffer.len) {
        if (zeroes(buffer[suffix_offset..]))
            return error.AppendedDataZeroed
        else
            return error.AppendedDataBufferBleed;
    }
    return header;
}

fn inflateRaw(ctx: *const Ctx, compressed: []const u8, uncompressed: []u8) errors!void {
    if (uncompressed.len == 0) return;
    var fbs = std.io.fixedBufferStream(compressed);
    var inflate = try deflate.decompressor(ctx.allocator, fbs.reader(), null);
    defer inflate.deinit();

    // TODO(stephen): Migrate across the rest of the zlib errors?
    inflate.reader().readNoEof(uncompressed) catch |err| switch (err) {
        error.CorruptInput => return error.InflateData,
        error.UnexpectedEndOfStream => return error.InflateStream,
        error.OutOfMemory => return error.InflateMemory,
        error.EndOfStream => return error.InflateUncompressedUnderflow,
        else => unreachable,
    };
}

fn locateEocdr(buffer: []const u8) errors!u64 {
    if (buffer.len < zip_eocdr_min) return error.TooSmall;
    var index = @as(i64, @bitCast(buffer.len)) - zip_eocdr_min;
    // The EOCDR can be at most EOCDR_MIN plus a variable length comment.
    // The variable length of the comment can be at most a 16-bit integer.
    // Assuming no garbage after the EOCDR, our maximum search distance is:
    var floor = @max(0, index - math.maxInt(u16));

    assert(!overflow(@as(u64, @bitCast(index)), Eocdr.signature.len, buffer.len));
    while (index >= floor) : (index -= 1) {
        if (mem.eql(u8, buffer[@as(u64, @bitCast(index))..][0..4], Eocdr.signature)) {
            assert(!overflow(@as(u64, @bitCast(index)), 4, buffer.len));
            return @as(u64, @bitCast(index));
        }
    }

    return error.EocdrNotFound;
}

fn locateFirstLfh(buffer: []const u8, eocdr: *const Eocdr) errors!u64 {
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
            error.PrependedDataZeroed
        else
            error.PrependedDataBufferBleed;
    }

    // We could not find any end to the prepended data:
    return error.PrependedData;
}

// Compare LFH against DDR:
fn diffDdrLfh(ddr: *const Ddr, lfh: *const Lfh) errors!void {
    if (lfh.crc32 != 0 and lfh.crc32 != ddr.crc32)
        return error.DiffLfhDdrCrc32;
    if (lfh.compressed_size != 0 and
        lfh.compressed_size != ddr.compressed_size)
        return error.DiffLfhDdrCompressedSize;
    if (lfh.uncompressed_size != 0 and
        lfh.uncompressed_size != ddr.uncompressed_size)
        return error.DiffLfhDdrUncompressedSize;
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
) errors!void {
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
        return error.AdNihilo;
    }

    assert(cdh.compressed_size > 0);
    assert(cdh.compressed_size <= math.maxInt(usize));
    assert(cdh.uncompressed_size > 0);
    assert(cdh.uncompressed_size <= math.maxInt(usize));

    // We verify the compression ratio here, after first checking for LFH overlap:
    // We do this to return zipBombFifield before zipBombRatio.
    ctx.compressed_size = try math.add(u64, ctx.compressed_size, cdh.compressed_size);
    ctx.uncompressed_size = try math.add(u64, ctx.uncompressed_size, cdh.uncompressed_size);
    try verifyCompressionRatio(
        ctx.compressed_size,
        ctx.uncompressed_size,
    );
    var raw_wrapper: MaybeOwned = .{ .data = "" };
    defer raw_wrapper.deinit(ctx.allocator);
    if (cdh.compression_method == .deflate) {
        var data = try ctx.allocator.alloc(u8, cdh.uncompressed_size);
        errdefer ctx.allocator.free(data);
        try inflateRaw(
            ctx,
            buffer[cdh.relative_offset + lfh.length ..][0..cdh.compressed_size],
            data,
        );
        raw_wrapper = .{
            .data = data,
            .owned = true,
        };
    } else {
        assert(cdh.compression_method == .uncompressed);
        raw_wrapper = .{
            .data = buffer[cdh.relative_offset + lfh.length ..],
            .owned = false,
        };
    }
    var raw: []const u8 = raw_wrapper.data;
    assert(raw.len > 0);

    if (crc.hash(raw[0..cdh.uncompressed_size]) != cdh.crc32)
        return error.Crc32;

    // TODO(joran):
    //  Check for common ZIP extensions in addition to PK signature.
    if (mem.startsWith(u8, raw, "PK")) {
        try zipMeta(ctx, raw[0..cdh.uncompressed_size]);
    } else {
        ctx.files += 1;
        if (ctx.files > files_max) return error.BombFiles;
    }
}

fn zipMeta(ctx: *Ctx, buffer: []const u8) errors!void {
    // Update and check context against limits:
    ctx.depth += 1;
    if (ctx.depth > depth_max) return error.BombDepth;
    ctx.files += 1;
    if (ctx.files > files_max) return error.BombFiles;
    ctx.archives += 1;
    if (ctx.archives > archives_max) return error.BombArchives;
    ctx.size = try math.add(u64, ctx.size, buffer.len);
    if (ctx.size > size_max) return error.SizeMax;

    // A zip file must contain at least an end of central directory record:
    if (buffer.len < zip_eocdr_min) return error.TooSmall;
    // ZIP64:
    if (buffer.len > math.maxInt(u32) - 1) return error.Size4Gb;
    // Malicious archive signatures (almost certainly when masquerading as a ZIP):
    if (mem.startsWith(u8, buffer, "Rar!\x1a\x07")) return error.Rar;
    if (mem.startsWith(u8, buffer, "ustar")) return error.Tar;
    if (mem.startsWith(u8, buffer, "xar!")) return error.Xar;

    // Locate and decode end of central directory record:
    const offset = try locateEocdr(buffer);
    var eocdr = try decodeEocdr(buffer, offset);

    // Locate the offset of the first local file header:
    var lfh_offset = try locateFirstLfh(buffer, &eocdr);
    assert(lfh_offset == 0 or lfh_offset == span_signature.len);

    // Compare central directory headers with local file headers:
    var cdh: Cdh = undefined;
    var lfh: Lfh = undefined;
    var cdh_offset = eocdr.cd_offset;
    var cdh_record: u64 = 0;
    while (cdh_record < eocdr.cd_records) {
        // Central Directory Header:
        cdh = try decodeCdh(buffer, cdh_offset);

        if (lfh_offset > cdh.relative_offset) {
            if (cdh.directory and cdh.relative_offset == 0 and
                cdh.crc32 == 0 and cdh.compressed_size == 0 and cdh.uncompressed_size == 0)
                return error.DirectoryHasNoLfh;
            return error.BombFifield;
        }

        if (lfh_offset < cdh.relative_offset) {
            assert(cdh.relative_offset <= buffer.len);
            if (zeroes(buffer[lfh_offset..cdh.relative_offset]))
                return error.LfhUnderflowZeroed
            else
                return error.LfhUnderflowBufferBleed;
        }

        // Local File Header:
        assert(cdh.relative_offset == lfh_offset);
        lfh = try decodeLfh(buffer, cdh.relative_offset);
        try diffCdhAndLfh(cdh, lfh);
        try verifySymlink(cdh, lfh, buffer);
        assert(lfh.length >= zip_lfh_min);
        lfh_offset += lfh.length;

        // File Data (compressed or uncompressed):
        lfh_offset = try math.add(u64, lfh_offset, cdh.compressed_size);
        if (lfh_offset > buffer.len) return error.LfhDataOverflow;

        // Data Descriptor Record (optional):
        if (lfh.gp_bits.lfh_fields_zeroed) {
            const ddr = try decodeDdr(buffer, lfh_offset, lfh.zip64);
            try diffCdhAndDdr(cdh, ddr);
            try diffDdrLfh(&ddr, &lfh);
            lfh_offset += ddr.length;
        }
        if (lfh_offset > eocdr.cd_offset) return error.LfOverflow;

        // We descend into the data only after checking for LFH overlap above:
        // We can therefore descend only after decoding at least two entries.
        if (cdh_record > 0)
            try verifyData(ctx, buffer, &cdh, &lfh);

        assert(cdh.length >= zip_cdh_min);
        cdh_offset += cdh.length;
        cdh_record += 1;
    }

    // Descend into the previous CDH and LFH:
    if (cdh_record > 0)
        try verifyData(ctx, buffer, &cdh, &lfh);
    if (lfh_offset > eocdr.cd_offset) return error.LfOverflow;
    if (lfh_offset < eocdr.cd_offset) {
        assert(eocdr.cd_offset <= buffer.len);
        if (zeroes(buffer[lfh_offset..eocdr.cd_offset]))
            return error.LfUnderflowZeroed
        else
            return error.LfUnderflowBufferBleed;
    }

    const cdh_offset_expected = eocdr.cd_offset + eocdr.cd_size;
    if (cdh_offset > cdh_offset_expected) return error.CdOverflow;
    if (cdh_offset < cdh_offset_expected) {
        assert(cdh_offset_expected <= buffer.len);
        if (zeroes(buffer[cdh_offset..cdh_offset_expected]))
            return error.CdUnderflowZeroed
        else
            return error.CdUnderflowBufferBleed;
    }

    if (cdh_offset < eocdr.offset) {
        assert(eocdr.offset <= buffer.len);
        if (zeroes(buffer[cdh_offset..eocdr.offset]))
            return error.CdEocdrUnderflowZeroed
        else
            return error.CdEocdrUnderflowBufferBleed;
    }

    assert(cdh_offset == eocdr.offset);
    assert(cdh_offset + eocdr.length == buffer.len);
    assert(ctx.depth > 0);
    ctx.depth -= 1;
}

pub fn zip(buffer: []const u8, allocator: mem.Allocator) errors!void {
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
    var ctx = Ctx{ .allocator = allocator };
    return zipMeta(&ctx, buffer);
}
