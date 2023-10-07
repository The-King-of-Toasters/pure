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

While the code is a bit of a mess, each change is checked against the original C
implementation under `c-impl` to make sure there are no regressions. Right now,
you can execute `zig build` and run `zig-out/bin/pure` on any zip files to see
if they trigger any errors.

Currently, `pure` is tested against the `libzip` regression test suite. You can
run check for yourself by [cloning `libzip` from
source](https://github.com/nih-at/libzip) and running:

```sh
zig-out/bin/pure path/to/libzip/regress/*.zip
```

## TODOs

- Nested zip files are recursively analysed to detect zip bombs, and the code
  will allocate memory for if they are compressed. The original code would clean
  up this memory and did not leak, but my rewrite did. I'm working around this
  by using an arena allocator.
- The original code would read the Zip structures by manually reading
  little-endian integers and incrementing an offset into the file. I was
  part-way through a refactor that would read packed structs, so that I could
  eventually use a `SeekableStream`.
- There is no API for providing a Zip source and iterating over it. Only that
  which is necessary for the `pure` tool is preserved.
- The large error-set should be refactored to use return some (optional?) error
  context with the error type and the offset where it was encountered.
- Anything else marked `TODO` in the code.
