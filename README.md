# krkrxp3

`krkrxp3` is a small Go command line tool for extracting and repacking KiriKiri
XP3 archives.

This project is based on the archived Python tool
[`awaken1ng/krkr-xp3`](https://github.com/awaken1ng/krkr-xp3). Thanks to the
Awakening author for the original implementation and for documenting the archive
layout clearly enough to make this Go port possible.

## What It Does

The tool reads XP3 archives, parses the archive index, and extracts each file to
disk. It can also walk a directory and build a new XP3 archive from the files it
finds.

Supported features:

- Extract XP3 archives.
- Repack directories into XP3 archives.
- Dump the raw archive index.
- Preserve folder structure or flatten files into the archive root.
- Optionally store file timestamps when repacking.
- Optionally omit UTF-16 path terminators for archives that use that index
  variant.
- Read and write the supported Awakening encryption modes:
  `none`, `neko_vol0`, `neko_vol0_steam`, `neko_vol1`, `neko_vol1_steam`.

## Install

Install with Go:

```bash
go install github.com/DarlingGoose/krkrxp3@latest
```

Or build from a local checkout:

```bash
git clone https://github.com/DarlingGoose/krkrxp3.git
cd krkrxp3
go build .
```

That creates a `krkrxp3` binary in the current directory.

## Usage

Extract an archive:

```bash
krkrxp3 -m extract data.xp3 data
```

Repack a directory:

```bash
krkrxp3 -m repack data data.xp3
```

Repack while flattening all files into the archive root:

```bash
krkrxp3 -m repack --flatten data data.xp3
```

Preserve file timestamps when repacking:

```bash
krkrxp3 -m repack --save-timestamps data data.xp3
```

Match archives that omit UTF-16 null terminators in index path chunks:

```bash
krkrxp3 -m repack --omit-path-terminators data data.xp3
```

Use an encryption mode:

```bash
krkrxp3 -m extract --encryption neko_vol0 data.xp3 data
krkrxp3 -m repack --encryption neko_vol0 data data.xp3
```

Dump the archive index:

```bash
krkrxp3 -m extract --dump-index data.xp3 data.index
```

## Configuration

The CLI uses Cobra and Viper. Flags can also be provided through environment
variables with the `KRKRXP3_` prefix:

```bash
KRKRXP3_MODE=repack krkrxp3 data data.xp3
KRKRXP3_ENCRYPTION=neko_vol0 krkrxp3 data.xp3 data
```

You can also pass a config file:

```bash
krkrxp3 --config .krkrxp3.yaml data.xp3 data
```

Example config:

```yaml
mode: extract
encryption: none
silent: false
flatten: false
dump-index: false
save-timestamps: false
omit-path-terminators: false
```

## Notes

XP3 archives have a few format variants in the wild. This port accepts the
common index layouts used by the original Python project and archives that omit
UTF-16 null terminators in file path chunks.
