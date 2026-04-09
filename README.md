# nx2elf
Convert Nintendo Switch executable files (NSO/NRO/MOD) to ELFs.

## Building

```
cmake -B build
cmake --build build
```

## Usage
```
nx2elf <file or directory> [--export-uncompressed <path>] [--export-elf <path>]
```

- `<file or directory>` — path to an NSO/NRO/MOD file, or a directory to batch-convert all files within it.
- `--export-elf <path>` — override the output ELF path (default: `<input>.elf`).
- `--export-uncompressed <path>` — export an uncompressed NSO variant.

## Features

- Supports compressed and uncompressed NSO files
- NRO and MOD (raw binary) input formats
- Reconstructs ELF sections: `.dynsym`, `.dynstr`, `.dynamic`, `.rela.dyn`, `.rela.plt`, `.plt`, `.got`, `.got.plt`, `.hash`, `.gnu.hash`, `.init`, `.fini`, `.init_array`, `.fini_array`, `.eh_frame_hdr`, `.eh_frame`, `.note`, `.bss`
- Non-overlapping section headers for clean loading in IDA and other tools
- Batch conversion of directories

## Known Issues
1. Does not handle 32-bit files.
