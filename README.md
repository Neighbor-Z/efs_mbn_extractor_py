# efs_mbn_extractor_py
A Python script that extracts the MCFG (Modem Configuration Binary) payload from an ELF-wrapped MBN file and writes contained NV items and files to disk.

This is a Python rewrite of the ExtractMbn functionality from the JohnBel/EfsTools project.

## Features

- Parses an MBN file and extracts the MCFG payload.
- Parses MCFG header, item headers and trailer.
- Extracts:
  - NV items → `NvItem__{nvId:08d}`
  - Files → saved with original filename (optionally with appended attributes)
- Default output directory is the directory containing the input MBN file, use `-p path` to customize output directory.
- A `--no-extra-data` flag to exclude extra attributes.

## Requirements

- pyelftools

Install dependency:

```bash
pip install pyelftools
```

## Usage

Make it executable if you like:

```bash
chmod +x efs_mbn_extractor.py
```

Basic usage:

```bash
python efs_mbn_extractor.py myfile.mbn
```

With the flag to avoid appending extra attributes to extracted file names:

```bash
python efs_mbn_extractor.py myfile.mbn --no-extra-data
```

Customize output directory:

```bash
python efs_mbn_extractor.py myfile.mbn -p /output/path/
```

Notes:

- By default, extracted items are placed into the directory named as `/mcfg_sw`.
- You may pass an absolute or relative path as the input file.

Example output after running on `mcfg_sw.mbn` located in `/home/user/mbns/`:

- `/home/user/mbns/mcfg_sw/NvItem__00001234`
- `/home/user/mbns/mcfg_sw/etc/configuration__81FF_0` (if `--no-extra-data` was not used)

## Errors and troubleshooting

- "Input file not found": check the path you passed.
- "Failed to parse ELF": file is not a valid ELF or pyelftools could not parse it.
- "Invalid MBN format. Can't find magic string": `MCFG` signature not found inside chosen ELF segment.
- "Invalid ... magic/size": the file does not match expected MBN/MCFG structure or it is corrupted/unsupported.
- If you suspect the MCFG payload is in a different segment than the 3rd one, the script currently uses the same behavior as the original (segment index 2). If needed, modify the script to search all segments for the `MCFG` signature.

## Note

Use at your own risk — no warranty.

## Acknowledgements

- Original implementation: JohnBel/[EfsTools](https://github.com/JohnBel/EfsTools) (C#)
- [pyelftools](https://github.com/eliben/pyelftools) for ELF parsing
