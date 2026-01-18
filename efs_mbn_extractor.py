#!/usr/bin/env python3
"""
MBN extractor

Usage:
  python efs_mbn_extractor.py input.mbn [-p outdir] [--no-extra-data]

Dependencies:
  pip install pyelftools
"""
from __future__ import annotations
import os
import io
import sys
import struct
import argparse
import logging
from enum import IntEnum
from typing import BinaryIO, Optional

from elftools.elf.elffile import ELFFile


class MbnExtractorException(Exception):
    pass


class ItemType(IntEnum):
    Nv = 1
    NvFile = 2
    File = 4


class McfgHeader:
    def __init__(self, magic: str, format_type: int, configuration_type: int,
                 items_count: int, carrier_index: int, reserved: int, version: int):
        self.magic = magic
        self.format_type = format_type
        self.configuration_type = configuration_type
        self.items_count = items_count
        self.carrier_index = carrier_index
        self.reserved = reserved
        self.version = version


class ItemHeader:
    def __init__(self, length: int, item_type: int, attributes: int, reserved: int):
        self.length = length
        self.type = item_type
        self.attributes = attributes
        self.reserved = reserved


class MbnExtractor:
    MAGIC = b"MCFG"
    TRAILER_MAGIC = b"MCFG_TRL"

    @staticmethod
    def extract(input_mbn_file_path: str, output_directory: str, no_extra_data: bool,
                logger: Optional[logging.Logger] = None) -> None:
        logger = logger or logging.getLogger("MbnExtractor")
        logger.info("Extracting MBN: %s", input_mbn_file_path)

        # load ELF
        with open(input_mbn_file_path, "rb") as f:
            try:
                elf = ELFFile(f)
            except Exception as e:
                raise MbnExtractorException(f"Failed to parse ELF: {e}")

            segments = list(elf.iter_segments())
            if len(segments) < 3:
                raise MbnExtractorException("Invalid MBN format: ELF segment with data not exist")

            # keep original behavior: use the 3rd segment
            segment = segments[2]
            try:
                contents = segment.data()
            except Exception:
                # pyelftools provides .data() for segments; fall back to reading via offsets
                data_offset = segment['p_offset']
                data_size = segment['p_filesz']
                f.seek(data_offset)
                contents = f.read(data_size)

            stream = io.BytesIO(contents)
            MbnExtractor._parse_image(stream, output_directory, no_extra_data, logger)

    @staticmethod
    def _read_exact(stream: BinaryIO, size: int) -> bytes:
        data = stream.read(size)
        if len(data) != size:
            raise MbnExtractorException("Unexpected EOF while reading MBN")
        return data

    @staticmethod
    def _find_magic_and_seek(stream: BinaryIO, magic: bytes) -> None:
        """
        Find magic bytes inside stream and position stream at the start of magic.
        Raises on not found.
        """
        # read once and search (stream small enough in memory in typical usage)
        data = stream.read()
        idx = data.find(magic)
        if idx == -1:
            raise MbnExtractorException("Invalid MBN format. Can't find magic string")
        stream.seek(idx)

    @staticmethod
    def _read_mcfg_header(stream: BinaryIO) -> McfgHeader:
        # locate "MCFG"
        MbnExtractor._find_magic_and_seek(stream, MbnExtractor.MAGIC)
        magic_bytes = MbnExtractor._read_exact(stream, len(MbnExtractor.MAGIC))
        # After magic, read fields in little-endian as in original C# BitConverter
        format_type = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        configuration_type = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        items_count = struct.unpack("<I", MbnExtractor._read_exact(stream, 4))[0]
        carrier_index = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        reserved = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        version_id = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if version_id != 4995:
            raise MbnExtractorException("Invalid MBN header version id")
        version_size = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if version_size != 4:
            raise MbnExtractorException("Invalid MBN header version size")
        version = struct.unpack("<I", MbnExtractor._read_exact(stream, 4))[0]

        return McfgHeader(magic_bytes.decode("ascii", errors="ignore"),
                          format_type, configuration_type, items_count,
                          carrier_index, reserved, version)

    @staticmethod
    def _read_item_header(stream: BinaryIO) -> ItemHeader:
        # uint32 length, byte type, byte attributes, ushort reserved
        data = MbnExtractor._read_exact(stream, 8)
        length, type_byte, attributes, reserved = struct.unpack("<I B B H", data)
        return ItemHeader(length, type_byte, attributes, reserved)

    @staticmethod
    def _parse_image(stream: BinaryIO, output_directory: str, no_extra_data: bool,
                     logger: logging.Logger) -> None:
        mcfg_header = MbnExtractor._read_mcfg_header(stream)
        # original loop: iterate items_count - 1 times
        if mcfg_header.items_count == 0:
            raise MbnExtractorException("Invalid MBN header: zero items count")
        total_items_to_read = max(0, mcfg_header.items_count - 1)
        for _ in range(total_items_to_read):
            item_header = MbnExtractor._read_item_header(stream)
            item_type = item_header.type
            if item_type == ItemType.Nv:
                MbnExtractor._parse_nv(stream, item_header, output_directory, logger)
            elif item_type == ItemType.NvFile:
                MbnExtractor._parse_file(stream, item_header, is_nv_file=True,
                                        no_extra_data=no_extra_data, output_directory=output_directory, logger=logger)
            elif item_type == ItemType.File:
                MbnExtractor._parse_file(stream, item_header, is_nv_file=False,
                                        no_extra_data=no_extra_data, output_directory=output_directory, logger=logger)
            else:
                raise MbnExtractorException("Invalid MBN: unknown item type")

        MbnExtractor._read_trailer(stream)

    @staticmethod
    def _read_trailer(stream: BinaryIO) -> None:
        _ = MbnExtractor._read_exact(stream, 4)  # recordLength (unused)
        trailer_magic = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if trailer_magic != 10:
            raise MbnExtractorException("Invalid trailer magic 1")
        _ = MbnExtractor._read_exact(stream, 2)  # reserved
        trailer_magic2 = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if trailer_magic2 != 0xA1:
            raise MbnExtractorException("Invalid trailer magic 2")
        data_length = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if data_length < 8:
            raise MbnExtractorException("Invalid trailer size")
        payload = MbnExtractor._read_exact(stream, data_length - 8)
        if payload.decode("ascii", errors="ignore") != MbnExtractor.TRAILER_MAGIC.decode("ascii"):
            raise MbnExtractorException("Invalid trailer magic value")

    @staticmethod
    def _parse_file(stream: BinaryIO, item_header: ItemHeader, is_nv_file: bool,
                    no_extra_data: bool, output_directory: str, logger: logging.Logger) -> None:
        pos = stream.tell()
        file_header_magic = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if file_header_magic != 1:
            raise MbnExtractorException("Invalid file header magic")
        file_name_length = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        raw_name = MbnExtractor._read_exact(stream, file_name_length)
        file_name = raw_name[:max(0, file_name_length - 1)].decode("ascii", errors="ignore") if file_name_length > 0 else ""
        file_size_magic = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        if file_size_magic != 2:
            raise MbnExtractorException("Invalid file size magic")
        data_length = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0] - 1
        _ = MbnExtractor._read_exact(stream, 1)  # dataMagic (unused)
        data = MbnExtractor._read_exact(stream, data_length)
        real_length = (stream.tell() - pos) + 8
        if real_length != item_header.length:
            raise MbnExtractorException("Invalid file item size")
        logger.info("%s", f"  ItemFile:{file_name}" if is_nv_file else f"  File:{file_name}")
        if no_extra_data:
            save_name = file_name
        else:
            save_name = f"{file_name}__E1FF_F" if is_nv_file else f"{file_name}__81FF_0"
        MbnExtractor._save_to_file(save_name, data, output_directory)

    @staticmethod
    def _parse_nv(stream: BinaryIO, item_header: ItemHeader, output_directory: str, logger: logging.Logger) -> None:
        pos = stream.tell()
        nv_id = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0]
        data_length = struct.unpack("<H", MbnExtractor._read_exact(stream, 2))[0] - 1
        _ = MbnExtractor._read_exact(stream, 1)  # dataMagic
        data = MbnExtractor._read_exact(stream, data_length)
        real_length = (stream.tell() - pos) + 8
        if real_length != item_header.length:
            raise MbnExtractorException("Invalid NV item size")
        logger.info("  Nv:%05d", nv_id)
        file_name = f"NvItem__{nv_id:08d}"
        MbnExtractor._save_to_file(file_name, data, output_directory)

    @staticmethod
    def _save_to_file(file_name: str, content: bytes, output_directory: str) -> None:
        # normalize slashes in file_name and join with output_directory
        file_path = file_name.replace("/", os.sep).lstrip(os.sep)
        path = os.path.join(output_directory, file_path)
        dir_name = os.path.dirname(path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
            f.flush()


def main():
    parser = argparse.ArgumentParser(description="Extract MBN (MCFG) from ELF-wrapped MBN file")
    parser.add_argument("input", help="Input MBN file path (positional)")
    parser.add_argument("-p", "--path", dest="output", help="Output directory path")
    parser.add_argument("--no-extra-data", dest="no_extra", action="store_true",
                        help="Don't save extra data in file name")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger = logging.getLogger("MbnExtractor")

    input_path = os.path.abspath(args.input)
    if not os.path.isfile(input_path):
        logger.error("Input file not found: %s", input_path)
        sys.exit(2)

    # default outdir is the directory containing the input file
    if args.output is None:
        outdir = os.path.dirname(input_path)+"/mcfg_sw" or os.getcwd()+"/mcfg_sw"
    else:
        outdir = args.output
    os.makedirs(outdir, exist_ok=True)

    try:
        MbnExtractor.extract(input_path, outdir, no_extra, logger=logger)
        logger.info("Extraction finished.")
    except MbnExtractorException as me:
        logger.error("Extraction failed: %s", me)
        sys.exit(2)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
