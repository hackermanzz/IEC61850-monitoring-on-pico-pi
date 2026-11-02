"""Check RP2040 UF2 blocks and compare every flash-load ELF byte, without flashing."""
import argparse
import hashlib
from pathlib import Path
import struct


def verify(elf: bytes, uf2: bytes) -> tuple[int, int]:
    if elf[:7] != b'\x7fELF\x01\x01\x01' or len(elf) < 52:
        raise ValueError('expected a little-endian ELF32 image')
    if struct.unpack_from('<H', elf, 18)[0] != 40:
        raise ValueError('expected an ARM ELF')
    if not uf2 or len(uf2) % 512:
        raise ValueError('UF2 must contain complete 512-byte blocks')
    total = len(uf2) // 512
    pages = {}
    for i in range(total):
        block = uf2[i * 512:(i + 1) * 512]
        magic0, magic1, flags, address, size, number, count, family = struct.unpack_from('<8I', block)
        if (magic0, magic1, struct.unpack_from('<I', block, 508)[0]) != (0x0a324655, 0x9e5d5157, 0x0ab16f30):
            raise ValueError(f'invalid UF2 magic at block {i}')
        if flags != 0x2000 or family != 0xe48bff56 or number != i or count != total or size != 256:
            raise ValueError(f'invalid RP2040 UF2 metadata at block {i}')
        if not 0x10000000 <= address < 0x10200000 or address % 256 or address in pages:
            raise ValueError(f'invalid/duplicate Pico flash destination at block {i}')
        pages[address] = block[32:32 + size]
    phoff = struct.unpack_from('<I', elf, 28)[0]
    entry_size, entries = struct.unpack_from('<HH', elf, 42)
    if entry_size < 32 or phoff + entries * entry_size > len(elf):
        raise ValueError('invalid ELF program header table')
    checked = 0
    for i in range(entries):
        kind, offset, virtual, physical, size, *_ = struct.unpack_from('<8I', elf, phoff + i * entry_size)
        if kind != 1 or not size:
            continue
        if offset + size > len(elf):
            raise ValueError('ELF segment exceeds file')
        if not 0x10000000 <= physical < 0x10200000:
            raise ValueError('non-flash ELF load segment requires a different validator')
        for j, expected in enumerate(elf[offset:offset + size]):
            at = physical + j
            page = pages.get(at & ~255)
            if page is None or page[at & 255] != expected:
                raise ValueError('UF2 payload differs from ELF flash-load bytes')
        checked += size
    if not checked:
        raise ValueError('ELF contains no flash-load bytes')
    return total, checked


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('uf2', type=Path, nargs='?')
    args = parser.parse_args()
    path = args.uf2 or args.elf.with_suffix('.uf2')
    try:
        raw = path.read_bytes()
        blocks, count = verify(args.elf.read_bytes(), raw)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'UF2 verification failed: {error}\n')
    print(f'PASS: {blocks} RP2040 blocks; {count} ELF flash-load bytes match.')
    print(f'UF2 SHA-256: {hashlib.sha256(raw).hexdigest()}')
