#!/usr/bin/env python3
"""
DOS LE (Linear Executable) Fixup/Relocation Applier
===================================================

Applies LE fixup/relocation records to produce a flat binary where all
code-to-data references are resolved. The output can be loaded directly
into Ghidra as a Raw Binary with fully accurate decompilation.

Background:
    DOS LE executables (often used with 32-bit DOS extenders like DOS/4GW or Watcom C/C++)
    store code and data in separate objects, applying relocations at load time.
    Ghidra's default loader struggles to fully process these LE fixups, 
    resulting in broken data references (e.g., global variables or strings 
    showing up as 0x0) during decompilation.

    This script solves the problem by:
    1. Parsing the LE header, object table, and fixup tables.
    2. Loading all object pages into a single flat memory image.
    3. Applying all fixup records (32-bit offsets, selectors, etc.).
    4. Writing the patched memory image as a flat binary.

    By loading this flat binary into Ghidra, you can significantly increase 
    the number of recognized functions and perfectly resolve data cross-references.
    (Very useful for reverse engineering, modding, or analyzing classic DOS games/apps).

Usage:
    python le_fixup_apply.py <input.exe> <output.bin>

Ghidra Import Instructions:
    1. File > Import File > <output.bin>
    2. Format: Raw Binary
    3. Language: x86:LE:32:default (or x86:LE:32:System Management Mode)
    4. Options > Base Address: (Set to the memory image start address printed by this script)
    5. Analyze > Auto Analyze
"""

import struct
import sys
import os

def parse_le_header(f, le_offset):
    """Parse LE header and return dict of key fields."""
    f.seek(le_offset)
    hdr = f.read(0xC4)

    sig = hdr[0:2]
    if sig != b'LE':
        raise ValueError(f"Not an LE executable (signature: {sig})")

    return {
        'le_offset': le_offset,
        'cpu_type': struct.unpack('<H', hdr[0x08:0x0A])[0],
        'target_os': struct.unpack('<H', hdr[0x0A:0x0C])[0],
        'module_flags': struct.unpack('<I', hdr[0x10:0x14])[0],
        'num_pages': struct.unpack('<I', hdr[0x14:0x18])[0],
        'eip_object': struct.unpack('<I', hdr[0x18:0x1C])[0],
        'eip': struct.unpack('<I', hdr[0x1C:0x20])[0],
        'esp_object': struct.unpack('<I', hdr[0x20:0x24])[0],
        'esp': struct.unpack('<I', hdr[0x24:0x28])[0],
        'page_size': struct.unpack('<I', hdr[0x28:0x2C])[0],
        'last_page_size': struct.unpack('<I', hdr[0x2C:0x30])[0],
        'fixup_section_size': struct.unpack('<I', hdr[0x30:0x34])[0],
        'obj_table_ofs': struct.unpack('<I', hdr[0x40:0x44])[0],
        'num_objects': struct.unpack('<I', hdr[0x44:0x48])[0],
        'obj_page_map_ofs': struct.unpack('<I', hdr[0x48:0x4C])[0],
        'fixup_page_table_ofs': struct.unpack('<I', hdr[0x68:0x6C])[0],
        'fixup_record_table_ofs': struct.unpack('<I', hdr[0x6C:0x70])[0],
        'import_mod_table_ofs': struct.unpack('<I', hdr[0x70:0x74])[0],
        'data_pages_ofs': struct.unpack('<I', hdr[0x80:0x84])[0],
    }


def parse_object_table(f, le_hdr):
    """Parse LE object table entries."""
    f.seek(le_hdr['le_offset'] + le_hdr['obj_table_ofs'])
    objects = []
    for i in range(le_hdr['num_objects']):
        entry = f.read(24)
        objects.append({
            'index': i + 1,
            'virt_size': struct.unpack('<I', entry[0:4])[0],
            'base': struct.unpack('<I', entry[4:8])[0],
            'flags': struct.unpack('<I', entry[8:12])[0],
            'page_idx': struct.unpack('<I', entry[12:16])[0],
            'num_pages': struct.unpack('<I', entry[16:20])[0],
        })
    return objects


def load_pages(f, le_hdr, objects):
    """Load all object pages into a flat memory image."""
    mem_start = min(o['base'] for o in objects)
    mem_end = max(o['base'] + o['virt_size'] for o in objects)
    mem_size = mem_end - mem_start
    mem = bytearray(mem_size)

    page_size = le_hdr['page_size']
    num_pages = le_hdr['num_pages']
    last_page_size = le_hdr['last_page_size']
    data_pages_ofs = le_hdr['data_pages_ofs']

    for obj in objects:
        for pg in range(obj['num_pages']):
            abs_pg = obj['page_idx'] - 1 + pg  # 0-based
            file_ofs = data_pages_ofs + abs_pg * page_size
            f.seek(file_ofs)

            if abs_pg == num_pages - 1:
                data = f.read(last_page_size)
            else:
                data = f.read(page_size)

            dest = obj['base'] - mem_start + pg * page_size
            mem[dest:dest + len(data)] = data

    return mem, mem_start


def apply_fixups(f, le_hdr, objects, mem, mem_start):
    """Parse and apply all fixup records to the memory image."""
    le_offset = le_hdr['le_offset']
    num_pages = le_hdr['num_pages']
    page_size = le_hdr['page_size']

    fixup_page_abs = le_offset + le_hdr['fixup_page_table_ofs']
    fixup_rec_abs = le_offset + le_hdr['fixup_record_table_ofs']

    f.seek(fixup_page_abs)
    page_offsets = [struct.unpack('<I', f.read(4))[0] for _ in range(num_pages + 1)]

    stats = {'applied': 0, 'errors': 0, 'by_src_type': {}, 'by_tgt_type': {}}

    for pg in range(num_pages):
        start = page_offsets[pg]
        end = page_offsets[pg + 1]
        if start == end:
            continue

        pg_num = pg + 1  # 1-based
        page_obj = None
        for obj in objects:
            if obj['page_idx'] <= pg_num < obj['page_idx'] + obj['num_pages']:
                page_obj = obj
                break
        if page_obj is None:
            continue

        page_vaddr = page_obj['base'] + (pg_num - page_obj['page_idx']) * page_size

        f.seek(fixup_rec_abs + start)
        data = f.read(end - start)
        pos = 0

        while pos < len(data):
            src_type = data[pos]
            target_flags = data[pos + 1]
            pos += 2

            src_kind = src_type & 0x0F
            has_src_list = bool(src_type & 0x20)
            tgt_kind = target_flags & 0x03
            has_additive = bool(target_flags & 0x04)
            tgt_ofs_32 = bool(target_flags & 0x10)
            add_32 = bool(target_flags & 0x20)
            obj_16 = bool(target_flags & 0x40)
            ord_8 = bool(target_flags & 0x80)

            if has_src_list:
                src_count = data[pos]
                pos += 1
            else:
                src_offset = struct.unpack('<H', data[pos:pos + 2])[0]
                pos += 2
                src_count = 1

            tgt_obj_num = None
            tgt_offset = 0

            if tgt_kind == 0x00:  # Internal reference
                if obj_16:
                    tgt_obj_num = struct.unpack('<H', data[pos:pos + 2])[0]
                    pos += 2
                else:
                    tgt_obj_num = data[pos]
                    pos += 1
                if src_kind != 0x02:  # Not selector-only
                    if tgt_ofs_32:
                        tgt_offset = struct.unpack('<I', data[pos:pos + 4])[0]
                        pos += 4
                    else:
                        tgt_offset = struct.unpack('<H', data[pos:pos + 2])[0]
                        pos += 2

            elif tgt_kind == 0x01:  # Import by ordinal
                if obj_16:
                    pos += 2
                else:
                    pos += 1
                if ord_8:
                    pos += 1
                elif tgt_ofs_32:
                    pos += 4
                else:
                    pos += 2

            elif tgt_kind == 0x02:  # Import by name
                if obj_16:
                    pos += 2
                else:
                    pos += 1
                if tgt_ofs_32:
                    pos += 4
                else:
                    pos += 2

            elif tgt_kind == 0x03:  # Entry table
                if obj_16:
                    pos += 2
                else:
                    pos += 1
                if tgt_ofs_32:
                    pos += 4
                else:
                    pos += 2

            additive = 0
            if has_additive:
                if add_32:
                    additive = struct.unpack('<I', data[pos:pos + 4])[0]
                    pos += 4
                else:
                    additive = struct.unpack('<H', data[pos:pos + 2])[0]
                    pos += 2

            if has_src_list:
                src_offsets = [struct.unpack('<H', data[pos + j * 2:pos + j * 2 + 2])[0]
                               for j in range(src_count)]
                pos += src_count * 2
            else:
                src_offsets = [src_offset]

            src_name = f'src=0x{src_kind:02X}'
            tgt_name = f'tgt=0x{tgt_kind:02X}'
            stats['by_src_type'][src_name] = stats['by_src_type'].get(src_name, 0) + src_count
            stats['by_tgt_type'][tgt_name] = stats['by_tgt_type'].get(tgt_name, 0) + src_count

            if tgt_kind == 0x00 and tgt_obj_num is not None and 1 <= tgt_obj_num <= len(objects):
                tgt_obj = objects[tgt_obj_num - 1]
                target_addr = tgt_obj['base'] + tgt_offset + additive

                for soff in src_offsets:
                    fixup_vaddr = page_vaddr + soff
                    mem_offset = fixup_vaddr - mem_start

                    if 0 <= mem_offset < len(mem) - 3:
                        if src_kind == 0x07:  # 32-bit offset
                            struct.pack_into('<I', mem, mem_offset, target_addr)
                            stats['applied'] += 1
                        elif src_kind == 0x05:  # 16-bit offset
                            struct.pack_into('<H', mem, mem_offset, target_addr & 0xFFFF)
                            stats['applied'] += 1
                        elif src_kind == 0x02:  # 16-bit selector
                            stats['applied'] += 1
                        elif src_kind == 0x08:  # 32-bit self-relative
                            rel = target_addr - (fixup_vaddr + 4)
                            struct.pack_into('<i', mem, mem_offset, rel)
                            stats['applied'] += 1
                        elif src_kind == 0x00:  # byte fixup
                            mem[mem_offset] = target_addr & 0xFF
                            stats['applied'] += 1
                        elif src_kind == 0x03:  # 16:16 pointer
                            struct.pack_into('<H', mem, mem_offset, target_addr & 0xFFFF)
                            stats['applied'] += 1
                        elif src_kind == 0x06:  # 16:32 pointer
                            struct.pack_into('<I', mem, mem_offset, target_addr)
                            stats['applied'] += 1
                        else:
                            stats['errors'] += 1
                    else:
                        stats['errors'] += 1
            else:
                stats['errors'] += src_count

    return stats


def find_le_offset(f):
    """Find LE header offset from MZ stub."""
    f.seek(0)
    mz_sig = f.read(2)
    if mz_sig != b'MZ':
        raise ValueError("Not an MZ executable")

    f.seek(0x3C)
    le_offset = struct.unpack('<I', f.read(4))[0]

    f.seek(le_offset)
    sig = f.read(2)
    if sig != b'LE':
        raise ValueError(f"Expected LE signature at 0x{le_offset:X}, got {sig}")

    return le_offset


def main():
    if len(sys.argv) != 3:
        print("Usage: python le_fixup_apply.py <input.exe> <output.bin>")
        print("Example: python le_fixup_apply.py GAME.EXE GAME_relocated.bin")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f"[*] Input:  {input_path}")
    print(f"[*] Output: {output_path}")

    try:
        with open(input_path, 'rb') as f:
            le_offset = find_le_offset(f)
            print(f"[*] LE header at file offset 0x{le_offset:X}")

            le_hdr = parse_le_header(f, le_offset)
            print(f"[*] Pages: {le_hdr['num_pages']} x {le_hdr['page_size']} bytes")
            print(f"[*] Objects: {le_hdr['num_objects']}")
            print(f"[*] Fixup section: {le_hdr['fixup_section_size']} bytes")

            objects = parse_object_table(f, le_hdr)
            for obj in objects:
                flags = obj['flags']
                attrs = []
                if flags & 0x01: attrs.append('R')
                if flags & 0x02: attrs.append('W')
                if flags & 0x04: attrs.append('X')
                if flags & 0x2000: attrs.append('BIG')
                print(f"    Object {obj['index']}: base=0x{obj['base']:08X} "
                      f"size=0x{obj['virt_size']:X} [{'/'.join(attrs)}] "
                      f"pages={obj['num_pages']}")

            eip_base = objects[le_hdr['eip_object'] - 1]['base']
            entry = eip_base + le_hdr['eip']
            print(f"\n[*] Entry point: 0x{entry:X} (object {le_hdr['eip_object']} + 0x{le_hdr['eip']:X})")

            print("\n[*] Loading pages...")
            mem, mem_start = load_pages(f, le_hdr, objects)
            print(f"[*] Memory image: 0x{mem_start:X} - 0x{mem_start + len(mem):X} ({len(mem)} bytes)")

            print("\n[*] Applying fixups...")
            stats = apply_fixups(f, le_hdr, objects, mem, mem_start)
            print(f"    Applied: {stats['applied']}")
            print(f"    Errors:  {stats['errors']}")
            print(f"    By source type: {stats['by_src_type']}")
            print(f"    By target type: {stats['by_tgt_type']}")

        # Ensure output directory exists if provided in path
        output_dir = os.path.dirname(os.path.abspath(output_path))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        with open(output_path, 'wb') as out:
            out.write(mem)
        print(f"\n[+] Saved: {output_path} ({len(mem)} bytes)")

        print(f"\n=== Ghidra Import Instructions ===")
        print(f"1. File > Import File > {os.path.basename(output_path)}")
        print(f"2. Format: Raw Binary")
        print(f"3. Language: x86:LE:32:default (or x86:LE:32:System Management Mode)")
        print(f"4. Options > Base Address: 0x{mem_start:X}")
        print(f"5. After import, mark memory regions (Window > Memory Map):")
        for obj in objects:
            name = '.code' if obj['flags'] & 0x04 else '.data'
            offset_in_bin = obj['base'] - mem_start
            print(f"   {name}: 0x{obj['base']:X} size=0x{obj['virt_size']:X} "
                  f"(binary offset 0x{offset_in_bin:X})")
        print(f"6. Go to Entry point: 0x{entry:X} and press 'D' to disassemble.")
        print(f"7. Analyze > Auto Analyze (all defaults)")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()