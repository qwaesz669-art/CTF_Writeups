
#!/usr/bin/env python3

import argparse
import binascii
import hashlib
import itertools
import lzma
import math
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import zipfile
import zlib


PROFILE_TAG_INDEX = {
    0x9D: 0, 0x38: 1, 0x31: 2, 0x84: 3, 0x49: 4,
    0xD2: 5, 0x6B: 6, 0xA9: 7, 0x22: 8, 0x3C: 9,
    0x35: 10, 0x90: 11, 0x3A: 12, 0xD4: 13, 0x6D: 14,
    0xD5: 15, 0xC1: 16, 0x46: 17, 0xC0: 18, 0xD3: 19,
}
EXPECTED_FIRMWARE_HASH = "d64430ce45979d6d9b3d6cb60bb81c9b813b5a6930f7bd32049025e727211c18"


def ensure(condition, message):
    if not condition:
        raise ValueError(message)


def calculate_crc16(data):
    return binascii.crc_hqx(data, 0xFFFF)


def file_sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare_image(input_path, temp_root):
    if not zipfile.is_zipfile(input_path):
        return input_path
    with zipfile.ZipFile(input_path) as archive:
        entries = [i for i in archive.infolist()
                   if not i.is_dir() and Path(i.filename).name == "gateway_snapshot.img"]
        ensure(len(entries) == 1, "Expected one gateway_snapshot.img in ZIP")
        target = temp_root / "gateway_snapshot.img"
        # Copy only the expected member to our own path; do not trust ZIP paths.
        with archive.open(entries[0]) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return target


def unpack_filesystem(snapshot, temp_root):
    ensure(shutil.which("debugfs"), "debugfs is required (e2fsprogs on Linux)")
    target = temp_root / "rootfs"
    target.mkdir()
    # Use a controlled relative output path in a private temporary directory.
    result = subprocess.run(
        ["debugfs", "-R", "rdump / rootfs", str(snapshot)],
        cwd=temp_root, text=True, capture_output=True, check=False,
    )
    ensure(result.returncode == 0, "debugfs failed: " + result.stderr)
    ensure((target / "var/cache/deltaforge/historian_cache.db").is_file(),
            "Historian database was not extracted")
    return target


def read_freelist(db):
    ensure(db.startswith(b"SQLite format 3\x00"), "Invalid SQLite header")
    size = int.from_bytes(db[16:18], "big")
    size = 65536 if size == 1 else size
    trunk = int.from_bytes(db[32:36], "big")
    expected = int.from_bytes(db[36:40], "big")
    pages, visited = [], set()
    while trunk:
        ensure(trunk not in visited, "Freelist trunk cycle")
        visited.add(trunk)
        off = (trunk - 1) * size
        ensure(0 <= off <= len(db) - size, "Freelist page outside database")
        nxt, count = struct.unpack_from(">II", db, off)
        ensure(count <= (size - 8) // 4, "Invalid freelist leaf count")
        pages.extend([trunk, *struct.unpack_from(f">{count}I", db, off + 8)])
        trunk = nxt
    ensure(len(pages) == expected, "Freelist count mismatch")
    return size, pages


def find_profiles(db):
    size, pages = read_freelist(db)
    unique, records = set(), []
    for page in pages:
        block = db[(page - 1) * size:page * size]
        off = 0
        while (off := block.find(b"R9CF", off)) >= 0:
            start = off
            off += 4
            payload_size = int.from_bytes(block[start + 5:start + 7], "little")
            raw = block[start:start + payload_size]
            if payload_size < 10 or len(raw) != payload_size or raw in unique:
                continue
            unique.add(raw)
            if raw[4] != 1 or calculate_crc16(raw[:-2]) != int.from_bytes(raw[-2:], "big"):
                continue
            fields, cursor = {}, 8
            while cursor + 2 <= len(raw) - 2:
                tag, count = raw[cursor:cursor + 2]
                end = cursor + 2 + count
                ensure(end <= len(raw) - 2, "Truncated profile TLV")
                ensure(tag in PROFILE_TAG_INDEX, f"Unknown profile tag {tag:02x}")
                slot = PROFILE_TAG_INDEX[tag]
                ensure(slot not in fields, "Duplicate profile field")
                fields[slot] = int.from_bytes(raw[cursor + 2:end], "little")
                cursor = end
            ensure(cursor == len(raw) - 2 and len(fields) == 20,
                    "Incomplete profile")
            records.append(fields)
    print(f"Freelist: {len(pages)} pages; {len(unique)} unique profile_rows; "
          f"{len(records)} pass CRC16")
    return records


def choose_profiles(records, case):
    groups = {}
    for p in records:
        if p[16] != zlib.crc32(case.encode()):
            continue
        lane, count = p[12] & 255, p[12] >> 8
        groups.setdefault((p[13], count), []).append(p)
    for (generation, count), group in sorted(groups.items(), reverse=True):
        if len(group) == count and sorted(p[12] & 255 for p in group) == list(range(count)):
            print(f"Selected case {case}, generation {generation}, {count} complete lanes")
            return sorted(group, key=lambda p: p[12] & 255)
    raise ValueError("No complete generation for this case")


def next_xorshift(state):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    return state


def build_codebook(p):
    table = list(itertools.permutations(range(p[2])))
    state = p[14] or 0x6D2B79F5
    for i in range(len(table) - 1, 0, -1):
        state = (next_xorshift(state) if p[15] == 1
                 else (1664525 * state + 1013904223) & 0xFFFFFFFF)
        j = state % (i + 1)
        table[i], table[j] = table[j], table[i]
    return table[:1 << p[3]]


def check_calibration(p, table, filesystem):
    lane = p[12] & 255
    raw = (filesystem / f"var/lib/deltaforge/lane_{lane}.cal").read_bytes()
    ensure(raw[:4] == b"C9TR", "Calibration magic mismatch")
    ensure(calculate_crc16(raw[:-2]) == int.from_bytes(raw[-2:], "big"), "Calibration CRC failure")
    ensure(raw[4:7] == bytes([lane, p[2], p[3]]), "Calibration parameters mismatch")
    count, cursor = raw[7], 8
    for _ in range(count):
        symbol = raw[cursor]
        pattern = tuple(raw[cursor + 1:cursor + 1 + p[2]])
        ensure(symbol < len(table) and table[symbol] == pattern, "Calibration table mismatch")
        cursor += 1 + p[2]
    ensure(cursor == len(raw) - 2, "Unexpected calibration payload_size")


def read_timing(deltas, p, lookup, phase):
    bits, previous = [], None
    width, symbol_bits = p[2], p[3]
    shifts = (range(symbol_bits - 1, -1, -1) if p[10] == 1 else range(symbol_bits))
    for off in range(phase, len(deltas) - width + 1, width):
        values = deltas[off:off + width]
        ranks = tuple(sum((other, j) < (value, i) for j, other in enumerate(values))
                      for i, value in enumerate(values))
        current = lookup.get(ranks)
        if current is None or previous is None:
            bits.extend([-1] * symbol_bits)
        else:
            symbol = ((current - previous) % len(lookup) if p[4] == 2
                      else current ^ previous)
            bits.extend((symbol >> shift) & 1 for shift in shifts)
        previous = current
    return bits


def make_mask(p, payload_size):
    lane = p[12] & 255
    state = p[11] ^ p[0] ^ (p[8] >> 8 if p[7] == 1 else p[8]) ^ lane
    state = ((state & 255) or 0xA7) if p[7] == 1 else (state or 0x6D2B79F5)
    result = []
    for _ in range(payload_size):
        if p[7] == 1:
            bit = state & 1
            state = ((state >> 1) ^ ((p[8] & 255) if bit else 0)) & 255
        else:
            state = next_xorshift(state)
            bit = state & 1
        result.append(bit)
    return result


def restore_order(bits, side, mode):
    ensure(len(bits) % (side * side) == 0, "Incomplete interleaver block")
    columns = list(range(side - 1, -1, -1) if mode == 2 else range(side))
    order = []
    for c, column in enumerate(columns):
        rows = range(side - 1, -1, -1) if mode == 3 and c % 2 else range(side)
        order.extend(row * side + column for row in rows)
    output = []
    for offset in range(0, len(bits), side * side):
        block = [0] * (side * side)
        for wire_index, original_index in enumerate(order):
            block[original_index] = bits[offset + wire_index]
        output.extend(block)
    return output


def make_hamming_word(nibble, size):
    a, b, c, d = ((nibble >> i) & 1 for i in (3, 2, 1, 0))
    word = [a ^ b ^ d, a ^ c ^ d, a, b ^ c ^ d, b, c, d]
    return word + [sum(word) & 1] if size == 8 else word


def decode_error_corrected(bits, size):
    words = [make_hamming_word(i, size) for i in range(16)]
    nibbles, errors = [], 0
    for offset in range(0, len(bits), size):
        chunk = bits[offset:offset + size]
        ensure(len(chunk) == size, "Incomplete Hamming word")
        distances = [sum(a != b for a, b in zip(chunk, word)) for word in words]
        distance = min(distances)
        ensure(distance <= 1 and distances.count(distance) == 1,
                "Uncorrectable/ambiguous Hamming word")
        nibbles.append(distances.index(distance))
        errors += distance
    # A short header probe can end on a single nibble. The final frame cannot.
    data = bytes((a << 4) | b for a, b in zip(nibbles[::2], nibbles[1::2]))
    return data, errors


def read_frame(bits, p):
    side = p[5]  # c8 -> 8x8; c7 -> 7x7. Do not reuse the stale 64-bit hint.
    probe_length = math.ceil(12 / side) * side * side
    ensure(len(bits) >= probe_length and -1 not in bits[:probe_length], "Invalid header bits")
    def recover(payload_size):
        mask = make_mask(p, payload_size)
        unmasked = [a ^ b for a, b in zip(bits[:payload_size], mask)]
        return decode_error_corrected(restore_order(unmasked, side, p[6]), side)
    header, _ = recover(probe_length)
    ensure(header[:2] == p[18].to_bytes(2, "little"), "Frame marker mismatch")
    ensure(header[2:4] == bytes([p[12] & 255, p[12] >> 8]), "Frame lane/count mismatch")
    payload_size = int.from_bytes(header[4:6], "big")
    frame_size = 6 + payload_size + 4
    alignment = math.lcm(side * side, p[3])
    wire_length = math.ceil(frame_size * 2 * side / alignment) * alignment
    ensure(len(bits) >= wire_length and -1 not in bits[:wire_length], "Missing frame symbols")
    frame, corrected = recover(wire_length)
    payload = frame[6:6 + payload_size]
    stored_crc = int.from_bytes(frame[6 + payload_size:frame_size], "big")
    ensure(zlib.crc32(payload) == stored_crc, "Payload CRC32 mismatch")
    ensure(all(value == 0 for value in frame[frame_size:]), "Unexpected frame padding")
    return payload, corrected, stored_crc, wire_length


def decode_channel(p, db, filesystem):
    ensure(p[2] == 4 and p[3] == 4 and p[4] in (1, 2), "Unexpected symbol configuration")
    ensure(p[17] == 2, "This case uses gateway arrival time (input_path selector 2)")
    assets = [row[0] for row in db.execute("SELECT DISTINCT asset_tag FROM samples")]
    assets = [a for a in assets if zlib.crc32(a.encode()) == p[0]]
    ensure(len(assets) == 1, "Ambiguous asset CRC32")
    asset = assets[0]
    table = build_codebook(p)
    check_calibration(p, table, filesystem)
    lookup = {pattern: symbol for symbol, pattern in enumerate(table)}
    rows = db.execute(
        "SELECT seq_no, gateway_time_ns FROM samples WHERE asset_tag=? ORDER BY seq_no", (asset,)
    ).fetchall()
    ensure(all(b[0] == a[0] + 1 for a, b in zip(rows, rows[1:])), "Missing sequence number")
    deltas = [b[1] - a[1] for a, b in zip(rows, rows[1:])]
    marker = "".join(f"{value:08b}" for value in p[9].to_bytes(8, "little"))
    matches = []
    for phase in range(p[2]):
        bits = read_timing(deltas, p, lookup, phase)
        text = "".join("?" if bit < 0 else str(bit) for bit in bits)
        offset = 0
        while (offset := text.find(marker, offset)) >= 0:
            start = offset + len(marker)
            try:
                result = read_frame(bits[start:], p)
            except ValueError:
                offset += 1
                continue
            matches.append((result, phase, offset, start))
            offset += 1
    ensure(len(matches) == 1, "Expected exactly one validated frame per lane")
    (payload, errors, crc, wire_length), phase, sync_bit, start = matches[0]
    delta_start = phase + (start // p[3]) * p[2]
    print(f"Lane {p[12] & 255}: {asset}; phase={phase}; sync_bit={sync_bit}; "
          f"payload deltas=[{delta_start},{delta_start + wire_length})")
    print(f"  calibration=valid; interleaver={p[5]}x{p[5]}; corrected_bits={errors}; "
          f"share_bytes={len(payload)}; CRC32={crc:08x} OK")
    return asset, payload


def run_solver(input_path):
    print(f"Evidence file hash: {file_sha256(input_path)}")
    with tempfile.TemporaryDirectory(prefix="temporal-paradox-") as temp:
        temp_root = Path(temp)
        snapshot = prepare_image(input_path, temp_root)
        print(f"Extracted image hash: {file_sha256(snapshot)}")
        filesystem = unpack_filesystem(snapshot, temp_root)
        ensure(file_sha256(filesystem / "usr/local/sbin/r9sampler") == EXPECTED_FIRMWARE_HASH,
                "Firmware build differs from the reverse-engineered TLV map")
        database_path = filesystem / "var/cache/deltaforge/historian_cache.db"
        with sqlite3.connect(database_path.as_uri() + "?mode=ro", uri=True) as db:
            info = dict(db.execute("SELECT key,value FROM system_info"))
            profile_rows = choose_profiles(find_profiles(database_path.read_bytes()), info["export_case"])
            ensure(len(profile_rows) == 2, "Expected this challenge's two-share XOR scheme")
            shares = [decode_channel(p, db, filesystem) for p in profile_rows]
        a, b = (item[1] for item in shares)
        ensure(len(a) == len(b), "Share payload_size mismatch")
        combined = bytes(x ^ y for x, y in zip(a, b))
        # Observed wrapper: 4 opaque bytes, codec byte, big-endian 16-bit size.
        # The trailing 20 bytes are retained but are not treated as a verified MAC.
        ensure(combined[4] == 3, "Expected observed XZ codec selector")
        payload_size = int.from_bytes(combined[5:7], "big")
        xz_data = combined[7:7 + payload_size]
        ensure(len(xz_data) == payload_size and xz_data.startswith(b"\xfd7zXZ\x00"),
                "Invalid XZ extent")
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        message = decoder.decompress(xz_data)
        ensure(decoder.eof and not decoder.unused_data and decoder.check == lzma.CHECK_CRC64,
                "XZ integrity/extent validation failed")
        ensure(("CASE=" + info["export_case"] + "\n").encode() in message, "Recovered case mismatch")
        ensure(("LANES=" + ",".join(item[0] for item in shares) + "\n").encode() in message,
                "Recovered asset identities mismatch")
        found_flags = re.findall(rb"^FLAG=(HTF\{[A-Za-z0-9_]+\})$", message, re.MULTILINE)
        ensure(len(found_flags) == 1, "Expected one flag in validated message")
        print(f"Combined combined: {len(combined)} bytes; XZ: {payload_size} bytes; "
              f"message: {len(message)} bytes; XZ CRC64 OK")
        print(f"Decoded message length: {len(message)} bytes")
        print("Decoded message:")
        print(message.decode(), end="")
        print(f"\nFlag confirmed: {found_flags[0].decode()}")
        print(f"Message SHA256: {hashlib.sha256(message).hexdigest()}")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    cli.add_argument("evidence", type=Path, help="Original ZIP or extracted ext4 snapshot")
    options = cli.parse_args()
    try:
        run_solver(options.evidence.resolve(strict=True))
    except (ValueError, OSError, sqlite3.Error, lzma.LZMAError, zipfile.BadZipFile) as problem:
        cli.exit(1, f"Validation failed: {problem}\n")
