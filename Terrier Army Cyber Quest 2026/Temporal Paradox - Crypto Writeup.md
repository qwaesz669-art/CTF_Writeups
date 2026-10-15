
| **Category**      |Crypto (with digital forensics and reverse engineering)|
| **Challenge**    |Temporal Paradox|
| **Flag format**|`HTF{}`|
| **Flag**                |`HTF{r9_9cfbf58fe2c300c42a442e2a073336f29e387a47}`|

## Challenge Description

At 03:26 UTC, an egress sensor recorded an encrypted transfer from the experimental DeltaForge R9 gateway serving Cold Rolling Line 9. Process values match the safety PLC, and an emergency disk snapshot was captured immediately afterward. The gateway was mid-rollout: live files, deleted state, diagnostic traces, and firmware may disagree. Treat the automated analyst cache as untrusted evidence. Determine what actually left the zone and submit the validated flag.

Challenge file: [Temporal Paradox.zip](https://ta-hackathon.s3.ap-south-1.amazonaws.com/ta-hackathon-files/Temporal+Paradox.zip)

## Summary

The attack vector combines **forensic recovery of deleted SQLite data** with **reverse engineering of the gateway's custom timing-channel encoding**.

1. Recover deleted channel profiles from the SQLite freelist.
2. Identify the correct firmware and profile generation.
3. Reconstruct two timing-based data channels (lanes) and validate their calibration.
4. Decode error-corrected frames and verify their CRCs.
5. XOR the two recovered shares and decompress the resulting XZ payload.

The flag is accepted only after the message passes integrity checks and contains the expected case and lane identities.

## Step-by-Step Approach

### 1. Initial triage

Unzip `Temporal Paradox.zip`, then run the usual file-inspection tools (`file`, `exiftool`, `binwalk`). They show the snapshot is a Linux rev 1.0 ext4 filesystem image.

![[Pasted image 20261015155521.png]]

![[Pasted image 20261015155527.png]]

![[Pasted image 20261015155534.png]]

Mount the image and explore it:
`rootfs/` contains:

|Path|Notes|
|---|---|
|`home/operator/`|`.gdb_history`, `triage_cache.txt`|
|`usr/local/sbin/r9sampler`|gateway sampler firmware|
|`var/cache/deltaforge/historian_cache.db`|SQLite historian database|
|`var/lib/deltaforge/`|`lane_0.cal`, `lane_1.cal`|
|`var/log/deltaforge/rollout.log`|rollout log|



### 2. The trap: `triage_cache.txt`

The first file that stands out is `triage_cache.txt`, sitting in the operator's home directory:

![[Pasted image 20261015155547.png]]

This is a clear decoy (a prompt-injection-style planted note). The challenge description already warned that the automated analyst cache is untrusted, so I ignored it and moved on. Note that it claims "only one lane", which the real data contradicts.

### 3. Inspecting the historian database

I opened `historian_cache.db` in read-only mode and listed its tables:

![[Pasted image 20261015155606.png]]

The relevant tables are `samples` and `system_info`:

```
sqlite> SELECT * FROM system_info;
╭───────────────┬────────────────────────────────────────────────────────────────╮
│      key      │                             value                              │
╞═══════════════╪════════════════════════════════════════════════════════════════╡
│ product       │ DeltaForge R9 experimental                                     │
│ export_case   │ TS-1138                                                        │
│ build_id      │ 6c52b90c2f26da3a6a55                                           │
│ clock_source  │ PTP with RX fallback                                           │
│ secure_delete │ OFF                                                            │
│ incident_note │ configuration rollout incomplete; recover effective lane state │
╰───────────────┴────────────────────────────────────────────────────────────────╯

sqlite> SELECT * FROM samples LIMIT 10;
╭────┬─────────────┬────────┬─────────────────────┬─────────────────────┬──────────────┬─────────╮
│ id │  asset_tag  │ seq_no │   device_time_ns    │   gateway_time_ns   │ sensor_value │ quality │
╞════╪═════════════╪════════╪═════════════════════╪═════════════════════╪══════════════╪═════════╡
│  1 │ CR9.THCK.B4 │   5354 │ 1788393202324853994 │ 1788393202464129515 │    2.3978401 │     192 │
│  2 │ CR9.THCK.B4 │   5347 │ 1788393195231222575 │ 1788393195370450029 │    2.3980789 │     192 │
│  3 │ CR9.THCK.B4 │   5344 │ 1788393192207557948 │ 1788393192335984945 │    2.3980791 │     192 │
│ …  │ …           │ …      │ …                   │ …                   │ …            │ …       │
╰────┴─────────────┴────────┴─────────────────────┴─────────────────────┴──────────────┴─────────╯
```

Key observations:

- `secure_delete = OFF`, so deleted rows may still be recoverable from unused pages.
- `incident_note` says the rollout was incomplete and the _effective_ lane state must be recovered.
- The `samples` table holds timing data (`device_time_ns`, `gateway_time_ns`), and the sensor values themselves are just cover traffic.

The live database alone does not contain the full picture.

### 4. Recovering deleted profiles from the SQLite freelist

The channel profile records are not in the live tables. They live in the **freelist**, the pages SQLite no longer considers part of the active database.

The solver validates the header, then walks the freelist trunk pages:

```python
ensure(db.startswith(b"SQLite format 3\x00"), "Invalid SQLite header")
size = int.from_bytes(db[16:18], "big")
trunk = int.from_bytes(db[32:36], "big")
expected = int.from_bytes(db[36:40], "big")
```

Each freelist page is scanned for the profile magic `R9CF`:

```python
while (off := block.find(b"R9CF", off)) >= 0:
```

Every candidate is validated by version byte and CRC16 before being parsed:

```python
if raw[4] != 1 or calculate_crc16(raw[:-2]) != int.from_bytes(raw[-2:], "big"):
    continue
```

Each profile is a TLV structure. I reverse engineered the tag-to-field mapping from the `r9sampler` firmware, and the solver pins the expected firmware hash so the mapping is only applied to the correct build.

### 5. Choosing the right profile generation

The gateway was mid-rollout, so the freelist holds profiles from **multiple generations**. Using the wrong one produces garbage.

Profiles are filtered by the case identifier (`TS-1138`):

```python
if p[16] != zlib.crc32(case.encode()):
    continue
```

Then grouped by `(generation, lane count)`:

```python
groups.setdefault((p[13], count), []).append(p)
```

Only a generation where every expected lane is present is accepted:

```python
if len(group) == count and sorted(p[12] & 255 for p in group) == list(range(count)):
```

Result:

```
Freelist: 12 pages; 11 unique profile_rows; 6 pass CRC16
Selected case TS-1138, generation 14108, 2 complete lanes
```

There are **two lanes**, which directly contradicts the decoy note.

### 6. Building the codebook and checking calibration

Each lane encodes symbols as the _ordering_ of inter-sample timing deltas. A codebook maps rank permutations to symbols:

```python
table = list(itertools.permutations(range(p[2])))
```

The permutations are shuffled using the profile's PRNG settings (xorshift or an LCG, depending on the profile):

```python
state = p[14] or 0x6D2B79F5
```

The on-disk calibration files (`lane_0.cal`, `lane_1.cal`) are then checked against the reconstructed codebook:

```python
ensure(raw[4:7] == bytes([lane, p[2], p[3]]), "Calibration parameters mismatch")
ensure(symbol < len(table) and table[symbol] == pattern, "Calibration table mismatch")
```

This confirms the decoder uses the right symbol ordering and parameters.

### 7. Decoding the timing channel

The data is carried in _timing differences_ between consecutive gateway timestamps, not in the sensor values:

```python
deltas = [b[1] - a[1] for a, b in zip(rows, rows[1:])]
```

Each group of deltas becomes a rank pattern:

```python
ranks = tuple(sum((other, j) < (value, i) for j, other in enumerate(values))
              for i, value in enumerate(values))
current = lookup.get(ranks)
```

Consecutive symbols are differenced (modular difference or XOR, depending on the profile) and turned into bits:

```python
symbol = ((current - previous) % len(lookup) if p[4] == 2 else current ^ previous)
```

The stream may not start on a symbol boundary, so every phase is tried, and a synchronization marker is searched for:

```python
for phase in range(p[2]):
    ...
marker = "".join(f"{value:08b}" for value in p[9].to_bytes(8, "little"))
```

### 8. Frame parsing and error correction

After the sync marker comes a structured frame. The header carries a frame marker, the lane/count, and the payload size:

```python
ensure(header[:2] == p[18].to_bytes(2, "little"), "Frame marker mismatch")
ensure(header[2:4] == bytes([p[12] & 255, p[12] >> 8]), "Frame lane/count mismatch")
payload_size = int.from_bytes(header[4:6], "big")
frame_size = 6 + payload_size + 4
```

Before the header can be read, the bits go through three layers:

1. **Whitening mask**: an LFSR or xorshift keystream XORed over the bits.
2. **Interleaver**: a per-lane block interleaver (8x8 on lane 0, 7x7 on lane 1) with a column/row order depending on the profile.
3. **Hamming code**: each nibble is encoded as a 7-bit or 8-bit word.

The Hamming decoder picks the nearest valid codeword and rejects ambiguous or uncorrectable words:

```python
distances = [sum(a != b for a, b in zip(chunk, word)) for word in words]
ensure(distance <= 1 and distances.count(distance) == 1,
       "Uncorrectable/ambiguous Hamming word")
```

Finally the payload CRC32 is verified:

```python
ensure(zlib.crc32(payload) == stored_crc, "Payload CRC32 mismatch")
```

The decoder requires **exactly one** validated frame per lane, so a lucky false sync can't be accepted.

### 9. XOR the two shares

Neither lane is the message by itself. They are two shares of a secret-split payload:

```python
ensure(len(a) == len(b), "Share payload_size mismatch")
combined = bytes(x ^ y for x, y in zip(a, b))
```

### 10. Unwrap and decompress

The combined blob has a small wrapper: 4 opaque bytes, a codec selector (`3` = XZ), and a big-endian 16-bit payload size.

```python
ensure(combined[4] == 3, "Expected observed XZ codec selector")
payload_size = int.from_bytes(combined[5:7], "big")
xz_data = combined[7:7 + payload_size]
ensure(xz_data.startswith(b"\xfd7zXZ\x00"), "Invalid XZ extent")
```

Decompress and verify XZ integrity (CRC64, no trailing data):

```python
decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
message = decoder.decompress(xz_data)
ensure(decoder.eof and not decoder.unused_data
       and decoder.check == lzma.CHECK_CRC64, "XZ integrity/extent validation failed")
```

### 11. Validating the message

Before trusting the result, the solver checks that it names the right case and lanes, and that exactly one flag is present:

```python
ensure(("CASE=" + info["export_case"] + "\n").encode() in message, "Recovered case mismatch")
ensure(("LANES=" + ",".join(item[0] for item in shares) + "\n").encode() in message,
       "Recovered asset identities mismatch")
found_flags = re.findall(rb"^FLAG=(HTF\{[A-Za-z0-9_]+\})$", message, re.MULTILINE)
ensure(len(found_flags) == 1, "Expected one flag in validated message")
```

## Running the Solver

```bash
python3 temporal_solve.py "Temporal+Paradox.zip"
```

Requirements: Python 3.11+ (for `hashlib.file_digest` and `math.lcm`) and `debugfs` from `e2fsprogs`.

Output:

```
Evidence file hash: a3752cd07b31c9f6844ee3e0d57d99793ca977cdf58eef5e39bd8becde183379
Extracted image hash: ed7f14dca2811bf1bca411776da44e9e528aac0ae9845562715f6c2915c7ce1d
Freelist: 12 pages; 11 unique profile_rows; 6 pass CRC16
Selected case TS-1138, generation 14108, 2 complete lanes
Lane 0: CR9.TEMP.A2; phase=1; sync_bit=516; payload deltas=[581,4741)
  calibration=valid; interleaver=8x8; corrected_bits=15; share_bytes=247; CRC32=afd88ac3 OK
Lane 1: CR9.FLOW.A4; phase=1; sync_bit=768; payload deltas=[833,4557)
  calibration=valid; interleaver=7x7; corrected_bits=18; share_bytes=247; CRC32=81fec207 OK
Combined: 247 bytes; XZ: 220 bytes; message: 166 bytes; XZ CRC64 OK
Decoded message:
DELTAFORGE R9 / CHANNEL REASSEMBLY
CASE=TS-1138
LANES=CR9.TEMP.A2,CR9.FLOW.A4
FLAG=HTF{r9_9cfbf58fe2c300c42a442e2a073336f29e387a47}
VERDICT=MULTI-CLOCK COVERT EXPORT

Flag confirmed: HTF{r9_9cfbf58fe2c300c42a442e2a073336f29e387a47}
Message SHA256: ecfb49b8d73dc7a004e86aeb68d9e003f84786cc9a1f87fff7aff8b5cf78c9bf
```

The full solver is in `temporal_solve.py`

## Key Takeaways

- **Deleted is not gone.** With `secure_delete = OFF`, SQLite freelist pages preserved the profile records the live database no longer referenced.
- **Mid-rollout state means multiple generations.** Picking the generation with a complete lane set was essential; a single stale profile would have decoded to noise.
- **Covert timing channels hide in plain sight.** The sensor values were irrelevant; the payload was encoded in the ordering of inter-arrival times.
- **Validate everything.** Calibration files, CRC16, CRC32, Hamming distance, XZ CRC64, and the case/lane identity checks all had to agree before the flag was accepted.
- **Never trust the planted cache.** `triage_cache.txt` tried to steer the analyst toward a fake flag and a false "one lane" conclusion. Evidence beats instructions embedded in evidence.

## Flag

```
HTF{r9_9cfbf58fe2c300c42a442e2a073336f29e387a47}
```