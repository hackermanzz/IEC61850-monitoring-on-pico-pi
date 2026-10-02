"""Small dependency-free PCAPNG decoder for IEC 61850 GOOSE and SV events.

Each GOOSE APDU yields one event; each SV ASDU yields one event. Unsupported
and malformed IEC frames are counted with frame-level diagnostics and never
silently treated as decoded training examples.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator


class DecodeError(ValueError):
    pass


def _blocks(path: Path) -> Iterator[tuple[int, bytes]]:
    """Yield (linktype, packet) from little/big endian PCAPNG sections."""
    data = path.read_bytes()
    offset = 0
    endian = None
    interfaces: list[tuple[int, float]] = []
    while offset < len(data):
        if len(data) - offset < 12:
            raise DecodeError(f"truncated PCAPNG block header at byte {offset}")
        block_type_raw = data[offset:offset + 4]
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            if len(data) - offset < 28:
                raise DecodeError("truncated section header block")
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise DecodeError(f"invalid byte-order magic at byte {offset}")
            interfaces = []
        if endian is None:
            raise DecodeError("file does not begin with a PCAPNG section")
        block_type, total_len = struct.unpack_from(endian + "II", data, offset)
        if total_len < 12 or total_len % 4 or offset + total_len > len(data):
            raise DecodeError(f"invalid PCAPNG block length {total_len} at byte {offset}")
        if struct.unpack_from(endian + "I", data, offset + total_len - 4)[0] != total_len:
            raise DecodeError(f"PCAPNG block length trailer mismatch at byte {offset}")
        body = data[offset + 8:offset + total_len - 4]
        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise DecodeError("truncated interface description block")
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            resolution = 1e-6
            option_pos = 8
            while option_pos + 4 <= len(body):
                code, length = struct.unpack_from(endian + "HH", body, option_pos)
                option_pos += 4
                if code == 0:
                    break
                value = body[option_pos:option_pos + length]
                if code == 9 and value:
                    raw = value[0]
                    resolution = 2.0 ** -(raw & 0x7f) if raw & 0x80 else 10.0 ** -raw
                option_pos += (length + 3) & ~3
            interfaces.append((linktype, resolution))
        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise DecodeError("truncated enhanced packet block")
            iid, high, low, caplen, _wirelen = struct.unpack_from(endian + "IIIII", body)
            if iid >= len(interfaces):
                raise DecodeError(f"packet references missing interface {iid}")
            linktype, resolution = interfaces[iid]
            packet = body[20:20 + caplen]
            if len(packet) != caplen:
                raise DecodeError("truncated captured packet")
            yield linktype, packet, ((high << 32) | low) * resolution
        elif block_type == 3:  # Simple Packet Block has no timestamp
            if not interfaces or len(body) < 4:
                raise DecodeError("simple packet block lacks interface or length")
            wirelen = struct.unpack_from(endian + "I", body)[0]
            yield interfaces[0][0], body[4:4 + wirelen], float("nan")
        offset += total_len


def _tlvs(data: bytes) -> list[tuple[int, bytes]]:
    result = []
    pos = 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise DecodeError("truncated BER tag/length")
        tag = data[pos]
        pos += 1
        length = data[pos]
        pos += 1
        if length & 0x80:
            count = length & 0x7f
            if count == 0 or count > 4 or pos + count > len(data):
                raise DecodeError("invalid BER long-form length")
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        if pos + length > len(data):
            raise DecodeError("BER value exceeds enclosing APDU")
        result.append((tag, data[pos:pos + length]))
        pos += length
    return result


def _int(value: bytes) -> int:
    if not value:
        raise DecodeError("empty BER integer")
    # Protocol counters/configuration values are unsigned. In particular a
    # 16-bit smpCnt above 32767 must not turn negative.
    return int.from_bytes(value, "big", signed=False)


def _text(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", errors="replace")


def _ethernet(packet: bytes) -> tuple[str, str, int, bytes, int | None]:
    if len(packet) < 14:
        raise DecodeError("truncated Ethernet header")
    src = ":".join(f"{v:02x}" for v in packet[6:12])
    dst = ":".join(f"{v:02x}" for v in packet[0:6])
    etype = int.from_bytes(packet[12:14], "big")
    offset = 14
    vlan_id = None
    while etype in (0x8100, 0x88A8, 0x9100):
        if len(packet) < offset + 4:
            raise DecodeError("truncated VLAN header")
        tci = int.from_bytes(packet[offset:offset + 2], "big")
        vlan_id = tci & 0x0fff
        etype = int.from_bytes(packet[offset + 2:offset + 4], "big")
        offset += 4
    return src, dst, etype, packet[offset:], vlan_id


def _goose(payload: bytes) -> dict:
    if len(payload) < 8:
        raise DecodeError("truncated GOOSE Ethernet header")
    appid = int.from_bytes(payload[:2], "big")
    apdu_len = int.from_bytes(payload[2:4], "big")
    # IEEE 61850 Ethernet length includes this 8-byte APPID/length/reserved header.
    if apdu_len < 10 or apdu_len > len(payload):
        raise DecodeError(f"invalid GOOSE APDU length {apdu_len}")
    top = _tlvs(payload[8:apdu_len])
    if len(top) != 1 or top[0][0] != 0x61:
        raise DecodeError("GOOSE APDU does not contain one [APPLICATION 1] PDU")
    fields = dict(_tlvs(top[0][1]))
    all_data = fields.get(0xAB, b"")
    boolean = ""
    if all_data:
        try:
            first = _tlvs(all_data)
            if first and first[0][0] == 0x83 and first[0][1]:
                boolean = str(first[0][1][-1] != 0)
        except DecodeError:
            pass
    return {
        "appid": appid,
        "goCbRef": _text(fields[0x80]) if 0x80 in fields else "",
        "stNum": _int(fields[0x85]) if 0x85 in fields else "",
        "sqNum": _int(fields[0x86]) if 0x86 in fields else "",
        # GOOSE test is an ASN.1 BOOLEAN. Preserve whether any encoded bit is set.
        "test": str(any(fields.get(0x87, b""))) if fields.get(0x87) else "",
        "confRev": _int(fields[0x88]) if 0x88 in fields else "",
        "boolean": boolean,
    }


def _sv(payload: bytes) -> tuple[int, list[dict]]:
    if len(payload) < 8:
        raise DecodeError("truncated SV Ethernet header")
    appid = int.from_bytes(payload[:2], "big")
    reserved1 = int.from_bytes(payload[4:6], "big")
    apdu_len = int.from_bytes(payload[2:4], "big")
    # IEEE 61850 Ethernet length includes this 8-byte APPID/length/reserved header.
    if apdu_len < 10 or apdu_len > len(payload):
        raise DecodeError(f"invalid SV APDU length {apdu_len}")
    top = _tlvs(payload[8:apdu_len])
    if len(top) != 1 or top[0][0] != 0x60:
        raise DecodeError("SV APDU does not contain one savPdu")
    pdu = dict(_tlvs(top[0][1]))
    advertised = _int(pdu[0x80]) if 0x80 in pdu else None
    if advertised is None or advertised < 1 or advertised > 256:
        raise DecodeError(f"invalid SV noASDU {advertised!r}")
    if 0xA2 not in pdu:
        raise DecodeError("SV savPdu lacks seqASDU")
    asdus = [value for tag, value in _tlvs(pdu[0xA2]) if tag == 0x30]
    if len(asdus) != advertised:
        raise DecodeError(f"advertised {advertised} ASDUs, decoded {len(asdus)}")
    rows = []
    for index, raw in enumerate(asdus):
        f = dict(_tlvs(raw))
        rows.append({
            "asdu_index": index,
            "appid": appid,
            "svID": _text(f[0x80]) if 0x80 in f else "",
            "smpCnt": _int(f[0x82]) if 0x82 in f else "",
            "confRev": _int(f[0x83]) if 0x83 in f else "",
            "smpSynch": _int(f[0x85]) if 0x85 in f else "",
            "noASDU": advertised,
            "seqData": f.get(0x87, b"").hex(),
            "raw_simulated": str(bool(reserved1 & 0x8000)),
            "sv_reserved1": f"0x{reserved1:04x}",
        })
    return advertised, rows


def decode_ethernet_frame(
    packet: bytes, timestamp: float, capture_id: str, frame_index: int,
) -> tuple[list[dict], str | None]:
    """Decode one captured Ethernet frame for both PCAP and live adapters.

    Returns ``([], None)`` for unrelated Ethernet traffic, decoded event rows
    on success, or ``([], reason)`` for a malformed supported IEC frame.
    """
    try:
        src, dst, etype, payload, vlan = _ethernet(packet)
        source = Path(capture_id).name
        common = {
            "capture_id": source, "source_pcap": source,
            "frame_index": int(frame_index), "timestamp": float(timestamp),
            "src_mac": src, "dst_mac": dst,
            "vlan_id": "" if vlan is None else vlan,
            "frame_length": len(packet),
        }
        if etype == 0x88B8:
            row = _goose(payload)
            return [{
                **common, "asdu_index": 0, "protocol": "GOOSE",
                "stream_id": row["goCbRef"], "st_num": row["stNum"],
                "sq_num": row["sqNum"], "smp_cnt": "", "smpcnt_modulus": "",
                "no_asdu": "", "conf_rev": row["confRev"], "smp_synch": "",
                "appid": row["appid"], "raw_test": row["test"],
                "raw_simulated": "", "boolean": row["boolean"],
                "goCbRef": row["goCbRef"],
            }], None
        if etype == 0x88BA:
            advertised, asdus = _sv(payload)
            return [{
                **common, "asdu_index": row["asdu_index"], "protocol": "SV",
                "stream_id": row["svID"], "st_num": "", "sq_num": "",
                "smp_cnt": row["smpCnt"], "smpcnt_modulus": "",
                "no_asdu": advertised, "conf_rev": row["confRev"],
                "smp_synch": row["smpSynch"], "appid": row["appid"],
                "raw_test": "", "raw_simulated": row["raw_simulated"],
                "svID": row["svID"], "seq_data": row["seqData"],
                "sv_reserved1": row["sv_reserved1"],
            } for row in asdus], None
        return [], None
    except DecodeError as exc:
        return [], str(exc)


def decode_pcapng(path: str | Path) -> tuple[list[dict], dict]:
    """Decode one PCAPNG. Returns event rows and visible capture diagnostics."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    events: list[dict] = []
    diagnostics = {"source_pcap": source.name, "frames": 0, "goose_frames": 0,
                   "sv_frames": 0, "malformed_iec_frames": [], "unsupported_linktype": 0,
                   "other_ethernet_frames": 0, "sv_asdus": 0}
    for frame_index, (linktype, packet, timestamp) in enumerate(_blocks(source)):
        diagnostics["frames"] += 1
        if linktype != 1:
            diagnostics["unsupported_linktype"] += 1
            continue
        try:
            _src, _dst, etype, _payload, _vlan = _ethernet(packet)
        except DecodeError as exc:
            diagnostics["malformed_iec_frames"].append({"frame_index": frame_index, "reason": str(exc)})
            continue
        decoded, error = decode_ethernet_frame(packet, timestamp, source.name, frame_index)
        if error:
            diagnostics["malformed_iec_frames"].append({"frame_index": frame_index, "reason": error})
        elif decoded:
            events.extend(decoded)
            if etype == 0x88B8:
                diagnostics["goose_frames"] += 1
            elif etype == 0x88BA:
                diagnostics["sv_frames"] += 1
                diagnostics["sv_asdus"] += len(decoded)
        else:
            diagnostics["other_ethernet_frames"] += 1
    return events, diagnostics


def decode_many(paths: list[str | Path]) -> tuple[list[dict], list[dict]]:
    all_events, diagnostics = [], []
    for path in paths:
        rows, report = decode_pcapng(path)
        all_events.extend(rows)
        diagnostics.append(report)
    if not all_events:
        raise ValueError("No GOOSE or SV event records decoded from supplied PCAPNG files")
    return all_events, diagnostics
