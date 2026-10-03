from scapy.all import Ether, Raw, sendp, get_if_hwaddr
import struct
import time

# -----------------------------
# Configuration
# -----------------------------
INTERFACE = "Ethernet"

# IEC 61850 GOOSE multicast MAC range:
# 01-0C-CD-01-00-00 through 01-0C-CD-01-01-FF
DST_MAC = "01:0c:cd:01:00:01"

SRC_MAC = get_if_hwaddr(INTERFACE)

APPID = 1000          # Decimal 1000 = 0x03E8

# Use a different control-block reference on every run. The Pico includes
# gocbRef in its stream key, so this starts with a fresh rolling window without
# requiring a Pico reboot.
GOCBREF = f"test-class1-{int(time.time())}"

# The extracted model's useful time_interval splits end near 0.512 seconds.
# About 294 ms was verified against the original joblib as a Class 1 test rate.
PACKET_INTERVAL_SECONDS = 0.294

# The Pico needs 17 successfully received packets for its first prediction.
# Send extra baseline packets because the experimental asynchronous RMII input
# may reject some captures. Only the latest 16 observations affect the median.
BASELINE_PACKETS = 24

# -----------------------------
# Basic BER helpers
# -----------------------------
def ber_length(length):
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return b"\x81" + bytes([length])
    return b"\x82" + struct.pack(">H", length)


def tlv(tag, value):
    return bytes([tag]) + ber_length(len(value)) + value


def uint_bytes(value):
    if value < 0:
        raise ValueError("BER unsigned integer cannot be negative")

    if value == 0:
        return b"\x00"

    result = value.to_bytes((value.bit_length() + 7) // 8, "big")

    # BER INTEGER must remain positive
    if result[0] & 0x80:
        result = b"\x00" + result

    return result


def make_goose(st_num=1, sq_num=0):

    # GOOSE PDU fields
    goose_fields = b""

    # [0] gocbRef
    goose_fields += tlv(0x80, GOCBREF.encode())

    # [1] timeAllowedToLive
    goose_fields += tlv(0x81, uint_bytes(2000))

    # [2] datSet
    goose_fields += tlv(0x82, b"test")

    # [3] goID
    goose_fields += tlv(0x83, b"test")

    # [4] timestamp
    # Simplified 8-byte timestamp for lab testing
    goose_fields += tlv(0x84, b"\x00" * 8)

    # [5] stNum
    goose_fields += tlv(0x85, uint_bytes(st_num))

    # [6] sqNum
    goose_fields += tlv(0x86, uint_bytes(sq_num))

    # [7] simulation = FALSE
    goose_fields += tlv(0x87, b"\x00")

    # [8] confRev
    goose_fields += tlv(0x88, uint_bytes(1))

    # [9] ndsCom = FALSE
    goose_fields += tlv(0x89, b"\x00")

    # [10] numDatSetEntries = 1
    goose_fields += tlv(0x8A, uint_bytes(1))

    # [11] allData
    # One BOOLEAN value = FALSE
    all_data = tlv(0x83, b"\x00")
    goose_fields += tlv(0xAB, all_data)

    # GOOSE PDU
    goose_pdu = tlv(0x61, goose_fields)

    # IEC 61850-8-1 GOOSE header
    #
    # APPID       2 bytes
    # Length      2 bytes
    # Reserved 1  2 bytes
    # Reserved 2  2 bytes
    #
    goose_length = 8 + len(goose_pdu)

    goose_header = struct.pack(
        ">HHHH",
        APPID,
        goose_length,
        0x0000,
        0x0000
    )

    return goose_header + goose_pdu


# -----------------------------
# Send one GOOSE frame
# -----------------------------
def send_goose(st_num, sq_num, phase):
    payload = make_goose(
        st_num=st_num,
        sq_num=sq_num
    )

    frame = (
        Ether(
            src=SRC_MAC,
            dst=DST_MAC,
            type=0x88B8       # IEC 61850 GOOSE EtherType
        )
        / Raw(payload)
    )

    sendp(
        frame,
        iface=INTERFACE,
        verbose=False
    )

    print(
        f"GOOSE sent | "
        f"dst={DST_MAC} | "
        f"APPID={APPID} | "
        f"gocbRef={GOCBREF} | "
        f"stNum={st_num} | "
        f"sqNum={sq_num} | "
        f"phase={phase}"
    )


# -----------------------------
# Finite Class 1 test sequence
# -----------------------------
# Build a low stNum history first. sqNum deliberately advances by two, as in
# the user's test. The extra baseline frames make it likely that the Pico fills
# its 16-transition window even if a few RMII captures fail CRC validation.
sq_num = 0
for packet_index in range(BASELINE_PACKETS):
    send_goose(st_num=1, sq_num=sq_num, phase="baseline")
    sq_num += 2
    time.sleep(PACKET_INTERVAL_SECONDS)

# Create a large positive departure from the historical stNum values. A state
# change conventionally resets sqNum, so this packet uses zero.
send_goose(st_num=100, sq_num=0, phase="upward-jump")
time.sleep(PACKET_INTERVAL_SECONDS)

# This is the requested decreasing-stNum test: 100 -> 99. It deliberately uses
# sqNum=2. With the preceding history and ~294 ms interval, the current feature
# extractor produces a high-confidence Class 1 input for the original model.
send_goose(st_num=99, sq_num=2, phase="decrease-target")

print(
    "Class 1 test complete. Check the Pico terminal for the packet with "
    "phase=decrease-target values stNum=99 and sqNum=2."
)
