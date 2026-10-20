"""The tasks of Laboratory Work No. 4 (task number = n mod 11) plus the one-round alternative.

Every task has a list of input fields and a solve() function that returns all intermediate steps.
The default values come from the worked example of "Theory of DES" (J. O. Grabbe):
key 133457799BBCDFF1, message 0123456789ABCDEF -> ciphertext 85E813540F0AB405,
so the output can be compared step by step with the course material.
"""

import random
from dataclasses import dataclass, field
from typing import Any, Callable

from des import (
    E, IP, IP_INV, P, PC2, SHIFTS, cd_halves, f, group, key_plus, parse_bits, parse_block,
    parse_int, permute, random_bits, random_text, round_keys, sbox, sboxes, to_hex, xor,
)


@dataclass
class Field:
    name: str
    label: str
    parse: Callable[[str], Any]
    random: Callable[[], str]
    default: str
    multiline: bool = False


@dataclass
class Step:
    label: str
    value: str = ""
    rows: list[dict] | None = None    # shown as a table


@dataclass
class Task:
    number: str
    title: str
    fields: list[Field]
    tables: list[str]
    solve: Callable[..., list[Step]]  # the last step is the answer
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- default values (Grabbe example)
EX_KEY = "133457799BBCDFF1"
EX_MSG = "0123456789ABCDEF"
_key64, _ = parse_block(EX_KEY, "key")
_msg64, _ = parse_block(EX_MSG, "message")
EX_KPLUS = key_plus(_key64)
EX_K1 = round_keys(EX_KPLUS)[0]
_ip = permute(_msg64, IP)
EX_L0, EX_R0 = _ip[:32], _ip[32:]
EX_B = xor(EX_K1, permute(EX_R0, E))
EX_S = sboxes(EX_B)


def _final_halves():
    left, right = EX_L0, EX_R0
    for k in round_keys(EX_KPLUS):
        left, right = right, xor(left, f(right, k))
    return left, right


EX_L16, EX_R16 = _final_halves()

MESSAGE_M = (
    "The Data Encryption Standard (DES) specifies two FIPS approved cryptographic algorithms as "
    "required by FIPS 140-1. When used in conjunction with American National Standards Institute (ANSI) "
    "X9.52 standard, this publication provides a complete description of the mathematical algorithms for "
    "encrypting (enciphering) and decrypting (deciphering) binary coded information. Encrypting data "
    "converts it to an unintelligible form called cipher. Decrypting cipher converts the data back to its "
    "original form called plaintext. The algorithms described in this standard specifies both enciphering "
    "and deciphering operations which are based on a binary number called a key."
)


# ---------------------------------------------------------------- formatting helpers
def bits(label: str, value: str, size: int = 4) -> Step:
    extra = f"   = {to_hex(value)} (hex)" if len(value) % 4 == 0 else ""
    return Step(label, group(value, size) + extra)


def byte_rows(block64: str) -> list[dict]:
    rows = []
    for i in range(8):
        byte = block64[8 * i:8 * i + 8]
        code = int(byte, 2)
        rows.append({"#": i + 1, "char": chr(code) if 32 <= code <= 126 else "·",
                     "ASCII": code, "hex": f"{code:02X}", "binary": byte})
    return rows


def sbox_rows(b48: str, only: int | None = None) -> list[dict]:
    rows = []
    for j in range(1, 9):
        if only and j != only:
            continue
        b = b48[6 * (j - 1):6 * j]
        row, col, value, out = sbox(j, b)
        rows.append({"j": j, "Bj": b, "row bits (b1 b6)": b[0] + b[5], "row": row,
                     "col bits (b2..b5)": b[1:5], "col": col, f"Sj[row][col]": value, "Sj(Bj)": out})
    return rows


def key_field(name="key", label="Key K (8 characters or 16 hex digits)", default=EX_KEY):
    return Field(name, label, lambda raw: parse_block(raw, "key"), random_text, default)


def bits_field(name, label, n, default_bits):
    return Field(name, f"{label} ({n} bits, binary or {n // 4} hex digits)",
                 lambda raw: parse_bits(raw, n, label), lambda: to_hex(random_bits(n)), to_hex(default_bits))


def int_field(name, label, low, high, default):
    return Field(name, f"{label} ({low}-{high})", lambda raw: parse_int(raw, low, high, label),
                 lambda: str(random.randint(low, high)), str(default))


# ---------------------------------------------------------------- the tasks
def solve_2_1(key):
    key64, desc = key
    kplus = key_plus(key64)
    return [
        Step(f"Key: {desc} - every character is written with its 8-bit ASCII code", rows=byte_rows(key64)),
        bits("K (64 bits)", key64, 8),
        Step("PC-1 takes bit 57 of K as bit 1 of K+, bit 49 as bit 2, ... The parity bits "
             "8, 16, 24, 32, 40, 48, 56, 64 of K are not used."),
        bits("K+ = PC-1(K) (56 bits)", kplus, 7),
    ]


def cd_rows(kplus, upto):
    halves = cd_halves(kplus, upto)
    return [{"i": i, "shifts": SHIFTS[i - 1] if i else "-", "Ci": group(c, 7), "Di": group(d, 7)}
            for i, (c, d) in enumerate(halves)]


def solve_2_2(kplus, i):
    c, d = cd_halves(kplus, i)[i]
    return [
        bits("K+ (56 bits)", kplus, 7),
        bits("C0 = left half of K+ (28 bits)", kplus[:28], 7),
        bits("D0 = right half of K+ (28 bits)", kplus[28:], 7),
        Step(f"C(r) and D(r) are obtained from C(r-1), D(r-1) by circular left shifts "
             f"(1 or 2 positions, table 'Shifts'), r = 1..{i}", rows=cd_rows(kplus, i)),
        bits(f"C{i}", c, 7),
        bits(f"D{i}", d, 7),
        Step(f"Answer: C{i}, D{i}", f"C{i} = {group(c, 7)}\nD{i} = {group(d, 7)}"),
    ]


def solve_2_3(kplus, i):
    c, d = cd_halves(kplus, i)[i]
    ki = permute(c + d, PC2)
    return [
        bits("K+ (56 bits)", kplus, 7),
        Step(f"C0D0 = K+, then shifts up to round {i}", rows=cd_rows(kplus, i)),
        bits(f"C{i}D{i} (56 bits)", c + d, 7),
        Step("PC-2 selects 48 of the 56 bits (bits 9, 18, 22, 25, 35, 38, 43, 54 are dropped)."),
        bits(f"K{i} = PC-2(C{i}D{i}) (48 bits)", ki, 6),
    ]


def solve_2_4(message):
    m64, desc = message
    ip = permute(m64, IP)
    return [
        Step(f"Message: {desc} - every character is written with its 8-bit ASCII code", rows=byte_rows(m64)),
        bits("M (64 bits)", m64, 8),
        bits("IP(M) (64 bits) - bit 58 of M becomes bit 1, bit 50 becomes bit 2, ...", ip, 8),
        bits("L0 = left half of IP(M)", ip[:32]),
        bits("R0 = right half of IP(M)", ip[32:]),
        Step("In round 1: L1 = R0 and R1 = L0 xor f(R0, K1)."),
        bits("L1 = R0 (32 bits)", ip[32:]),
    ]


def solve_2_5(kplus):
    halves = cd_halves(kplus)
    keys = round_keys(kplus)
    rows = [{"i": i, "shifts": SHIFTS[i - 1], "Ci": group(halves[i][0], 7), "Di": group(halves[i][1], 7),
             "Ki = PC-2(CiDi)": group(keys[i - 1], 6), "Ki (hex)": to_hex(keys[i - 1])}
            for i in range(1, 17)]
    return [
        bits("K+ (56 bits)", kplus, 7),
        bits("C0", kplus[:28], 7),
        bits("D0", kplus[28:], 7),
        Step("Ci, Di (left shifts) and Ki = PC-2(CiDi) for every round", rows=rows),
        Step("Answer: the 16 round keys", "\n".join(f"K{i:<2} = {group(k, 6)}   = {to_hex(k)}"
                                                     for i, k in enumerate(keys, start=1))),
    ]


def solve_2_6(i, ki, r_prev):
    e = permute(r_prev, E)
    b = xor(ki, e)
    return [
        bits(f"R{i - 1} (32 bits)", r_prev),
        Step(f"E expands R{i - 1} to 48 bits: groups of 4 bits get the neighbouring bits on both sides."),
        bits(f"E(R{i - 1}) (48 bits)", e, 6),
        bits(f"K{i} (48 bits)", ki, 6),
        bits(f"K{i} xor E(R{i - 1})", b, 6),
        Step("Split into 8 groups of 6 bits", rows=[{"j": j, "Bj": b[6 * (j - 1):6 * j]} for j in range(1, 9)]),
        Step("Answer: B1B2B3B4B5B6B7B8", group(b, 6)),
    ]


def solve_2_7(b48):
    out = sboxes(b48)
    return [
        bits("B1B2...B8 (48 bits)", b48, 6),
        Step("For every Bj: row = bits 1 and 6, column = bits 2..5; Sj[row][col] is written on 4 bits",
             rows=sbox_rows(b48)),
        bits("Answer: S1(B1)S2(B2)...S8(B8) (32 bits)", out),
    ]


def solve_r(k, l_prev, s_out):
    fk = permute(s_out, P)
    r = xor(l_prev, fk)
    return [
        bits("S1(B1)...S8(B8) (32 bits)", s_out),
        Step("f = P(S1(B1)...S8(B8)) - bit 16 becomes bit 1, bit 7 becomes bit 2, ..."),
        bits(f"f(R{k - 1}, K{k}) = P(...)", fk),
        bits(f"L{k - 1}", l_prev),
        Step(f"R{k} = L{k - 1} xor f(R{k - 1}, K{k})"),
        bits(f"Answer: R{k} (32 bits)", r),
    ]


def solve_2_9(b48, j):
    b = b48[6 * (j - 1):6 * j]
    row, col, value, out = sbox(j, b)
    return [
        bits("Ki xor E(Ri-1) (48 bits)", b48, 6),
        Step(f"B{j} = bits {6 * (j - 1) + 1}..{6 * j}", b),
        Step(f"row = b1 b6 = {b[0]}{b[5]} = {row}; column = b2b3b4b5 = {b[1:5]} = {col}",
             rows=sbox_rows(b48, only=j)),
        Step(f"S{j}[{row}][{col}] = {value}"),
        Step(f"Answer: S{j}(B{j})", f"{out}  (= {value})"),
    ]


def solve_2_11(l16, r16):
    pre = r16 + l16
    c = permute(pre, IP_INV)
    return [
        bits("L16", l16),
        bits("R16", r16),
        Step("After round 16 the halves are swapped: the pre-output is R16L16."),
        bits("R16L16 (64 bits)", pre, 8),
        bits("C = IP^-1(R16L16) - bit 40 becomes bit 1, bit 8 becomes bit 2, ...", c, 8),
        Step("Answer: encrypted block (hex)", to_hex(c)),
    ]


def solve_alt(message, i, key):
    if not message:
        raise ValueError("The message is empty.")
    for pos, ch in enumerate(message, start=1):
        if ord(ch) > 126:
            raise ValueError(f"Character '{ch}' at position {pos} of the message is not ASCII.")
    blocks = [message[k:k + 8] for k in range(0, len(message), 8)]
    if i > len(blocks):
        raise ValueError(f"The message has only {len(blocks)} blocks of 8 characters; choose i <= {len(blocks)}.")
    block = blocks[i - 1].ljust(8)
    key64, kdesc = key
    m64 = "".join(f"{ord(ch):08b}" for ch in block)
    kplus = key_plus(key64)
    c1, d1 = cd_halves(kplus, 1)[1]
    k1 = permute(c1 + d1, PC2)
    ip = permute(m64, IP)
    l0, r0 = ip[:32], ip[32:]
    e = permute(r0, E)
    b = xor(k1, e)
    s = sboxes(b)
    fk = permute(s, P)
    l1, r1 = r0, xor(l0, fk)
    c = permute(r1 + l1, IP_INV)
    return [
        Step(f"The message has {len(message)} characters = {len(blocks)} blocks of 8 "
             f"(the last one is padded with spaces). Block {i}: '{block}'", rows=byte_rows(m64)),
        bits(f"M (block {i}, 64 bits)", m64, 8),
        Step(f"Key: {kdesc}", rows=byte_rows(key64)),
        bits("K (64 bits)", key64, 8),
        bits("K+ = PC-1(K)", kplus, 7),
        bits("C0", kplus[:28], 7), bits("D0", kplus[28:], 7),
        bits("C1 = C0 <<< 1", c1, 7), bits("D1 = D0 <<< 1", d1, 7),
        bits("K1 = PC-2(C1D1)", k1, 6),
        bits("IP(M)", ip, 8),
        bits("L0", l0), bits("R0", r0),
        bits("E(R0)", e, 6),
        bits("K1 xor E(R0) = B1...B8", b, 6),
        Step("S-boxes", rows=sbox_rows(b)),
        bits("S1(B1)...S8(B8)", s),
        bits("f(R0, K1) = P(...)", fk),
        bits("L1 = R0", l1),
        bits("R1 = L0 xor f(R0, K1)", r1),
        bits("R1L1 (halves swapped, as after the last round)", r1 + l1, 8),
        bits("C = IP^-1(R1L1)", c, 8),
        Step("Answer: encrypted block (hex)", to_hex(c)),
    ]


TASKS = [
    Task("2.1", "Given the DES key (8 symbols), determine K+",
         [key_field()], ["PC-1"], solve_2_1),
    Task("2.2", "Given K+, determine Ci and Di for a given i",
         [bits_field("kplus", "K+", 56, EX_KPLUS), int_field("i", "i", 0, 16, 1)], ["Shifts"], solve_2_2),
    Task("2.3", "Given K+, determine the round key Ki for a given i",
         [bits_field("kplus", "K+", 56, EX_KPLUS), int_field("i", "i", 1, 16, 1)], ["Shifts", "PC-2"], solve_2_3),
    Task("2.4", "Given the message (8 characters), find L1",
         [Field("message", "Message M (8 characters or 16 hex digits)", lambda raw: parse_block(raw, "message"),
                random_text, EX_MSG)], ["IP"], solve_2_4),
    Task("2.5", "Given K+, determine all 16 round keys Ki",
         [bits_field("kplus", "K+", 56, EX_KPLUS)], ["Shifts", "PC-2"], solve_2_5),
    Task("2.6", "Given Ki and Ri-1 in round i, compute B1B2B3B4B5B6B7B8",
         [int_field("i", "Round i", 1, 16, 1), bits_field("ki", "Ki", 48, EX_K1),
          bits_field("r_prev", "Ri-1", 32, EX_R0)], ["E"], solve_2_6),
    Task("2.7", "Given B1B2...B8, find S1(B1)S2(B2)...S8(B8)",
         [bits_field("b48", "B1...B8", 48, EX_B)], [f"S{j}" for j in range(1, 9)], solve_2_7),
    Task("2.8", "Compute Rk for round k, knowing Lk-1 and the output of the S-boxes",
         [int_field("k", "Round k", 1, 16, 1), bits_field("l_prev", "Lk-1", 32, EX_L0),
          bits_field("s_out", "S-box output", 32, EX_S)], ["P"], solve_r),
    Task("2.9", "Ki + E(Ri-1) is known (48 bits); determine Sj(Bj) for a given j",
         [bits_field("b48", "Ki + E(Ri-1)", 48, EX_B), int_field("j", "j", 1, 8, 1)],
         [f"S{j}" for j in range(1, 9)], solve_2_9),
    Task("2.10", "S1(B1)...S8(B8) and Li-1 are known in round i; compute Ri",
         [int_field("k", "Round i", 1, 16, 1), bits_field("l_prev", "Li-1", 32, EX_L0),
          bits_field("s_out", "S1(B1)...S8(B8)", 32, EX_S)], ["P"], solve_r),
    Task("2.11", "Given L16 and R16, determine the encrypted block in hex",
         [bits_field("l16", "L16", 32, EX_L16), bits_field("r16", "R16", 32, EX_R16)], ["IP^-1"], solve_2_11),
    Task("Alt", "Alternative: encrypt block i of message m with key k, DES with a single round",
         [Field("message", "Message m", lambda raw: raw, lambda: MESSAGE_M, MESSAGE_M, multiline=True),
          Field("i", "Block index i (1, 2, ...)", lambda raw: parse_int(raw, 1, 9999, "block index"),
                lambda: str(random.randint(1, (len(MESSAGE_M) + 7) // 8)), "1"),
          key_field("key", "Key k (8 characters or 16 hex digits)")],
         ["PC-1", "Shifts", "PC-2", "IP", "E"] + [f"S{j}" for j in range(1, 9)] + ["P", "IP^-1"], solve_alt),
]

TASKS_BY_NUMBER = {t.number: t for t in TASKS}


def run(task: Task, raw: dict[str, str]) -> list[Step]:
    """Validate every field (collecting all errors), then solve. Raises ValueError with all messages."""
    values, errors = {}, []
    for fld in task.fields:
        try:
            values[fld.name] = fld.parse(raw[fld.name])
        except ValueError as err:
            errors.append(str(err))
    if errors:
        raise ValueError("\n".join(errors))
    return task.solve(**values)
