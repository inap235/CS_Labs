"""DES (FIPS 46-3) building blocks for Laboratory Work No. 4.

Bits are kept as strings of '0'/'1' so that every intermediate value can be shown as it is.
Positions in the tables are numbered from 1, as in the standard.
"""

import random
import string

# ---------------------------------------------------------------- tables of the standard
# Permuted choice 1: 64-bit key -> K+ (56 bits); the parity bits 8, 16, ..., 64 are dropped
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# Permuted choice 2: CiDi (56 bits) -> round key Ki (48 bits)
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Number of left shifts of C and D in every round
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Initial permutation
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Final permutation IP^-1
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Expansion E: R (32 bits) -> 48 bits
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# Permutation P applied to the output of the S-boxes
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

# S-boxes S1..S8, each 4 rows x 16 columns
S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

# name -> (values, columns per row) - used to print the tables
TABLES = {
    "PC-1": (PC1, 7),
    "PC-2": (PC2, 6),
    "Shifts": (SHIFTS, 16),
    "IP": (IP, 8),
    "IP^-1": (IP_INV, 8),
    "E": (E, 6),
    "P": (P, 4),
    **{f"S{j}": ([v for row in box for v in row], 16) for j, box in enumerate(S_BOXES, start=1)},
}


def table_rows(name):
    values, cols = TABLES[name]
    return [values[i:i + cols] for i in range(0, len(values), cols)]


# ---------------------------------------------------------------- bit helpers
def permute(bits: str, table: list[int]) -> str:
    """Output bit k is input bit table[k] (positions counted from 1)."""
    return "".join(bits[pos - 1] for pos in table)


def xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def rotl(bits: str, n: int) -> str:
    return bits[n:] + bits[:n]


def group(bits: str, size: int) -> str:
    """'1010101111' -> '10101 01111' for readability."""
    return " ".join(bits[i:i + size] for i in range(0, len(bits), size))


def to_hex(bits: str) -> str:
    return "".join(f"{int(bits[i:i + 4], 2):X}" for i in range(0, len(bits), 4))


def hex_to_bits(hexstr: str) -> str:
    return "".join(f"{int(ch, 16):04b}" for ch in hexstr)


def text_to_bits(text: str) -> str:
    """Every character -> its 8-bit ASCII code."""
    return "".join(f"{ord(ch):08b}" for ch in text)


def bits_to_text(bits: str) -> str:
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))


# ---------------------------------------------------------------- input validation
BLOCK_CHARS_MSG = "8 ASCII characters (codes 32-126, spaces count) or 16 hexadecimal digits"


def parse_block(raw: str, what: str) -> tuple[str, str]:
    """A key / message block: 8 ASCII characters or 16 hex digits -> (64 bits, description)."""
    if len(raw) == 8:
        for pos, ch in enumerate(raw, start=1):
            if not 32 <= ord(ch) <= 126:
                raise ValueError(f"Character '{ch}' at position {pos} of the {what} is not printable ASCII. "
                                 f"Enter {BLOCK_CHARS_MSG}.")
        return text_to_bits(raw), f"text '{raw}'"
    compact = "".join(raw.split())
    if len(compact) == 16 and all(ch in string.hexdigits for ch in compact):
        return hex_to_bits(compact), f"hex {compact.upper()}"
    raise ValueError(f"The {what} has {len(raw)} characters. Enter {BLOCK_CHARS_MSG}.")


def parse_bits(raw: str, n: int, what: str) -> str:
    """n bits given in binary (n digits 0/1) or in hexadecimal (n/4 digits); spaces are ignored."""
    s = "".join(raw.split())
    if len(s) == n and set(s) <= {"0", "1"}:
        return s
    if n % 4 == 0 and len(s) == n // 4 and all(ch in string.hexdigits for ch in s):
        return hex_to_bits(s)
    hint = f" or {n // 4} hexadecimal digits" if n % 4 == 0 else ""
    raise ValueError(f"The {what} must have {n} binary digits{hint} (spaces are ignored); "
                     f"{len(s)} characters were entered.")


def parse_int(raw: str, low: int, high: int, what: str) -> int:
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise ValueError(f"The {what} must be an integer between {low} and {high}.") from None
    if not low <= value <= high:
        raise ValueError(f"The {what} must be between {low} and {high}; {value} was entered.")
    return value


# ---------------------------------------------------------------- random input
def random_text(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def random_bits(n: int) -> str:
    return "".join(random.choice("01") for _ in range(n))


# ---------------------------------------------------------------- DES steps
def key_plus(key64: str) -> str:
    return permute(key64, PC1)


def cd_halves(kplus: str, upto: int = 16) -> list[tuple[str, str]]:
    """[(C0, D0), (C1, D1), ..., (Cupto, Dupto)]."""
    c, d = kplus[:28], kplus[28:]
    halves = [(c, d)]
    for r in range(upto):
        c, d = rotl(c, SHIFTS[r]), rotl(d, SHIFTS[r])
        halves.append((c, d))
    return halves


def round_keys(kplus: str) -> list[str]:
    """[K1, ..., K16]."""
    return [permute(c + d, PC2) for c, d in cd_halves(kplus)[1:]]


def sbox(j: int, b6: str) -> tuple[int, int, int, str]:
    """Sj(Bj): row = first and last bit, column = the 4 middle bits -> (row, col, value, 4 bits)."""
    row, col = int(b6[0] + b6[5], 2), int(b6[1:5], 2)
    value = S_BOXES[j - 1][row][col]
    return row, col, value, f"{value:04b}"


def sboxes(b48: str) -> str:
    return "".join(sbox(j, b48[6 * (j - 1):6 * j])[3] for j in range(1, 9))


def f(r32: str, k48: str) -> str:
    return permute(sboxes(xor(k48, permute(r32, E))), P)


def encrypt_block(block64: str, key64: str, rounds: int = 16) -> str:
    """DES encryption of one block (rounds < 16 gives the shortened version of the guide)."""
    keys = round_keys(key_plus(key64))
    ip = permute(block64, IP)
    left, right = ip[:32], ip[32:]
    for i in range(rounds):
        left, right = right, xor(left, f(right, keys[i]))
    return permute(right + left, IP_INV)


def decrypt_block(block64: str, key64: str) -> str:
    keys = round_keys(key_plus(key64))[::-1]
    ip = permute(block64, IP)
    left, right = ip[:32], ip[32:]
    for k in keys:
        left, right = right, xor(left, f(right, k))
    return permute(right + left, IP_INV)
