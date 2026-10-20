"""Playfair cipher for messages in Romanian (31 letters).

The 31 letters do not fit in a 5x6 matrix, so - as in the classical algorithm - the letter J
is written as I. The remaining 30 letters fill a matrix with 5 rows and 6 columns.
"""

import unicodedata
from dataclasses import dataclass

# Letter order of the Romanian alphabet (the same table as in Laboratory Work No. 1)
ALPHABET = [
    "A", "Ă", "Â", "B", "C", "D", "E", "F", "G", "H", "I",
    "Î", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "Ș", "T", "Ț", "U", "V", "W", "X", "Y", "Z",
]
REPLACE = {"J": "I"}                                   # J is encrypted as I
MATRIX_ALPHABET = [ch for ch in ALPHABET if ch not in REPLACE]  # 30 letters
ROWS, COLS = 5, 6

FILLERS = ("X", "Q")   # inserted between two identical letters of a pair
PAD = "X"              # added when the prepared text has an odd number of letters
KEY_MIN_LEN = 7

# Ș/Ț are often typed with a cedilla (Ş/Ţ) instead of a comma below
CEDILLA_TO_COMMA = {"Ş": "Ș", "ş": "ș", "Ţ": "Ț", "ţ": "ț"}

ALLOWED_TEXT_MSG = (
    "Only letters are allowed: 'A'-'Z', 'a'-'z' and the Romanian letters Ă Â Î Ș Ț / ă â î ș ț "
    "(spaces are allowed and removed)."
)


def normalize(text: str) -> str:
    """Compose diacritics, map cedilla variants to comma-below, convert to uppercase."""
    text = unicodedata.normalize("NFC", text)
    text = "".join(CEDILLA_TO_COMMA.get(ch, ch) for ch in text)
    return text.upper()


def letters_only(raw: str, what: str) -> str:
    """Uppercase the text, remove spaces and check that every character is a letter."""
    text = "".join(normalize(raw).split())
    for pos, ch in enumerate(text, start=1):
        if ch not in ALPHABET:
            raise ValueError(f"Invalid character '{ch}' at position {pos} in the {what}. {ALLOWED_TEXT_MSG}")
    if not text:
        raise ValueError(f"The {what} is empty. {ALLOWED_TEXT_MSG}")
    return text


def validate_key(raw: str) -> str:
    """Return the key in uppercase without spaces; it must contain at least 7 letters."""
    key = letters_only(raw, "key")
    if len(key) < KEY_MIN_LEN:
        raise ValueError(
            f"The key is too short ({len(key)} letters): it must contain at least {KEY_MIN_LEN} letters."
        )
    return key


def prepare_message(raw: str) -> str:
    """Message for encryption: letters only, uppercase, no spaces, J written as I."""
    return "".join(REPLACE.get(ch, ch) for ch in letters_only(raw, "message"))


def prepare_ciphertext(raw: str) -> str:
    """Ciphertext for decryption: letters of the matrix, even length, no pair of equal letters."""
    text = letters_only(raw, "ciphertext")
    for pos, ch in enumerate(text, start=1):
        if ch in REPLACE:
            raise ValueError(
                f"Invalid character '{ch}' at position {pos}: the letter {ch} is not in the matrix "
                f"(it is encrypted as {REPLACE[ch]}), so it cannot appear in a ciphertext."
            )
    if len(text) % 2:
        raise ValueError(
            f"The ciphertext has an odd number of letters ({len(text)}); a Playfair ciphertext "
            "always consists of pairs of letters."
        )
    for i in range(0, len(text), 2):
        if text[i] == text[i + 1]:
            raise ValueError(
                f"Pair {i // 2 + 1} '{text[i:i + 2]}' contains two identical letters; this cannot "
                "occur in a Playfair ciphertext."
            )
    return text


def key_letters(key: str) -> str:
    """Key without repeated letters (only the first occurrence is kept), J written as I."""
    result = []
    for ch in key:
        ch = REPLACE.get(ch, ch)
        if ch not in result:
            result.append(ch)
    return "".join(result)


@dataclass
class Matrix:
    rows: list[list[str]]

    def __post_init__(self):
        self.position = {ch: (r, c) for r, row in enumerate(self.rows) for c, ch in enumerate(row)}

    @property
    def n_rows(self) -> int:
        return len(self.rows)

    @property
    def n_cols(self) -> int:
        return len(self.rows[0])


def build_matrix(key: str, alphabet=MATRIX_ALPHABET, cols: int = COLS) -> Matrix:
    """Key letters first (row by row), then the remaining letters of the alphabet in order."""
    order = key_letters(key)
    order += "".join(ch for ch in alphabet if ch not in order)
    return Matrix([list(order[i:i + cols]) for i in range(0, len(order), cols)])


def split_pairs(text: str, fillers=FILLERS, pad: str = PAD) -> list[str]:
    """Split the text into pairs, inserting a filler inside pairs of identical letters.

    Consecutive insertions alternate between the fillers (SSS -> SX SQ S...), and a filler is
    never equal to the letter it separates. An odd last letter is completed with `pad`.
    """
    pairs = []
    i, run = 0, 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else None
        if b is None:
            pairs.append(a + (pad if a != pad else next(f for f in fillers if f != a)))
            i += 1
        elif a == b:
            choices = [f for f in fillers if f != a]
            pairs.append(a + choices[run % len(choices)])
            run += 1
            i += 1
        else:
            pairs.append(a + b)
            run = 0
            i += 2
    return pairs


def transform_pair(pair: str, matrix: Matrix, direction: int) -> tuple[str, str]:
    """Apply the Playfair rules to one pair. direction = +1 encrypts, -1 decrypts.

    Returns the new pair and the rule used: 'rectangle', 'row' or 'column'.
    """
    (r1, c1), (r2, c2) = matrix.position[pair[0]], matrix.position[pair[1]]
    if r1 == r2:   # same row: letter to the right (encryption) / to the left (decryption)
        c1, c2 = (c1 + direction) % matrix.n_cols, (c2 + direction) % matrix.n_cols
        rule = "row"
    elif c1 == c2:  # same column: letter below (encryption) / above (decryption)
        r1, r2 = (r1 + direction) % matrix.n_rows, (r2 + direction) % matrix.n_rows
        rule = "column"
    else:          # rectangle: same row, column of the other letter
        c1, c2 = c2, c1
        rule = "rectangle"
    return matrix.rows[r1][c1] + matrix.rows[r2][c2], rule


def encrypt_pairs(pairs: list[str], matrix: Matrix) -> list[str]:
    return [transform_pair(p, matrix, +1)[0] for p in pairs]


def decrypt_pairs(pairs: list[str], matrix: Matrix) -> list[str]:
    return [transform_pair(p, matrix, -1)[0] for p in pairs]


def encrypt(message: str, key: str) -> str:
    """Encrypt a raw message with a raw key (both are validated)."""
    matrix = build_matrix(validate_key(key))
    return "".join(encrypt_pairs(split_pairs(prepare_message(message)), matrix))


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt a raw ciphertext with a raw key (both are validated)."""
    matrix = build_matrix(validate_key(key))
    text = prepare_ciphertext(ciphertext)
    return "".join(decrypt_pairs([text[i:i + 2] for i in range(0, len(text), 2)], matrix))


def remove_fillers(text: str, fillers=FILLERS, pad: str = PAD) -> str:
    """Suggestion for the manual phase: drop fillers that were probably inserted by split_pairs.

    A filler is removed when it is the second letter of a pair and the next pair starts with
    the same letter as the first one (SX SQ SH -> SSSH), and a final pad letter is removed.
    The result must still be checked by a human, since such letters may also be genuine.
    """
    pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
    out = []
    for i, p in enumerate(pairs):
        nxt = pairs[i + 1] if i + 1 < len(pairs) else None
        if len(p) == 2 and p[1] in fillers and nxt and nxt[0] == p[0]:
            out.append(p[0])
        elif nxt is None and len(p) == 2 and (p[1] == pad or (p[0] == pad and p[1] in fillers)):
            out.append(p[0])
        else:
            out.append(p)
    return "".join(out)
