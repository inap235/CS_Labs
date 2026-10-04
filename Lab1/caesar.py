"""Caesar cipher (one key and two keys) over the Romanian alphabet, n = 31.

Letters are encoded only through the ALPHABET table below (Table 2 of the lab):
A=0, Ă=1, Â=2, ..., Z=30. ASCII / Unicode code points are never used for the shift.
"""

import unicodedata

# Table 2 - letter encoding of the Romanian alphabet
ALPHABET = [
    "A", "Ă", "Â", "B", "C", "D", "E", "F", "G", "H", "I",
    "Î", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "Ș", "T", "Ț", "U", "V", "W", "X", "Y", "Z",
]
N = len(ALPHABET)  # 31
CODE = {letter: i for i, letter in enumerate(ALPHABET)}

KEY_MIN, KEY_MAX = 1, N - 1
KEYWORD_MIN_LEN = 7

# Ș/Ț are often typed with a cedilla (Ş/Ţ) instead of a comma below
CEDILLA_TO_COMMA = {"Ş": "Ș", "ş": "ș", "Ţ": "Ț", "ţ": "ț"}

ALLOWED_TEXT_MSG = (
    "Only letters of the Romanian alphabet are allowed: "
    "A-Z, a-z, Ă Â Î Ș Ț, ă â î ș ț (spaces are allowed and removed)."
)


def normalize(text: str) -> str:
    """Compose diacritics, map cedilla variants to comma-below, convert to uppercase."""
    text = unicodedata.normalize("NFC", text)
    text = "".join(CEDILLA_TO_COMMA.get(ch, ch) for ch in text)
    return text.upper()


def validate_key(raw) -> int:
    """Return the shift key as an int in [1, 30] or raise ValueError with a clear message."""
    raw = str(raw).strip()
    try:
        key = int(raw)
    except ValueError:
        raise ValueError(
            f"Invalid key '{raw}': the key must be an integer between {KEY_MIN} and {KEY_MAX} inclusive."
        ) from None
    if not KEY_MIN <= key <= KEY_MAX:
        raise ValueError(
            f"Invalid key {key}: the key must be an integer between {KEY_MIN} and {KEY_MAX} inclusive."
        )
    return key


def prepare_text(raw: str) -> str:
    """Uppercase the text, remove spaces and check that every character is a Romanian letter."""
    text = "".join(normalize(raw).split())
    for pos, ch in enumerate(text, start=1):
        if ch not in CODE:
            raise ValueError(f"Invalid character '{ch}' at position {pos}. {ALLOWED_TEXT_MSG}")
    if not text:
        raise ValueError(f"The text is empty. {ALLOWED_TEXT_MSG}")
    return text


def validate_keyword(raw: str) -> str:
    """Return the uppercase keyword (letters only, length >= 7) or raise ValueError."""
    keyword = normalize(raw.strip())
    for pos, ch in enumerate(keyword, start=1):
        if ch not in CODE:
            raise ValueError(
                f"Invalid character '{ch}' at position {pos} in the keyword. The keyword may contain "
                f"only letters of the Romanian alphabet (A-Z, Ă, Â, Î, Ș, Ț), without spaces."
            )
    if len(keyword) < KEYWORD_MIN_LEN:
        raise ValueError(
            f"The keyword is too short ({len(keyword)} letters): it must contain at least "
            f"{KEYWORD_MIN_LEN} letters of the Romanian alphabet."
        )
    return keyword


def permuted_alphabet(keyword: str) -> list[str]:
    """Distinct letters of the keyword first, then the remaining letters in Table 2 order."""
    result = []
    for ch in keyword + "".join(ALPHABET):
        if ch not in result:
            result.append(ch)
    return result


def shift(text: str, key: int, alphabet=ALPHABET) -> str:
    """Replace every letter x with the letter at position (x + key) mod n of the given alphabet."""
    n = len(alphabet)
    position = {letter: i for i, letter in enumerate(alphabet)}
    # Python's % always returns a value in 0..n-1, even for negative operands
    return "".join(alphabet[(position[ch] + key) % n] for ch in text)


def encrypt(text: str, key: int, alphabet=ALPHABET) -> str:
    return shift(text, key, alphabet)          # c = (x + k) mod n


def decrypt(text: str, key: int, alphabet=ALPHABET) -> str:
    return shift(text, -key, alphabet)         # m = (y - k) mod n
