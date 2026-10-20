"""Frequency-analysis attack on a monoalphabetic substitution cipher (English text).

Only the 26 Latin letters are substituted; every other character
(spaces, digits, punctuation) stays unchanged.

Display convention (same as in section 2.3 of the lab guide):
  - letters already decrypted are shown in lowercase (plaintext),
  - letters not decrypted yet are shown in UPPERCASE (ciphertext).
"""

from collections import Counter
from string import ascii_uppercase

ALPHABET = ascii_uppercase  # A..Z

# Table 2.2 - letter frequencies of the English language (%)
ENGLISH_FREQ = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23, "G": 2.01,
    "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03, "M": 2.41, "N": 6.75,
    "O": 7.51, "P": 1.93, "Q": 0.09, "R": 5.99, "S": 6.33, "T": 9.06, "U": 2.76,
    "V": 0.98, "W": 2.36, "X": 0.15, "Y": 1.97, "Z": 0.07,
}

# Table 2.1 - letter frequencies of the Romanian language (%), kept for reference
ROMANIAN_FREQ = {
    "A": 9.95, "Ă": 4.06, "Â": 0.91, "B": 1.07, "C": 5.28, "D": 3.45, "E": 11.47,
    "F": 1.18, "G": 0.99, "H": 0.47, "I": 9.96, "Î": 1.40, "J": 0.24, "K": 0.11,
    "L": 4.48, "M": 3.10, "N": 6.47, "O": 4.07, "P": 3.18, "Q": 0.00, "R": 6.82,
    "S": 4.40, "Ș": 1.55, "T": 6.04, "Ț": 1.00, "U": 6.20, "V": 1.23, "W": 0.03,
    "X": 0.11, "Y": 0.07, "Z": 0.71,
}

COMMON_DIGRAPHS = ["TH", "HE", "AN", "IN", "ER", "ON", "RE", "ED", "ND", "HA", "AT", "EN"]
COMMON_TRIGRAPHS = ["THE", "AND", "THA", "ENT", "ION", "TIO", "FOR", "NDE", "HAS", "NCE", "TIS", "OFT", "MEN"]


def letter_counts(text: str) -> dict[str, int]:
    """Absolute frequency of every letter A..Z (case-insensitive), including zeros."""
    counts = Counter(ch for ch in text.upper() if ch in ALPHABET)
    return {letter: counts.get(letter, 0) for letter in ALPHABET}


def letter_percentages(text: str) -> dict[str, float]:
    """Relative frequency (%) of every letter A..Z."""
    counts = letter_counts(text)
    total = sum(counts.values()) or 1
    return {letter: 100 * n / total for letter, n in counts.items()}


def sorted_by_frequency(freq: dict[str, float]) -> list[tuple[str, float]]:
    """Letters sorted by decreasing frequency (ties broken alphabetically)."""
    return sorted(freq.items(), key=lambda item: (-item[1], item[0]))


def ngram_counts(text: str, n: int, top: int = 15) -> list[tuple[str, int]]:
    """Most frequent n-grams inside words (letters only)."""
    counts = Counter()
    for word in "".join(ch if ch.isalpha() else " " for ch in text.upper()).split():
        counts.update(word[i:i + n] for i in range(len(word) - n + 1))
    return counts.most_common(top)


def word_counts(text: str, length: int | None = None, top: int = 15) -> list[tuple[str, int]]:
    """Most frequent words (optionally only those with the given length)."""
    words = "".join(ch if ch.isalpha() else " " for ch in text.upper()).split()
    if length is not None:
        words = [w for w in words if len(w) == length]
    return Counter(words).most_common(top)


def validate_mapping(mapping: dict[str, str]) -> dict[str, str]:
    """Normalize a cipher->plain mapping and check that it is injective."""
    clean = {}
    for cipher, plain in mapping.items():
        cipher, plain = cipher.upper(), plain.upper()
        if cipher not in ALPHABET or plain not in ALPHABET:
            raise ValueError(f"Invalid pair {cipher!r} -> {plain!r}: only letters A-Z are allowed.")
        clean[cipher] = plain
    plains = list(clean.values())
    duplicates = {p for p in plains if plains.count(p) > 1}
    if duplicates:
        raise ValueError(
            "Two ciphertext letters cannot map to the same plaintext letter: "
            + ", ".join(sorted(duplicates))
        )
    return clean


def apply_mapping(ciphertext: str, mapping: dict[str, str]) -> str:
    """Substitute known letters (shown lowercase); unknown letters stay UPPERCASE."""
    mapping = validate_mapping(mapping)
    out = []
    for ch in ciphertext:
        up = ch.upper()
        if up in mapping:
            out.append(mapping[up].lower())
        elif up in ALPHABET:
            out.append(up)
        else:
            out.append(ch)
    return "".join(out)


def decrypt(ciphertext: str, mapping: dict[str, str]) -> str:
    """Full decryption that keeps the original letter case."""
    mapping = validate_mapping(mapping)
    out = []
    for ch in ciphertext:
        up = ch.upper()
        if up in mapping:
            plain = mapping[up]
            out.append(plain if ch.isupper() else plain.lower())
        else:
            out.append(ch)
    return "".join(out)


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt with a key given as the 26-letter ciphertext alphabet (a->key[0], ...)."""
    key = key.upper()
    if sorted(key) != list(ALPHABET):
        raise ValueError("The key must be a permutation of the 26 letters A-Z.")
    table = dict(zip(ALPHABET, key))
    return "".join(
        (table[ch.upper()] if ch.isupper() else table[ch.upper()].lower())
        if ch.upper() in table else ch
        for ch in plaintext
    )


def key_from_mapping(mapping: dict[str, str]) -> str:
    """Ciphertext alphabet aligned under the plaintext alphabet ('?' = unknown)."""
    inverse = {plain: cipher for cipher, plain in validate_mapping(mapping).items()}
    return "".join(inverse.get(letter, "?") for letter in ALPHABET)


def text_bar_chart(freq: dict[str, float], width: int = 50, fmt: str = "{:6.2f}") -> str:
    """Simple horizontal bar chart for the console."""
    peak = max(freq.values()) or 1
    return "\n".join(
        f"{letter} {fmt.format(value)} {'#' * round(width * value / peak)}"
        for letter, value in freq.items()
    )
