"""Laboratory Work No. 2 - variant 17.

Step-by-step frequency-analysis attack on the intercepted ciphertext
(ciphertext.txt), reproducing the process from section 2.3.


"""

import sys
from pathlib import Path

from frequency_analysis import (
    ALPHABET, ENGLISH_FREQ, apply_mapping, decrypt, encrypt, key_from_mapping,
    letter_counts, letter_percentages, ngram_counts, sorted_by_frequency,
    text_bar_chart, word_counts,
)

HERE = Path(__file__).parent
CIPHERTEXT = (HERE / "ciphertext.txt").read_text(encoding="utf-8").strip()

# Each step: (explanation, {cipher letter: plain letter} added in this step)
STEPS = [
    (
        "The most frequent ciphertext letters are 'V' (272) and 'W' (186). In English the most "
        "frequent letters are 'e' (12.70%) and 't' (9.06%), so we assume V -> e and W -> t.",
        {"V": "e", "W": "t"},
    ),
    (
        "The 3-letter word 'tQe' appears very often in the text. The most common 3-letter word in "
        "English is 'the', so Q -> h.",
        {"Q": "h"},
    ),
    (
        "The 2-letter word 'tN' is very frequent - it can only be 'to', so N -> o. "
        "The frequent word 'oC' must then be 'of', so C -> f.",
        {"N": "o", "C": "f"},
    ),
    (
        "The third most frequent letter is 'T' (168) and it also appears as a one-letter word. "
        "The only one-letter words in English are 'a' and 'I'; 'thTt' becomes 'that', so T -> a.",
        {"T": "a"},
    ),
    (
        "The words 'Xt', 'XG' and 'thXP' are frequent: they are 'it', 'in' and 'this'. "
        "So X -> i, G -> n, P -> s. 'aGO' (and) gives O -> d.",
        {"X": "i", "G": "n", "P": "s", "O": "d"},
    ),
    (
        "The first sentence now begins 'had the UIesident IeHoZZended his oRn sFsteZ'. "
        "'UIesident' is 'President' (U -> p, I -> r), 'IeHoZZended' is 'recommended' "
        "(H -> c, Z -> m), 'oRn' is 'own' (R -> w) and 'sFsteZ' is 'system' (F -> y).",
        {"U": "p", "I": "r", "H": "c", "Z": "m", "R": "w", "F": "y"},
    ),
    (
        "'woDSd' appears several times: it is 'would' (D -> u, S -> l). "
        "'SiArary of conJress' is 'Library of Congress' (A -> b).",
        {"D": "u", "S": "l", "A": "b"},
    ),
    (
        "'deKice' is 'device' (K -> v), 'conJress' is 'Congress' (J -> g) and "
        "'Eames madison' is 'James Madison' (E -> j).",
        {"K": "v", "J": "g", "E": "j"},
    ),
    (
        "The remaining letters: 'Lnighted' -> 'knighted' (L -> k), 'Bueen victoria' -> "
        "'Queen Victoria' (B -> q), 'eYperiments' -> 'experiments' (Y -> x) and "
        "'populariMed' -> 'popularized' (M -> z).",
        {"L": "k", "B": "q", "Y": "x", "M": "z"},
    ),
]


def frequency_table(freq: dict, fmt: str) -> str:
    letters = list(freq)
    head = "| Letter | " + " | ".join(letters) + " |"
    sep = "|---" * (len(letters) + 1) + "|"
    row = "| Frequency | " + " | ".join(fmt.format(freq[l]) for l in letters) + " |"
    return "\n".join([head, sep, row])


def build_report() -> str:
    out = []
    counts = letter_counts(CIPHERTEXT)
    percents = letter_percentages(CIPHERTEXT)

    out.append("# Laboratory Work No. 2 - Variant 17\n")
    out.append("## Intercepted ciphertext\n")
    out.append(CIPHERTEXT + "\n")

    out.append(f"## Step 0. Letter frequencies in the ciphertext (total letters: {sum(counts.values())})\n")
    out.append(frequency_table(counts, "{}") + "\n")
    out.append("Sorted in decreasing order of frequency:\n")
    out.append(frequency_table(dict(sorted_by_frequency(counts)), "{}") + "\n")
    out.append("English letter frequencies (Table 2.2), sorted:\n")
    out.append(frequency_table(dict(sorted_by_frequency(ENGLISH_FREQ)), "{:.2f}") + "\n")
    out.append("```\nCiphertext (%)\n" + text_bar_chart(percents) + "\n\nEnglish (%)\n"
               + text_bar_chart(ENGLISH_FREQ) + "\n```\n")
    out.append("Most frequent ciphertext 3-letter words: "
               + ", ".join(f"{w} ({n})" for w, n in word_counts(CIPHERTEXT, 3, 8)) + "  ")
    out.append("Most frequent ciphertext 2-letter words: "
               + ", ".join(f"{w} ({n})" for w, n in word_counts(CIPHERTEXT, 2, 8)) + "  ")
    out.append("Most frequent ciphertext digraphs: "
               + ", ".join(f"{g} ({n})" for g, n in ngram_counts(CIPHERTEXT, 2, 10)) + "  ")
    out.append("Most frequent ciphertext trigraphs: "
               + ", ".join(f"{g} ({n})" for g, n in ngram_counts(CIPHERTEXT, 3, 10)) + "\n")

    mapping = {}
    for number, (explanation, pairs) in enumerate(STEPS, start=1):
        mapping.update(pairs)
        subs = ", ".join(f"{c} -> {p}" for c, p in pairs.items())
        out.append(f"## Step {number}. {subs}\n")
        out.append(explanation + "\n")
        out.append(f"Known letters so far: {len(mapping)}/26\n")
        out.append("```\n" + apply_mapping(CIPHERTEXT, mapping) + "\n```\n")

    assert len(mapping) == 26, "every ciphertext letter must be decrypted"
    plaintext = decrypt(CIPHERTEXT, mapping)
    key = key_from_mapping(mapping)
    assert encrypt(plaintext, key) == CIPHERTEXT, "re-encryption must give back the ciphertext"

    out.append("## Recovered plaintext\n")
    out.append(plaintext + "\n")
    out.append("## Recovered key (Table 2.5 for variant 17)\n")
    out.append("| Plaintext alphabet | " + " | ".join(ALPHABET.lower()) + " |")
    out.append("|---" * 27 + "|")
    out.append("| Ciphertext alphabet | " + " | ".join(key) + " |\n")
    out.append(f"Key as a string: `{key}`  ")
    out.append("Check: re-encrypting the plaintext with this key gives exactly the ciphertext.\n")
    return "\n".join(out)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    report = build_report()
    print(report)
    if "--save" in sys.argv:
        path = HERE / "attack_output.md"
        path.write_text(report, encoding="utf-8")
        print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
