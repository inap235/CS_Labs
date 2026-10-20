"""Automatic solver for a monoalphabetic substitution cipher 

  1. English model - from a list of the 20,000 most frequent English words
     (english_words.txt) the program learns how often every group of
     3 letters (trigram) appears in English, e.g. THE, AND, ING.
     "_" marks the start / end of a word, so "_TH" means a word starting with TH.
  2. Fitness - a number that says how much a text looks like English:
     the sum of log10(probability) of all its trigrams. Real English gets a high
     (less negative) score; gibberish such as "QXZ" gets a very low one.
  3. Start key - the frequency attack: the most frequent ciphertext letter -> E,
     the second -> T, ... (English order E T A O I N S H R D L ...).
  4. Hill climbing - try to swap the plaintext letters of two ciphertext letters.
     If the decrypted text gets a better fitness, keep the swap, otherwise undo it.
     Repeat until no swap of any pair improves the text.
  5. Restarts - to be sure it is not stuck in a "local maximum", start again
     several times from the best key with a few random swaps; keep the best key.

Run:  python auto_solver.py
"""

import math
import random
import sys
from collections import Counter
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path

from frequency_analysis import (
    ALPHABET, ENGLISH_FREQ, apply_mapping, decrypt, encrypt, key_from_mapping,
    letter_counts, sorted_by_frequency,
)

HERE = Path(__file__).parent
WORDS_FILE = HERE / "english_words.txt"


# ---------------------------------------------------------------- 1. English model
@dataclass
class EnglishModel:
    log_prob: dict[str, float]  # trigram -> log10(probability)
    floor: float                # score of a trigram never seen in English
    words: set[str]             # dictionary, used only to report "% of real words"


def load_english_model(path: Path = WORDS_FILE) -> EnglishModel:
    """Count trigrams in the English word list, weighted by how often each word is used."""
    counts = Counter()
    words = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        word, freq = line.split()
        words.add(word.upper())
        padded = f"_{word.upper()}_"
        for i in range(len(padded) - 2):
            counts[padded[i:i + 3]] += int(freq)
    total = sum(counts.values())
    log_prob = {gram: math.log10(n / total) for gram, n in counts.items()}
    return EnglishModel(log_prob, math.log10(0.01 / total), words)


# ---------------------------------------------------------------- 2. Fitness
def text_words(text: str) -> list[str]:
    """Words of the text: only letters, uppercase."""
    return "".join(ch if ch.isalpha() else " " for ch in text.upper()).split()


def trigram_counts(text: str) -> Counter:
    """Trigrams of the text, counted once, so every key can be scored quickly."""
    counts = Counter()
    for word in text_words(text):
        padded = f"_{word}_"
        counts.update(padded[i:i + 3] for i in range(len(padded) - 2))
    return counts


def fitness(cipher_trigrams: Counter, mapping: dict[str, str], model: EnglishModel) -> float:
    """How English-like the decryption with this key is (higher = better)."""
    table = str.maketrans(mapping)
    return sum(n * model.log_prob.get(gram.translate(table), model.floor)
               for gram, n in cipher_trigrams.items())


def real_word_ratio(text: str, model: EnglishModel) -> float:
    """Percent of the words of the text that are English dictionary words."""
    words = text_words(text)
    return 100 * sum(w in model.words for w in words) / (len(words) or 1)


# ---------------------------------------------------------------- 3. Start key
def frequency_key(ciphertext: str) -> dict[str, str]:
    """Most frequent ciphertext letter -> E, second -> T, ... (pure frequency attack)."""
    cipher_order = [letter for letter, _ in sorted_by_frequency(letter_counts(ciphertext))]
    english_order = [letter for letter, _ in sorted_by_frequency(ENGLISH_FREQ)]
    return dict(zip(cipher_order, english_order))


# ---------------------------------------------------------------- 4. Hill climbing
@dataclass
class Swap:
    number: int
    cipher_a: str
    cipher_b: str
    old_a: str
    old_b: str
    score: float


@dataclass
class SolveResult:
    start_mapping: dict[str, str]
    start_score: float
    mapping: dict[str, str]
    score: float
    swaps: list[Swap] = field(default_factory=list)       # accepted swaps of the first climb
    restarts: list[float] = field(default_factory=list)   # best score after each restart
    evaluations: int = 0


def hill_climb(cipher_trigrams, mapping, model, swaps=None):
    """Swap pairs of letters while the fitness improves. Returns (mapping, score, evaluations)."""
    mapping = dict(mapping)
    best = fitness(cipher_trigrams, mapping, model)
    evaluations = 1
    improved = True
    while improved:
        improved = False
        for a, b in combinations(ALPHABET, 2):
            mapping[a], mapping[b] = mapping[b], mapping[a]
            score = fitness(cipher_trigrams, mapping, model)
            evaluations += 1
            if score > best:
                best = score
                improved = True
                if swaps is not None:
                    swaps.append(Swap(len(swaps) + 1, a, b, mapping[b], mapping[a], score))
            else:
                mapping[a], mapping[b] = mapping[b], mapping[a]  # undo
    return mapping, best, evaluations


# ---------------------------------------------------------------- 5. Solver with restarts
def solve(ciphertext: str, model: EnglishModel | None = None, restarts: int = 10, seed: int = 17) -> SolveResult:
    model = model or load_english_model()
    grams = trigram_counts(ciphertext)
    start = frequency_key(ciphertext)
    result = SolveResult(start, fitness(grams, start, model), start, 0.0)

    mapping, score, result.evaluations = hill_climb(grams, start, model, result.swaps)
    rng = random.Random(seed)
    for _ in range(restarts):
        shaken = dict(mapping)
        for _ in range(rng.randint(2, 5)):  # a few random swaps to leave a possible local maximum
            a, b = rng.sample(ALPHABET, 2)
            shaken[a], shaken[b] = shaken[b], shaken[a]
        candidate, candidate_score, n = hill_climb(grams, shaken, model)
        result.evaluations += n
        if candidate_score > score:
            mapping, score = candidate, candidate_score
        result.restarts.append(score)

    result.mapping, result.score = mapping, score
    return result


def describe_swap(swap: Swap) -> str:
    return (f"{swap.cipher_a}: {swap.old_a.lower()} -> {swap.old_b.lower()}, "
            f"{swap.cipher_b}: {swap.old_b.lower()} -> {swap.old_a.lower()}")


# ---------------------------------------------------------------- console
def main():
    sys.stdout.reconfigure(encoding="utf-8")
    from attack import CIPHERTEXT, STEPS

    model = load_english_model()
    print(f"1. English model: {len(model.log_prob)} different trigrams learned from "
          f"{len(model.words)} English words\n")

    result = solve(CIPHERTEXT, model)
    start_text = decrypt(CIPHERTEXT, result.start_mapping)
    print("2. Start key from letter frequencies (cipher -> plain):")
    print("   " + ", ".join(f"{c}->{p.lower()}" for c, p in result.start_mapping.items()))
    print(f"   fitness = {result.start_score:.0f}, real English words = {real_word_ratio(start_text, model):.0f}%")
    print("   " + start_text[:150] + "...\n")

    print(f"3. Hill climbing - {len(result.swaps)} swaps improved the text:")
    for swap in result.swaps:
        print(f"   {swap.number:3}. {describe_swap(swap):30}  fitness = {swap.score:.0f}")
    print(f"\n4. Restarts: best fitness after each restart = {[round(s) for s in result.restarts]}")
    print(f"   keys tried in total: {result.evaluations}\n")

    plaintext = decrypt(CIPHERTEXT, result.mapping)
    key = key_from_mapping(result.mapping)
    print(f"5. Result: fitness = {result.score:.0f}, real English words = {real_word_ratio(plaintext, model):.0f}%")
    print("   Plaintext:  " + ALPHABET.lower())
    print("   Ciphertext: " + key)
    print()
    print(plaintext)

    manual = {}
    for _, pairs in STEPS:
        manual.update({c: p.upper() for c, p in pairs.items()})
    same = sum(result.mapping[c] == manual[c] for c in ALPHABET)
    print(f"\nComparison with the manual attack: {same}/26 letters are the same.")
    print("Check: re-encrypting the plaintext gives the ciphertext:", encrypt(plaintext, key) == CIPHERTEXT)


if __name__ == "__main__":
    main()
