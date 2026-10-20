"""Console version of Laboratory Work No. 3: asks again until every value is valid."""

import sys

from playfair import (
    KEY_MIN_LEN, build_matrix, decrypt_pairs, encrypt_pairs, key_letters, prepare_ciphertext,
    prepare_message, remove_fillers, split_pairs, transform_pair, validate_key,
)

RULE_CODE = {"rectangle": "RE", "row": "RO", "column": "CO"}


def ask(prompt, validator):
    while True:
        try:
            return validator(input(prompt))
        except ValueError as err:
            print(f"  Error: {err}\n")


def ask_choice(prompt, options):
    while True:
        choice = input(prompt).strip().lower()
        if choice in options:
            return choice
        print(f"  Error: please enter one of: {', '.join(options)}.\n")


def print_matrix(matrix):
    print("Encryption matrix:")
    for row in matrix.rows:
        print("  " + " ".join(f"{ch:>2}" for ch in row))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
    print("Playfair cipher - Romanian alphabet (31 letters, J = I, 5x6 matrix)")
    while True:
        op = ask_choice("\nOperation - (e)ncrypt, (d)ecrypt or e(x)it: ", ["e", "d", "x"])
        if op == "x":
            break
        key = ask(f"Key (at least {KEY_MIN_LEN} letters): ", validate_key)
        matrix = build_matrix(key)
        print(f"Key without repeated letters: {key_letters(key)}")
        print_matrix(matrix)
        if op == "e":
            text = ask("Message: ", prepare_message)
            pairs = split_pairs(text)
            result = encrypt_pairs(pairs, matrix)
        else:
            text = ask("Ciphertext: ", prepare_ciphertext)
            pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
            result = decrypt_pairs(pairs, matrix)
        rules = [transform_pair(p, matrix, 1 if op == "e" else -1)[1] for p in pairs]
        print(f"Prepared input: {text}")
        print("Pairs:          " + " ".join(pairs))
        print("Result pairs:   " + " ".join(result))
        print("Rules:          " + " ".join(RULE_CODE[r] for r in rules)
              + "   (RE = rectangle, RO = same row, CO = same column)")
        if op == "e":
            print(f"Ciphertext: {''.join(result)}")
        else:
            print(f"Decrypted message: {''.join(result)}")
            print(f"Without fillers (suggestion, check manually): {remove_fillers(''.join(result))}")
            print("Spaces between words are added manually.")


if __name__ == "__main__":
    main()
