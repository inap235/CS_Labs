"""Console version of Laboratory Work No. 1: asks again until every value is valid."""

import sys

from caesar import (
    decrypt, encrypt, permuted_alphabet, prepare_text, validate_key, validate_keyword,
)


def ask(prompt, validator):
    while True:
        try:
            return validator(input(prompt))
        except ValueError as err:
            print(f"  Error: {err}\n")


def ask_choice(prompt, options):
    while True:
        choice = input(prompt).strip()
        if choice in options:
            return choice
        print(f"  Error: please enter one of: {', '.join(options)}.\n")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
    print("Caesar cipher - Romanian alphabet (n = 31)")
    while True:
        print("\n1) Caesar cipher (Task 1.1)\n2) Caesar cipher with keyword (Task 1.2)\n0) Exit")
        task = ask_choice("Task: ", ["0", "1", "2"])
        if task == "0":
            break
        op = ask_choice("Operation - (e)ncrypt or (d)ecrypt: ", ["e", "d"])
        key = ask("Key 1 (integer 1..30): ", validate_key)
        alphabet = None
        if task == "2":
            keyword = ask("Key 2 - keyword (min. 7 Romanian letters): ", validate_keyword)
            alphabet = permuted_alphabet(keyword)
            print("Permuted alphabet:")
            print("  " + " ".join(f"{i:>2}" for i in range(len(alphabet))))
            print("  " + " ".join(f"{c:>2}" for c in alphabet))
        label = "Message" if op == "e" else "Ciphertext"
        text = ask(f"{label}: ", prepare_text)
        func = encrypt if op == "e" else decrypt
        result = func(text, key, alphabet) if alphabet else func(text, key)
        print(f"Prepared input: {text}")
        print(f"{'Ciphertext' if op == 'e' else 'Decrypted message'}: {result}")


if __name__ == "__main__":
    main()
