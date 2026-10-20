"""Checks of the DES implementation:  python Lab4/test_des.py"""

import random
import sys

from des import (
    E, P, decrypt_block, encrypt_block, f, group, hex_to_bits, key_plus, parse_bits, parse_block,
    permute, round_keys, sbox, sboxes, to_hex, xor,
)
from tasks import TASKS, run


def nospace(s):
    return s.replace(" ", "")


# Values of the worked example in "Theory of DES" (J. O. Grabbe)
KEY = hex_to_bits("133457799BBCDFF1")
MSG = hex_to_bits("0123456789ABCDEF")


def test_grabbe_example():
    kplus = key_plus(KEY)
    assert kplus == nospace("1111000 0110011 0010101 0101111 0101010 1011001 1001111 0001111")
    keys = round_keys(kplus)
    assert keys[0] == nospace("000110 110000 001011 101111 111111 000111 000001 110010")
    assert keys[15] == nospace("110010 110011 110110 001011 000011 100001 011111 110101")
    r0 = nospace("1111 0000 1010 1010 1111 0000 1010 1010")
    b = xor(keys[0], permute(r0, E))
    assert b == nospace("011000 010001 011110 111010 100001 100110 010100 100111")
    assert sboxes(b) == nospace("0101 1100 1000 0010 1011 0101 1001 0111")
    assert f(r0, keys[0]) == nospace("0010 0011 0100 1010 1010 1001 1011 1011")
    assert to_hex(encrypt_block(MSG, KEY)) == "85E813540F0AB405"
    assert decrypt_block(encrypt_block(MSG, KEY), KEY) == MSG


def test_other_vectors():
    # FIPS / well-known test vectors
    assert to_hex(encrypt_block(hex_to_bits("8787878787878787"), hex_to_bits("0E329232EA6D0D73"))) == "0000000000000000"
    assert to_hex(encrypt_block(hex_to_bits("0000000000000000"), hex_to_bits("0000000000000000"))) == "8CA64DE9C1B123A7"


def test_sbox_lookup():
    assert sbox(1, "011011") == (1, 13, 5, "0101")   # example of the guide: row 01, column 1101


def test_parsing():
    assert parse_block("ABCDEFGH", "key")[0] == "".join(f"{ord(c):08b}" for c in "ABCDEFGH")
    assert parse_block("13 34 57 79 9B BC DF F1", "key")[0] == KEY
    assert parse_bits("F0AA F0AA", 32, "R") == hex_to_bits("F0AAF0AA")
    for bad in ("short", "ABCDEFGHI", "ĂBCDEFGH"):
        try:
            parse_block(bad, "key")
        except ValueError:
            continue
        raise AssertionError(bad)


def test_roundtrip_random():
    for _ in range(50):
        k = "".join(random.choice("01") for _ in range(64))
        m = "".join(random.choice("01") for _ in range(64))
        assert decrypt_block(encrypt_block(m, k), k) == m


def test_all_tasks_run():
    for task in TASKS:
        steps = run(task, {fl.name: fl.default for fl in task.fields})
        assert steps
        for _ in range(5):
            run(task, {fl.name: fl.random() for fl in task.fields})
    ans = {t.number: run(t, {fl.name: fl.default for fl in t.fields})[-1] for t in TASKS}
    assert ans["2.11"].value == "85E813540F0AB405"
    assert nospace(ans["2.8"].value).startswith(nospace("1110 1111 0100 1010 0110 0101 0100 0100"))
    assert "0101" == ans["2.9"].value[:4]   # S1(B1) with B1 = 011000 -> 5
    one_round = run(TASKS[-1], {"message": "0123456789ABCDEF", "i": "1", "key": "133457799BBCDFF1"})
    assert one_round[-1].value == to_hex(encrypt_block(parse_block("01234567", "m")[0], KEY, rounds=1))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"OK  {name}")
    print("All checks passed.")
