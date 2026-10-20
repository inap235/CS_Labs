"""Checks of the Playfair implementation:  python Lab3/test_playfair.py"""

import random
import string
import sys

from playfair import (
    ALPHABET, MATRIX_ALPHABET, build_matrix, decrypt, decrypt_pairs, encrypt, encrypt_pairs,
    prepare_ciphertext, prepare_message, remove_fillers, split_pairs, transform_pair, validate_key,
)

# Example of section 3.2.3 of the guide (English alphabet, 5x5 matrix, J = I)
EN_ALPHABET = [c for c in string.ascii_uppercase if c != "J"]
GUIDE_PAIRS = """CO NG RE SX SZ SH AL LM MA KE NO LA WR ES PE CT IN GA NE ST AB
LI SH ME NT OF RE LI GI ON OR PR OH IB IT IN GT FR EX EZ EX ER CI
SE TH ER EO FO RA BR RI DG IN GT HE FR EX ED OM OF SP EX EC HO
RO FT HE PR ES SO RT HE RI GH TO FT HE PE OP LE PE AC EA BL YT
OA SX SE MB LE AN DT OP ET IT IO NT HE GO VE RN ME NT FO RA RE
DR ES SO FG RI EV AN CE SB""".split()
GUIDE_CIPHERTEXT = (
    "OWEHEGRYTYNQBVOAEMGDMQVBXINRXGKISMBEDNTFBLOFNQENDSLIEGOFCRQMPIXEQCFCRFSMKRISGRDXGRGEOMRNSK"
    "GEMPILFEGFSREKSMKRGNISGRNAWCLIRQGRMGCQIPIFGNXENRIQSFGNSRHKIUIFGNXGPQPAXGMBNMLVZSLMRYRNACPAM"
    "DKDPQDRRFMWDSGNCPXASEENDSILFEEGETNRIQRBSRAXMDGMFH"
)


def test_guide_matrix_and_ciphertext():
    m = build_matrix("FIRSTAMENDMENT", EN_ALPHABET, cols=5)
    assert ["".join(r) for r in m.rows] == ["FIRST", "AMEND", "BCGHK", "LOPQU", "VWXYZ"]
    assert transform_pair("NP", m, +1)[0] == "EQ"   # rectangle
    assert transform_pair("IT", m, +1)[0] == "RF"   # same row, wraps around
    assert transform_pair("CW", m, +1)[0] == "OI"   # same column, wraps around
    assert "".join(encrypt_pairs(GUIDE_PAIRS, m)) == GUIDE_CIPHERTEXT
    pairs = [GUIDE_CIPHERTEXT[i:i + 2] for i in range(0, len(GUIDE_CIPHERTEXT), 2)]
    assert decrypt_pairs(pairs, m) == GUIDE_PAIRS


def test_romanian_matrix():
    m = build_matrix(validate_key("criptografie"))
    assert (m.n_rows, m.n_cols) == (5, 6)
    flat = [ch for row in m.rows for ch in row]
    assert sorted(flat) == sorted(MATRIX_ALPHABET) and len(flat) == 30
    assert "".join(flat).startswith("CRIPTOGAFE")


def test_split_pairs():
    assert split_pairs("CONGRESSSHALL") == ["CO", "NG", "RE", "SX", "SQ", "SH", "AL", "LX"]
    assert split_pairs("XX") == ["XQ", "XQ"]
    assert split_pairs("Z") == ["ZX"]
    assert split_pairs("X") == ["XQ"]
    assert split_pairs("ȘȘȘ") == ["ȘX", "ȘQ", "ȘX"]


def test_roundtrip_romanian():
    key = "Țară frumoasă"
    msg = "Știința și tehnologia înaintează împreună în această țară"
    c = encrypt(msg, key)
    assert all(ch in MATRIX_ALPHABET for ch in c) and len(c) % 2 == 0
    p = decrypt(c, key)
    assert remove_fillers(p) == prepare_message(msg)


def test_random_roundtrip():
    rng = random.Random(3)
    for _ in range(500):
        key = "".join(rng.choices(ALPHABET, k=rng.randint(7, 15)))
        msg = "".join(rng.choices(MATRIX_ALPHABET, k=rng.randint(1, 60)))
        m = build_matrix(key)
        pairs = split_pairs(msg)
        assert all(a != b for a, b in pairs)
        c = "".join(encrypt_pairs(pairs, m))
        assert decrypt(c, key) == "".join(pairs)


def test_validation():
    for bad_key in ["scurt", "cheie123", "cheie-lungă"]:
        try:
            validate_key(bad_key)
        except ValueError:
            pass
        else:
            raise AssertionError(bad_key)
    for bad_text in ["", "abc1", "hello!", "ü"]:
        try:
            prepare_message(bad_text)
        except ValueError:
            pass
        else:
            raise AssertionError(bad_text)
    for bad_c in ["ABC", "AABC", "JABC"]:
        try:
            prepare_ciphertext(bad_c)
        except ValueError:
            pass
        else:
            raise AssertionError(bad_c)
    assert prepare_message("Jos  Ţara") == "IOSȚARA"


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"{len(tests)} tests passed")
