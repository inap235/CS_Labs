#Streamlit interface    .\.venv\Scripts\Activate.ps1   streamlit run Lab3/app.py

import pandas as pd
import streamlit as st

from playfair import (
    COLS, FILLERS, KEY_MIN_LEN, PAD, ROWS, build_matrix, decrypt_pairs, encrypt_pairs, key_letters,
    prepare_ciphertext, prepare_message, remove_fillers, split_pairs, transform_pair, validate_key,
)

st.set_page_config(page_title="Playfair Cipher - Lab 3", page_icon="🔐", layout="wide")

RULE_TEXT = {
    "rectangle": "different row and column → same row, column of the other letter",
    "row": "same row → letter to the right",
    "column": "same column → letter below",
}
RULE_TEXT_DEC = {
    "rectangle": RULE_TEXT["rectangle"],
    "row": "same row → letter to the left",
    "column": "same column → letter above",
}


def matrix_frame(matrix, highlight=""):
    df = pd.DataFrame(matrix.rows, index=[str(i) for i in range(matrix.n_rows)],
                      columns=[str(i) for i in range(matrix.n_cols)])

    def color(ch):
        return "background-color: #ffe08a; font-weight: bold" if ch in highlight else ""

    return df.style.map(color)


def pairs_frame(pairs, result, matrix, direction):
    texts = RULE_TEXT if direction > 0 else RULE_TEXT_DEC
    rules = [transform_pair(p, matrix, direction)[1] for p in pairs]
    return pd.DataFrame({
        "#": range(1, len(pairs) + 1),
        "pair": pairs,
        "rule": [texts[r] for r in rules],
        "result": result,
    })


st.title("🔐 Playfair Cipher - Romanian Alphabet")
st.caption(f"Laboratory Work No. 3 · Task 3.1 · 31 letters, J is written as I · "
           f"{ROWS}×{COLS} matrix · key ≥ {KEY_MIN_LEN} letters")

with st.form("playfair"):
    op = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True)
    raw_key = st.text_input(f"Key (at least {KEY_MIN_LEN} letters, spaces are removed)", "criptografie")
    raw_text = st.text_area("Message / ciphertext", "Atacul începe la ora cinci")
    submitted = st.form_submit_button("Run", type="primary")
if submitted:
    errors = []
    prepare = prepare_message if op == "Encrypt" else prepare_ciphertext
    for validator, raw in ((validate_key, raw_key), (prepare, raw_text)):
        try:
            validator(raw)
        except ValueError as err:
            errors.append(str(err))
    for e in errors:
        st.error(e)
    if errors:
        st.info("Please correct the value(s) above and press **Run** again.")
    else:
        key, text = validate_key(raw_key), prepare(raw_text)
        matrix = build_matrix(key)
        c1, c2 = st.columns([1, 2])
        with c1:
            st.markdown(f"**Key** `{key}` → without repeated letters `{key_letters(key)}`")
            st.markdown("**Encryption matrix**")
            st.dataframe(matrix_frame(matrix, key_letters(key)))
        with c2:
            st.text_input("Prepared input (uppercase, no spaces, J → I)", text, disabled=True)
            if op == "Encrypt":
                pairs = split_pairs(text)
                result = encrypt_pairs(pairs, matrix)
                st.markdown(f"**Pairs** (filler {' / '.join(FILLERS)} between identical letters, "
                            f"{PAD} added to an odd length)")
            else:
                pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
                result = decrypt_pairs(pairs, matrix)
                st.markdown("**Pairs**")
            st.code(" ".join(pairs), language=None)
            if op == "Encrypt":
                st.success(f"**Ciphertext:** `{''.join(result)}`")
            else:
                plain = "".join(result)
                st.success(f"**Decrypted message:** `{plain}`")
                st.markdown("**Manual phase** - remove the filler letters and add the spaces:")
                st.text_input("Suggestion without fillers (edit it)", remove_fillers(plain))
        st.markdown("**Pair by pair**")
        st.dataframe(pairs_frame(pairs, result, matrix, 1 if op == "Encrypt" else -1),
                     hide_index=True, use_container_width=True,
                     height=min(35 * (len(pairs) + 1) + 3, 800),
                     column_config={"#": st.column_config.Column(width=50)})
