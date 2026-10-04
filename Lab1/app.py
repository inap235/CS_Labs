#Streamlit interface

import pandas as pd
import streamlit as st

from caesar import (
    ALPHABET, KEY_MAX, KEY_MIN, KEYWORD_MIN_LEN, N,
    decrypt, encrypt, permuted_alphabet, prepare_text, validate_key, validate_keyword,
)

st.set_page_config(page_title="Caesar Cipher - Lab 1", page_icon="🔐", layout="wide")


def mapping_table(alphabet, key):
    """Plain alphabet row, its codes and the shifted (cipher) alphabet row."""
    n = len(alphabet)
    return pd.DataFrame(
        [list(range(n)), alphabet, [(i + key) % n for i in range(n)],
         [alphabet[(i + key) % n] for i in range(n)]],
        index=["x", "m", "x+k", "c"],
        columns=[str(i) for i in range(n)],
    )


def show_table(df):
    """Narrow columns so that all 31 positions fit on screen."""
    cols = {c: st.column_config.Column(width=34) for c in df.columns}
    st.dataframe(df, column_config=cols)


def show_result(op, text, result):
    st.text_input("Prepared input (uppercase, no spaces)", text, disabled=True)
    label = "Ciphertext" if op == "Encrypt" else "Decrypted message"
    st.success(f"**{label}:** `{result}`")


st.title("🔐 Caesar Cipher - Romanian Alphabet")
st.caption(f"Laboratory Work No. 1 · n = {N} letters · A = 0, Ă = 1, …, Z = 30")

with st.expander("Letter encoding (Table 2)"):
    show_table(pd.DataFrame([ALPHABET], index=["Letter"], columns=[str(i) for i in range(N)]))

tab1, tab2, tab3 = st.tabs(["Task 1.1 - Caesar cipher", "Task 1.2 - Caesar with keyword", "Brute-force attack"])

# ---------------------------------------------------------------- Task 1.1
with tab1:
    with st.form("task11"):
        op = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True, key="op1")
        raw_key = st.text_input(f"Key k (integer {KEY_MIN}-{KEY_MAX})", "3", key="k1")
        raw_text = st.text_area("Message / ciphertext", "cifrul cezar", key="t1")
        submitted = st.form_submit_button("Run", type="primary")
    if submitted:
        errors = []
        try:
            key = validate_key(raw_key)
        except ValueError as err:
            errors.append(str(err))
        try:
            text = prepare_text(raw_text)
        except ValueError as err:
            errors.append(str(err))
        for e in errors:
            st.error(e)
        if errors:
            st.info("Please correct the value(s) above and press **Run** again.")
        else:
            result = encrypt(text, key) if op == "Encrypt" else decrypt(text, key)
            show_result(op, text, result)
            st.markdown("**Substitution table**")
            show_table(mapping_table(ALPHABET, key))

# ---------------------------------------------------------------- Task 1.2
with tab2:
    with st.form("task12"):
        op2 = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True, key="op2")
        c1, c2 = st.columns(2)
        raw_key2 = c1.text_input(f"Key 1 - shift (integer {KEY_MIN}-{KEY_MAX})", "3", key="k2")
        raw_kw = c2.text_input(f"Key 2 - keyword (at least {KEYWORD_MIN_LEN} Romanian letters)",
                               "criptografie", key="kw")
        raw_text2 = st.text_area("Message / ciphertext", "cifrul cezar", key="t2")
        submitted2 = st.form_submit_button("Run", type="primary")
    if submitted2:
        errors = []
        for validator, raw in ((validate_key, raw_key2), (validate_keyword, raw_kw), (prepare_text, raw_text2)):
            try:
                validator(raw)
            except ValueError as err:
                errors.append(str(err))
        for e in errors:
            st.error(e)
        if errors:
            st.info("Please correct the value(s) above and press **Run** again.")
        else:
            key, keyword, text = validate_key(raw_key2), validate_keyword(raw_kw), prepare_text(raw_text2)
            perm = permuted_alphabet(keyword)
            st.markdown(f"**Permuted alphabet** (keyword `{keyword}` → distinct letters "
                        f"`{''.join(dict.fromkeys(keyword))}` + remaining letters)")
            st.code(" ".join(perm), language=None)
            result = encrypt(text, key, perm) if op2 == "Encrypt" else decrypt(text, key, perm)
            show_result(op2, text, result)
            st.markdown("**Substitution table** (codes are positions in the permuted alphabet)")
            show_table(mapping_table(perm, key))


with tab3:
    st.write(f"With only {KEY_MAX} possible keys, the plain Caesar cipher is broken by trying all of them. "
             "Exactly one line should be readable Romanian text.")
    raw_c = st.text_input("Ciphertext", "FKITXOFHÂBT", key="bf")
    if raw_c:
        try:
            c = prepare_text(raw_c)
            st.dataframe(pd.DataFrame({"k": range(KEY_MIN, KEY_MAX + 1),
                                       "candidate plaintext": [decrypt(c, k) for k in range(KEY_MIN, KEY_MAX + 1)]}),
                         hide_index=True, height=1100,
                         column_config={"k": st.column_config.Column(width=60)})
        except ValueError as err:
            st.error(str(err))
