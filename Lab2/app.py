#Streamlit interface    .\.venv\Scripts\Activate.ps1   then   streamlit run Lab2\app.py

import pandas as pd
import streamlit as st

from attack import CIPHERTEXT, STEPS
from auto_solver import describe_swap, load_english_model, real_word_ratio, solve
from frequency_analysis import (
    ALPHABET, ENGLISH_FREQ, apply_mapping, decrypt, key_from_mapping,
    letter_counts, letter_percentages, ngram_counts, sorted_by_frequency,
    validate_mapping, word_counts,
)

st.set_page_config(page_title="Frequency Analysis - Lab 2", page_icon="🔎", layout="wide")


def show_table(df):
    """Narrow columns so that all 26 letters fit on screen."""
    cols = {c: st.column_config.Column(width=34) for c in df.columns}
    st.dataframe(df, column_config=cols)


@st.cache_resource
def english_model():
    return load_english_model()


def freq_row(freq, label, fmt="{:.2f}"):
    return pd.DataFrame([[fmt.format(v) for v in freq.values()]], index=[label], columns=list(freq))


st.title("🔎 Cryptanalysis of Monoalphabetic Ciphers")
st.caption("Laboratory Work No. 2 · Variant 17 · frequency-analysis attack (English)")

tab1, tab2, tab3, tab4 = st.tabs(["Frequencies", "Interactive breaking", "Step-by-step attack (V17)", "Automatic solver"])

# ---------------------------------------------------------------- Frequencies
with tab1:
    text = st.text_area("Ciphertext", CIPHERTEXT, height=200, key="freq_text")
    counts = letter_counts(text)
    st.subheader(f"Letter frequencies (total letters: {sum(counts.values())})")
    show_table(freq_row(counts, "Count", "{}"))
    show_table(freq_row(dict(sorted_by_frequency(counts)), "Sorted", "{}"))
    show_table(freq_row(dict(sorted_by_frequency(ENGLISH_FREQ)), "English %"))

    chart = pd.DataFrame(
        {"Ciphertext %": letter_percentages(text), "English %": ENGLISH_FREQ}
    )
    left, right = st.columns(2)
    left.bar_chart(chart["English %"], color="#4e79a7")
    right.bar_chart(chart["Ciphertext %"], color="#c0504d")

    c1, c2, c3, c4 = st.columns(4)
    c1.write("**3-letter words**")
    c1.dataframe(pd.DataFrame(word_counts(text, 3, 10), columns=["Word", "Count"]), hide_index=True)
    c2.write("**2-letter words**")
    c2.dataframe(pd.DataFrame(word_counts(text, 2, 10), columns=["Word", "Count"]), hide_index=True)
    c3.write("**Digraphs**")
    c3.dataframe(pd.DataFrame(ngram_counts(text, 2, 10), columns=["Digraph", "Count"]), hide_index=True)
    c4.write("**Trigraphs**")
    c4.dataframe(pd.DataFrame(ngram_counts(text, 3, 10), columns=["Trigraph", "Count"]), hide_index=True)

# ---------------------------------------------------------------- Interactive breaking
with tab2:
    text = st.text_area("Ciphertext", CIPHERTEXT, height=150, key="break_text")
    order = [letter for letter, _ in sorted_by_frequency(letter_counts(text))]
    st.write("Type the plaintext letter under each ciphertext letter (sorted by frequency). "
             "Decrypted letters are shown in lowercase, unknown ones stay UPPERCASE.")

    mapping = {}
    for row in range(0, 26, 13):
        cols = st.columns(13)
        for col, cipher in zip(cols, order[row:row + 13]):
            plain = col.text_input(cipher, max_chars=1, key=f"map_{cipher}").strip()
            if plain:
                mapping[cipher] = plain

    try:
        mapping = validate_mapping(mapping)
    except ValueError as err:
        st.error(str(err))
    else:
        st.info(f"Known letters: {len(mapping)}/26 · key: `{key_from_mapping(mapping)}`")
        st.code(apply_mapping(text, mapping), language=None, wrap_lines=True)

# ---------------------------------------------------------------- Step-by-step attack
with tab3:
    step = st.slider("Step", 0, len(STEPS), len(STEPS))
    mapping = {}
    for explanation, pairs in STEPS[:step]:
        mapping.update(pairs)
    for number, (explanation, pairs) in enumerate(STEPS[:step], start=1):
        subs = ", ".join(f"{c} → {p}" for c, p in pairs.items())
        st.markdown(f"**Step {number}.** `{subs}` — {explanation}")
    st.code(apply_mapping(CIPHERTEXT, mapping), language=None, wrap_lines=True)

    if len(mapping) == 26:
        key = key_from_mapping(mapping)
        st.success("**Recovered plaintext:**\n\n" + decrypt(CIPHERTEXT, mapping))
        st.subheader("Recovered key (Table 2.5)")
        show_table(pd.DataFrame([list(ALPHABET.lower()), list(key)],
                                index=["Plaintext", "Ciphertext"], columns=list(ALPHABET)))

# ---------------------------------------------------------------- Automatic solver
with tab4:
    st.write("The program finds the key by itself: it starts from the frequency key (most frequent letter → E, "
             "second → T, ...) and keeps swapping two letters of the key whenever the swap makes the text look "
             "more like English. *Fitness* = sum of log₁₀ probabilities of all 3-letter groups (trigrams) of the "
             "text, learned from the 20,000 most frequent English words - higher means more English-like.")
    text = st.text_area("Ciphertext", CIPHERTEXT, height=150, key="auto_text")
    restarts = st.number_input("Restarts (random shakes of the best key)", 0, 50, 10)
    if st.button("Solve automatically", type="primary"):
        model = english_model()
        with st.spinner("Hill climbing..."):
            result = solve(text, model, restarts=int(restarts))
        start_text = decrypt(text, result.start_mapping)
        plaintext = decrypt(text, result.mapping)

        st.subheader("1. Start: frequency key")
        c1, c2 = st.columns(2)
        c1.metric("Fitness", f"{result.start_score:.0f}")
        c2.metric("Real English words", f"{real_word_ratio(start_text, model):.0f}%")
        st.code(apply_mapping(text, result.start_mapping)[:600] + " ...", language=None, wrap_lines=True)

        st.subheader(f"2. Hill climbing: {len(result.swaps)} swaps improved the text")
        st.line_chart(pd.DataFrame({"Fitness": [result.start_score] + [s.score for s in result.swaps]}),
                      x_label="Accepted swap", y_label="Fitness")
        st.dataframe(pd.DataFrame([{"#": s.number, "Swap": describe_swap(s), "Fitness": round(s.score)}
                                   for s in result.swaps]), hide_index=True, height=250)
        st.caption(f"Best fitness after each restart: {[round(s) for s in result.restarts]} · "
                   f"keys tried: {result.evaluations}")

        st.subheader("3. Result")
        c1, c2 = st.columns(2)
        c1.metric("Fitness", f"{result.score:.0f}", f"{result.score - result.start_score:+.0f}")
        c2.metric("Real English words", f"{real_word_ratio(plaintext, model):.0f}%")
        st.success(plaintext)
        key = key_from_mapping(result.mapping)
        show_table(pd.DataFrame([list(ALPHABET.lower()), list(key)],
                                index=["Plaintext", "Ciphertext"], columns=list(ALPHABET)))
        if text.strip() == CIPHERTEXT:
            manual = {}
            for _, pairs in STEPS:
                manual.update(pairs)
            same = sum(result.mapping[c].lower() == manual[c] for c in ALPHABET)
            st.info(f"Comparison with the manual step-by-step attack: {same}/26 letters are the same.")
