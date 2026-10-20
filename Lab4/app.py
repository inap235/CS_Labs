#Streamlit interface    .\.venv\Scripts\Activate.ps1   streamlit run Lab4/app.py

import pandas as pd
import streamlit as st

from des import table_rows
from tasks import TASKS, run

st.set_page_config(page_title="DES - Lab 4", page_icon="🔐", layout="wide")

st.title("🔐 Block ciphers - the DES algorithm")
st.caption("Laboratory Work No. 4 · task number = n mod 11 · the example values are those of "
           "\"Theory of DES\": key 133457799BBCDFF1, message 0123456789ABCDEF → 85E813540F0AB405")

labels = [f"{t.number} - {t.title}" for t in TASKS]
idx = st.selectbox("Task", range(len(TASKS)), index=5, format_func=lambda i: labels[i])
task = TASKS[idx]

# input widgets keep their values in session_state; the buttons overwrite them before the widgets are drawn
keys = {fld.name: f"{task.number}:{fld.name}" for fld in task.fields}
for fld in task.fields:
    st.session_state.setdefault(keys[fld.name], fld.default)

b1, b2, _ = st.columns([1, 1, 4])
if b1.button("🎲 Random input"):
    for fld in task.fields:
        st.session_state[keys[fld.name]] = fld.random()
if b2.button("↺ Example values"):
    for fld in task.fields:
        st.session_state[keys[fld.name]] = fld.default

raw = {}
for fld in task.fields:
    widget = st.text_area if fld.multiline else st.text_input
    raw[fld.name] = widget(fld.label, key=keys[fld.name])

try:
    steps = run(task, raw)
except ValueError as err:
    for line in str(err).splitlines():
        st.error(line)
    st.stop()

with st.expander(f"Tables used: {', '.join(task.tables)}", expanded=len(task.tables) <= 2):
    cols = st.columns(min(len(task.tables), 4))
    for n, name in enumerate(task.tables):
        rows = table_rows(name)
        sbox = name.startswith("S") and name != "Shifts"
        df = pd.DataFrame(rows, index=[f"row {r}" for r in range(len(rows))] if sbox else None)
        with cols[n % len(cols)]:
            st.markdown(f"**{name}**")
            st.dataframe(df, hide_index=not sbox)

st.subheader("Steps")
for n, step in enumerate(steps, start=1):
    last = n == len(steps)
    if last:
        st.success(f"**{step.label}**")
    else:
        st.markdown(f"**{n}. {step.label}**")
    if step.value:
        st.code(step.value, language=None)
    if step.rows:
        st.dataframe(pd.DataFrame(step.rows), hide_index=True)
